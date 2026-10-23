"""C6 host coordination, source-only until the root runtime window.

The root-owned driver supplies actual candidate lifecycle, its synthetic database
connection, and authenticated HTTP request function. This module does not provision
TLS material or inspect credential stores. No fake server or native events exist.
Driver methods are mandatory; absent integration fails rather than passing.
"""
from __future__ import annotations

import json
import select
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Protocol


class Store(Protocol):
    engine: str
    def rows(self, sql: str, params: tuple = ()) -> list[dict]: ...
    def execute_owned_fault(self, statements: list[str]) -> None: ...
    # Execute uses only this case's newly created database. SELECT parameters
    # must be bound by the engine adapter, never interpolated into SQL.


class Candidate(Protocol):
    def post_message(self, request: dict) -> dict: ...
    def wait_expected_exit(self, code: int, diagnostic: str, seconds: float) -> dict: ...
    def denied_old_capability(self, old_owner: str, delivery: dict) -> dict: ...
    # post_message MUST call the real candidate /message and retain HTTP receipt.
    # The last method performs real /messages/pull + /messages/ack requests,
    # validating empty items and removed=0; it is supporting fence evidence.


FAULT = "c6_native_ack_storage_fault"


def trigger_statements(engine: str, install: bool) -> list[str]:
    """No delimiter command: adapters execute each complete native statement."""
    if engine == "sqlite":
        return ([f"CREATE TRIGGER {FAULT} BEFORE UPDATE OF acked_at ON targets "
                 "WHEN OLD.acked_at IS NULL AND NEW.acked_at IS NOT NULL BEGIN "
                 f"SELECT RAISE(ABORT,'{FAULT}'); END"] if install else
                [f"DROP TRIGGER {FAULT}"])
    if engine == "mysql":
        return ([f"CREATE TRIGGER {FAULT} BEFORE UPDATE ON targets FOR EACH ROW BEGIN "
                 "IF OLD.acked_at IS NULL AND NEW.acked_at IS NOT NULL THEN "
                 f"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='{FAULT}'; END IF; END"]
                if install else [f"DROP TRIGGER {FAULT}"])
    if engine == "pg":
        return ([f"CREATE FUNCTION {FAULT}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                 "IF OLD.acked_at IS NULL AND NEW.acked_at IS NOT NULL THEN "
                 f"RAISE EXCEPTION '{FAULT}'; END IF; RETURN NEW; END $$",
                 f"CREATE TRIGGER {FAULT} BEFORE UPDATE OF acked_at ON targets "
                 f"FOR EACH ROW EXECUTE FUNCTION {FAULT}()"] if install else
                [f"DROP TRIGGER {FAULT} ON targets", f"DROP FUNCTION {FAULT}()"])
    raise ValueError(f"unsupported native engine {engine}")


class OpaqueTlsRelay:
    """Only forwards TLS bytes and cuts owned sockets; no protocol decoding."""
    def __init__(self, upstream: tuple[str, int]):
        self.upstream = upstream
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.lock = threading.Lock()
        self.pairs: set[tuple[socket.socket, socket.socket]] = set()
        self.accepted = 0
        self.errors: list[str] = []
        self.closed = threading.Event()
        self.threads: list[threading.Thread] = []

    def start(self):
        thread = threading.Thread(target=self._accept, daemon=True)
        self.threads.append(thread)
        thread.start()

    def _accept(self):
        while not self.closed.is_set():
            try:
                left, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                right = socket.create_connection(self.upstream, timeout=3)
            except OSError as exc:
                left.close()
                self.errors.append(str(exc))
                continue
            pair = (left, right)
            with self.lock:
                self.pairs.add(pair)
                self.accepted += 1
            thread = threading.Thread(target=self._forward, args=(pair,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def _forward(self, pair):
        try:
            while not self.closed.is_set():
                ready, _, _ = select.select(pair, [], [], .2)
                for source in ready:
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    (pair[1] if source is pair[0] else pair[0]).sendall(chunk)
        except OSError:
            pass  # Expected for an explicitly cut connection; not a success oracle.
        finally:
            for stream in pair:
                stream.close()
            with self.lock:
                self.pairs.discard(pair)

    def cut(self):
        with self.lock:
            pairs = list(self.pairs)
        for pair in pairs:
            for stream in pair:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def snapshot(self):
        with self.lock:
            return {"accepted": self.accepted, "active": len(self.pairs), "errors": list(self.errors)}

    def close(self):
        self.closed.set()
        self.listener.close()
        self.cut()
        for thread in self.threads:
            thread.join(2)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("owned relay threads remain alive")


def wait_fact(check, label: str, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.025)  # Observation polling, never a retry of a product action.
    raise AssertionError(f"bounded observation failed: {label}")


class NativeCoordinator:
    def __init__(self, store: Store, candidate: Candidate, relay: OpaqueTlsRelay, out: Path):
        self.store, self.candidate, self.relay, self.out = store, candidate, relay, out
        self.out.mkdir(parents=True, exist_ok=True)
        self.first_error = None
        self.sequence = 0
        self.cut_count = None
        self.fault_installed = False

    def message(self, delivery):
        rows = self.store.rows("SELECT * FROM messages WHERE delivery_id=?", (delivery,))
        if len(rows) != 1:
            raise AssertionError(f"expected one actual message, got {len(rows)}")
        return rows[0]

    def targets(self, delivery):
        return self.store.rows("SELECT * FROM targets WHERE delivery_id=? ORDER BY device_key", (delivery,))

    def settled(self, data):
        def check():
            message = self.message(data["delivery_id"])
            rows = self.targets(data["delivery_id"])
            return ({"message_id": message["message_id"], "pending_targets": message["pending_targets"],
                     "payload_bytes": message["payload_bytes"], "targets": rows}
                    if message["message_id"] == data["message_id"] and message["status"] == "sent" and
                    all(row["acked_at"] is not None for row in rows) and
                    int(message["pending_targets"]) == 0 and int(message["payload_bytes"]) == 0 else None)
        return wait_fact(check, "actual ACK commit and payload release")

    def checkpoint(self, request):
        if self.first_error:
            raise RuntimeError("case already failed; preserve first error")
        action, data = request["action"], request["data"]
        if action == "submit":
            body = {name: data[name] for name in ("channel_id", "password", "title", "body")}
            body["op_id"] = str(uuid.uuid4())
            response = self.candidate.post_message(body)
            message = self.message(response["delivery_id"])
            assert message["channel_id"] == data["channel_id"]
            result = {"delivery_id": message["delivery_id"], "message_id": message["message_id"],
                      "title": data["title"], "body": data["body"]}
        elif action in ("ack-committed", "replay-ack-committed", "transferred-private-ack-committed"):
            result = self.settled(data)
        elif action == "arm-server-ack-storage-failure":
            assert not self.fault_installed
            self.store.execute_owned_fault(trigger_statements(self.store.engine, True))
            self.fault_installed = True
            result = {"fault": FAULT, "classification": "actual server storage ACK failure; not wire loss"}
        elif action == "server-ack-storage-failed":
            result = self.candidate.wait_expected_exit(70, FAULT, 15)
            rows = self.targets(data["delivery_id"])
            assert rows and all(row["acked_at"] is None for row in rows)
            assert int(self.message(data["delivery_id"])["payload_bytes"]) > 0
            result["retained_targets"] = rows
        elif action == "cut-owned-tcp-relay":
            self.cut_count = self.relay.snapshot()["accepted"]
            self.relay.cut()
            result = {"accepted_before_cut": self.cut_count}
        elif action in ("connected", "reconnected"):
            minimum = 0 if action == "connected" else self.cut_count
            assert minimum is not None
            result = wait_fact(lambda: (s if (s := self.relay.snapshot())["active"] > 0 and
                               s["accepted"] > minimum else None), "owned TLS connection")
        elif action in ("old-private-offline", "old-route-exited-to-fcm", "winner-private-route-exited"):
            result = wait_fact(lambda: self.relay.snapshot() if self.relay.snapshot()["active"] == 0 else None,
                               "owned Private socket closed")
            if action != "old-private-offline":
                rows = self.store.rows("SELECT * FROM devices WHERE device_key=?", (data["device_key"],))
                assert len(rows) == 1 and rows[0]["provider"] == "FCM" and rows[0]["provider_token"]
                result["device"] = rows[0]
        elif action == "no-private-target":
            rows = self.targets(data["delivery_id"])
            assert not any(row["delivery_mode"] == "private" for row in rows)
            result = {"targets": rows}
        elif action == "owner-coalesced":
            old, winner = data["old_owner"], data["current_owner"]
            rows = self.store.rows("SELECT * FROM devices WHERE device_key=?", (old,))
            assert len(rows) == 1 and rows[0]["coalesced_to"] == winner
            targets = self.targets(data["delivery"]["delivery_id"])
            assert targets and all(row["pull_owner"] == winner and row["acked_at"] is None for row in targets)
            result = {"old_owner": rows[0], "targets": targets,
                      "old_capability": self.candidate.denied_old_capability(old, data["delivery"])}
        elif action == "tls-rejected":
            result = self.relay.snapshot()
            assert result["accepted"] > 0 and data["native_detail"]
            result.update(data)
        else:
            raise ValueError(f"unimplemented actual checkpoint: {action}")
        self.sequence += 1
        path = self.out / f"checkpoint-{self.sequence:03d}-{action}.json"
        path.write_text(json.dumps({"request": request, "result": result}, default=str, indent=2))
        return {"verified": True, "data": result}

    def remove_owned_fault_after_export(self):
        # Caller force-stops/export Room first, then removes trigger and restarts
        # the SAME owned case database. New native PID is asserted in phase2.
        assert self.fault_installed
        self.store.execute_owned_fault(trigger_statements(self.store.engine, False))
        self.fault_installed = False

    def server(self):
        coordinator = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    assert self.path == "/checkpoint"
                    size = int(self.headers.get("Content-Length", "0"))
                    assert 0 < size <= 32768
                    payload = coordinator.checkpoint(json.loads(self.rfile.read(size)))
                    status = 200
                except Exception as error:
                    if coordinator.first_error is None:
                        coordinator.first_error = repr(error)
                        (coordinator.out / "first-error.json").write_text(json.dumps({"error": repr(error)}))
                    status, payload = 500, {"verified": False, "error": coordinator.first_error}
                encoded = json.dumps(payload, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            def log_message(self, *args):
                pass
        return ThreadingHTTPServer(("127.0.0.1", 0), Handler)
