#!/usr/bin/env python3
"""Reproduce a fixed-main migration blocker; this is NOT a migration command.

Only creates a fresh local fixture. No caller-supplied database is accepted.
The binaries are sealed normal products, not a protocol stub or QA runtime.
Exit 0 means the blocker and existing refusal were reproduced, not migrated.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import time
import traceback
import urllib.error
import urllib.request


SOURCE_SHA = "5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077"
CANDIDATE_SHA = "643bdd9789d02c97adf2af0a493b70f230927d0b35e8a98bcada369becf3a4fe"
FLOOR_WITH_RESERVE = (4 * 1024 + 512) * 1024 * 1024
OP_IDS = ("c14-empty-a", "c14-empty-b")
OBLIGATION_TABLES = (
    "dispatch_op_dedupe", "dispatch_submission", "provider_dispatch_outbox",
    "private_payloads", "private_outbox", "provider_pull_queue",
)


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def guard_disk(path):
    assert shutil.disk_usage(path).free >= FLOOR_WITH_RESERVE, "resource STOP: disk floor/reserve"


def port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


@contextlib.contextmanager
def read_db(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        yield connection
    finally:
        connection.close()


def scalar(path, sql, args=()):
    with read_db(path) as connection:
        return connection.execute(sql, args).fetchone()[0]


def family(directory):
    # All files belong to this script's new, otherwise empty fixture directory.
    paths = sorted(directory.glob("*.sqlite"))
    assert paths and directory.joinpath("gateway.sqlite") in paths
    return paths


def backup_family(source, target):
    """Caller has joined its sole fixture writer; SQLite backup includes WAL.

    Sequential per-file snapshots are consistent ONLY under that drained-writer
    precondition. This helper provides no lock against another Gateway process.
    """
    guard_disk(source)
    target.mkdir(mode=0o700)
    manifest = []
    for path in family(source):
        destination = target / path.name
        with read_db(path) as reader:
            with contextlib.closing(sqlite3.connect(destination)) as writer:
                reader.backup(writer, pages=64)
                assert writer.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        manifest.append({"name": path.name, "sha256": sha(destination),
                         "bytes": destination.stat().st_size})
    write_json(target / "backup-manifest.json", {
        "precondition": "sole owned fixture writer exited; no concurrent writers",
        "method": "sqlite3 backup API for every core/delivery/dispatch/runtime file present",
        "files": manifest, "production_backup_acceptance": False,
    })


def logical_snapshot(directory):
    """Hash each bounded synthetic table, not just the total row count."""
    result = {}
    for path in family(directory):
        with read_db(path) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            schema = connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall()
            tables = {}
            for entry in schema:
                if entry["type"] != "table":
                    continue
                name = entry["name"]
                rows = connection.execute('SELECT * FROM "' + name.replace('"', '""') + '" LIMIT 257').fetchall()
                assert len(rows) <= 256, "unexpected fixture size; refusing an unbounded inspection"
                # Covers every field without retaining credentials/payload text.
                encoded = sorted(repr(tuple(row)).encode() for row in rows)
                tables[name] = {"rows": len(rows), "row_hashes": [hashlib.sha256(row).hexdigest() for row in encoded]}
            result[path.name] = {"schema_sha256": hashlib.sha256(repr([tuple(row) for row in schema]).encode()).hexdigest(), "tables": tables}
    return result


class Product:
    def __init__(self, binary, directory, label, credential):
        guard_disk(directory)
        self.base = f"http://127.0.0.1:{port()}"
        mqtt = port()
        self.credential = credential
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.events = []
        self.http_observed = False
        self.log_path = directory / f"{label}.log"
        self.events_path = directory / f"{label}.http.json"
        args = [str(binary), "--http-addr", self.base.removeprefix("http://"),
                "--db-url", f"sqlite://{directory}/gateway.sqlite?mode=rwc",
                "--runtime-profile", "small", "--token-service-url", "http://127.0.0.1:1",
                "--private-transports", "mqtt", "--mqtt-bind", f"127.0.0.1:{mqtt}",
                "--mqtt-port", str(mqtt), "--observability-log-level", "info"]
        write_json(directory / f"{label}.command.json", {"argv": args, "PUSHGO_TOKEN": "synthetic process environment; not retained"})
        env = {k: v for k, v in os.environ.items() if not k.startswith("PUSHGO_")}
        env["PUSHGO_TOKEN"] = credential
        with self.log_path.open("xb") as log:
            self.child = subprocess.Popen(args, env=env, stdout=log, stderr=log)

    def request(self, path, body=None):
        raw = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, raw, {
            "Authorization": "Bearer " + self.credential, "Content-Type": "application/json"})
        try:
            response = self.opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, raw = response.status, response.read(256 * 1024 + 1)
        assert len(raw) <= 256 * 1024
        self.http_observed = True
        value = {"ready": status == 200} if path == "/" else json.loads(raw)
        self.events.append({"path": path, "http_status": status, "response": value})
        assert status == 200, (path, status, value)
        if path != "/":
            assert value["success"] is True, value
        return value

    def ready(self):
        end = time.monotonic() + 20
        while time.monotonic() < end:
            assert self.child.poll() is None, f"startup exited: {self.log_path}"
            try:
                self.request("/")
                return
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        raise AssertionError("normal product readiness timeout")

    def close(self):
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGINT)
            try:
                self.child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()
                raise AssertionError("owned fixture writer required forced termination")
        write_json(self.events_path, self.events)
        return self.child.returncode


def inspect_missing_facts(directory, expected):
    core = directory / "gateway.sqlite"
    facts = []
    for op, message in expected.items():
        with read_db(core) as connection:
            rows = connection.execute("SELECT op_id,model,entity_id,status,dispatch_status,accepted_at,expires_at FROM sender_submit_status WHERE op_id=?", (op,)).fetchall()
        assert len(rows) == 1
        row = dict(rows[0])
        assert row["entity_id"] == message and row["status"] == "failed" and row["dispatch_status"] == "not_attempted"
        facts.append(row)
    tables = {}
    identities, deliveries = [], []
    for path in family(directory):
        with read_db(path) as connection:
            names = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in OBLIGATION_TABLES:
                if name in names:
                    count = connection.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                    assert count == 0, (path.name, name, count)
                    tables[f"{path.name}:{name}"] = count
            if "semantic_id_registry" in names:
                identities.extend(dict(r) for r in connection.execute("SELECT dedupe_key,semantic_id,created_at,expires_at FROM semantic_id_registry"))
            if "dispatch_delivery_dedupe" in names:
                deliveries.extend(dict(r) for r in connection.execute("SELECT dedupe_key,delivery_id,state,created_at FROM dispatch_delivery_dedupe"))
    assert {r["semantic_id"] for r in identities} == set(expected.values())
    assert len(deliveries) == len(expected)
    return {"messages": facts, "semantic_identities": identities,
            "unassociated_delivery_reservations": deliveries, "empty_obligation_tables": tables,
            "missing": ["request fingerprint", "original request content and TTL", "relational op_id/message_id to delivery_id mapping"],
            "pending_delivery_responsibilities": 0, "historical_recipient_count_proven_from_fixture": 0}


def run(args):
    os.umask(0o077)
    root = args.evidence_root.resolve()
    root.parent.mkdir(parents=True, exist_ok=True)
    guard_disk(root.parent)
    root.mkdir(mode=0o700)  # Never overwrite an old receipt or accept an existing DB.
    args.created_root = True
    for binary, expected in [(args.source_binary, SOURCE_SHA), (args.candidate_binary, CANDIDATE_SHA)]:
        assert binary.is_absolute() and os.access(binary, os.X_OK)
        assert sha(binary) == expected, "binary identity differs from fixed C13 products"
    write_json(root / "identity.json", {"source_commit": "dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6",
        "runtime_commit": "0163e0ac27791cd4b08b3a9750fbc8e6bf1f8886",
        "source_binary": str(args.source_binary), "source_sha256": SOURCE_SHA,
        "candidate_binary": str(args.candidate_binary), "candidate_sha256": CANDIDATE_SHA,
        "private": "enabled MQTT listener; no peer or external Provider, no real credentials", "injected_business_rows": 0})
    source = root / "source"
    source.mkdir()
    credential = secrets.token_urlsafe(32)
    product = Product(args.source_binary, source, "source", credential)
    expected = {}
    try:
        product.ready()
        key = product.request("/device/register", {"platform": "mqtt"})["data"]["device_key"]
        product.request("/channel/device", {"device_key": key, "platform": "mqtt", "channel_type": "private"})
        channel = product.request("/channel/subscribe", {"device_key": key, "channel_name": "c14-empty-target", "password": credential})["data"]["channel_id"]
        assert product.request("/channel/unsubscribe", {"device_key": key, "channel_id": channel})["data"]["removed"]
        for index, op in enumerate(OP_IDS):
            response = product.request("/message", {"channel_id": channel, "password": credential,
                "op_id": op, "title": f"synthetic empty {index}", "body": f"distinct original body {index}", "ttl": 3600 + index})
            expected[op] = response["data"]["message_id"]
            product.request("/send_status/" + op)
    finally:
        assert product.close() == 0
    before = inspect_missing_facts(source, expected)
    write_json(root / "missing-source-facts.json", before)
    snapshot = logical_snapshot(source)
    write_json(root / "source-logical-snapshot.json", snapshot)
    # Preserve the original family; candidate startup only touches a fresh clone.
    backup_family(source, root / "snapshot")
    assert logical_snapshot(root / "snapshot") == snapshot
    backup_family(root / "snapshot", root / "candidate-refusal")
    candidate = Product(args.candidate_binary, root / "candidate-refusal", "candidate", credential)
    try:
        end = time.monotonic() + 20
        while candidate.child.poll() is None and time.monotonic() < end:
            try:
                candidate.request("/")
                raise AssertionError("candidate exposed HTTP for unmigrated legacy data")
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        assert candidate.child.poll() is not None, "candidate did not refuse within startup bound"
    finally:
        candidate_exit = candidate.close()
    assert candidate_exit != 0 and not candidate.http_observed
    assert "legacy ordinary" in candidate.log_path.read_text()
    assert inspect_missing_facts(root / "candidate-refusal", expected) == before
    candidate_core = root / "candidate-refusal/gateway.sqlite"
    ordinary_table = scalar(candidate_core, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ordinary_messages'")
    if ordinary_table:
        assert scalar(candidate_core, "SELECT COUNT(*) FROM ordinary_messages") == 0
    backup_family(root / "snapshot", root / "restored-old")
    assert logical_snapshot(root / "restored-old") == snapshot
    old = Product(args.source_binary, root / "restored-old", "restored", credential)
    try:
        old.ready()
        for fact in before["messages"]:
            data = old.request("/send_status/" + fact["op_id"])["data"]
            assert all(data[k] == fact[k] for k in ("op_id", "model", "entity_id", "status", "accepted_at", "expires_at"))
    finally:
        assert old.close() == 0
    assert inspect_missing_facts(root / "restored-old", expected) == before
    assert logical_snapshot(source) == snapshot
    write_json(root / "result.json", {"status": "BLOCKER_REPRODUCED_NOT_MIGRATED", "messages": 2,
        "normal_main_http_success": 2, "messages_with_zero_targets": 2,
        "target_count": 0, "injected_business_rows": 0,
        "candidate_exit": candidate_exit, "candidate_http_opened": False,
        "candidate_migrated_identities": 0, "candidate_ordinary_table_created": bool(ordinary_table),
        "source_family_unchanged": True,
        "drained_family_backup_and_old_status_restore": True,
        "rollback_A_after_successful_migration": "NOT RUN: no migration implemented",
        "rollback_B_marker": "NOT IMPLEMENTED / NOT RUN",
        "postgres_mysql": "NOT RUN: shared semantic blocker; stopped before dependent implementation",
        "free_bytes_end": shutil.disk_usage(root).free})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-binary", required=True, type=Path)
    parser.add_argument("--candidate-binary", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    args = parser.parse_args()
    args.created_root = False
    try:
        run(args)
    except BaseException:
        if args.created_root:
            failure = args.evidence_root / "probe-failure.txt"
            if not failure.exists():
                failure.write_text(traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
