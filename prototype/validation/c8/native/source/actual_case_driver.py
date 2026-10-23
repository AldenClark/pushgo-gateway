"""Actual C7 candidate + native database driver; no runtime on import.

Run with bundled Python (cryptography already installed); observers reuse the
frozen C5 pure Python vendor. Only explicitly assigned C7 URL references accepted.
No user database discovery or credential-store inspection occurs.
"""
import argparse
import hashlib
import json
import io
import zipfile
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from private_native_coordination import NativeCoordinator, OpaqueTlsRelay, wait_fact
from device_phase_runner import Device, run_phases
from verify_room_body_hashes import verify as verify_room_hashes

ROOT = Path(__file__).resolve().parents[1]
C8 = ROOT.parent
C5 = C8.parent / "c5-mysql-ordinary-20261015/native"
sys.path.insert(0, str(C5 / "vendor"))
sys.path.insert(0, str(C5 / "harness"))
from c3_mock import C3Mock


def encode(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"hex": bytes(value).hex(), "bytes": len(value)}
    return str(value)


def save(path, value):
    path.write_text(json.dumps(value, default=encode, indent=2) + "\n")


def mysql_budget(label, output, tool):
    result = json.loads(subprocess.check_output([sys.executable, str(tool), label]))
    save(output / (label + "-mysql-budget.json"), result)
    if "guard_pass" in result:
        assert result["guard_pass"] and result["status"] == "BUDGET_READY", "MySQL disk3 requires actual OS-first 4GiB guard; stop for root review"
    else:
        assert result["reservation_met"], "MySQL below 410376KiB reservation; root review required"
    return result


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ActualStore:
    def __init__(self, engine, case_receipt, output, case_label="native_client"):
        self.engine, self.output = engine, output
        self.helper = None
        self.url = None
        if engine == "sqlite":
            self.sqlite = output / "candidate.sqlite"
            assert not self.sqlite.exists()
            self.url = "sqlite://" + str(self.sqlite)
            return
        # Case receipt is explicit root input. No scan of env URLs or old state.
        expected_manifest = (C8 / "env/active-case-manifest.json").resolve()
        assert case_receipt.resolve() == expected_manifest
        manifest_bytes = case_receipt.read_bytes()
        environment = json.loads((C8 / "env/environment-identity.json").read_text())
        assert environment["status"] == "OWNED_IDENTITY_CAPTURED_EMPTY_CASES_NO_WORKLOAD_AUTHORITY"
        assert environment["environment_namespace"] == "C8/isolated"
        assert Path(environment["case_manifest"]).resolve() == expected_manifest
        assert environment["case_manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
        assigned = json.loads(manifest_bytes)
        if "cases" in assigned:
            matches = [row for row in assigned["cases"] if row["label"] == case_label and row["backend"] == ("postgres" if engine == "pg" else "mysql")]
            assert len(matches) == 1
            assigned = matches[0]
        assert assigned["label"] == case_label
        assert assigned["backend"] == ("postgres" if engine == "pg" else "mysql")
        reference = Path(assigned["url_file"]).resolve()
        allowed = (C8 / "env").resolve()
        assert reference.is_relative_to(allowed) and reference.stat().st_mode & 0o077 == 0
        database = assigned["database"]
        assert assigned["environment_namespace"] == "C8/isolated"
        assert assigned["legacy_fixture_name"] is True
        assert re.fullmatch(r"c5_synthetic_[0-9a-f]{32}", database)
        assert re.fullmatch(r"[0-9a-f]{64}", assigned["container_id"])
        assert re.fullmatch(r"[0-9a-f]{32}", assigned["owner_uuid"])
        captured = environment["engines"][engine]
        assert captured["id"] == assigned["container_id"] and captured["owner_uuid"] == assigned["owner_uuid"]
        captured_case = captured["case_refs"][database]
        registry_owner = assigned["case_registry_owner"]
        assert re.fullmatch(r"[0-9a-f]{32}", registry_owner)
        assert captured["case_registry_owner"] == captured_case["case_registry_owner"] == registry_owner
        assert captured["engine_lease_only"] is True and captured_case["engine_lease_only"] is True
        authority = (C8.parent / "c7-private-frame64-20261015/env" / (engine + "-owned.json")).resolve()
        assert Path(assigned["engine_authority_source"]).resolve() == authority
        assert Path(captured["engine_authority_source"]).resolve() == authority
        assert Path(captured_case["engine_authority_source"]).resolve() == authority
        assert re.fullmatch(r"[0-9a-f]{64}", captured["engine_authority_sha256"])
        assert captured_case["label"] == case_label == "native_client"
        assert captured_case["legacy_fixture_name"] is True
        assert Path(captured_case["url_file"]).resolve() == reference
        self.url = reference.read_text().strip()
        parsed = urllib.parse.urlsplit(self.url)
        assert parsed.hostname in ("127.0.0.1", "localhost") and parsed.path == "/" + database
        assert not parsed.query and not parsed.fragment
        assert parsed.scheme in (("postgres", "postgresql") if engine == "pg" else ("mysql",))
        self.helper = Path(assigned["environment_helper"]).resolve()
        assert self.helper == (C8 / "env/isolated_db.py").resolve() and self.helper.is_file()
        assert reference.parent == self.helper.parent
        assert Path(assigned["captured_state"]).resolve() == (C8 / "env" / (engine + "-owned.json")).resolve()
        status = json.loads(subprocess.check_output([sys.executable, str(self.helper), "status", engine]))
        assert status["status"] == "running" and status["endpoint"] == f"{parsed.hostname}:{parsed.port}"
        assert status["id"] == assigned["container_id"]
        self.assigned, self.status = assigned, status
        self.kw = dict(host=parsed.hostname, port=parsed.port, database=database,
                       user=urllib.parse.unquote(parsed.username or ""),
                       password=urllib.parse.unquote(parsed.password or ""))

    def connection(self):
        if self.engine == "sqlite":
            return sqlite3.connect(self.sqlite, timeout=5)
        if self.engine == "pg":
            import pg8000.dbapi
            return pg8000.dbapi.connect(**self.kw, timeout=5)
        import pymysql
        # Local isolated synthetic DB endpoint matches C5 observer policy. This
        # is unrelated to Android Private TLS, whose PKIX/host/pin stay enabled.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return pymysql.connect(**self.kw, ssl=context, connect_timeout=5,
                               read_timeout=5, write_timeout=5)

    def rows(self, sql, params=()):
        assert sql.startswith("SELECT ") and ";" not in sql
        connection = self.connection()
        try:
            cursor = connection.cursor()
            if self.engine != "sqlite":
                cursor.execute("SET TRANSACTION READ ONLY")
            if self.engine == "pg":
                cursor.execute("SET LOCAL search_path TO pushgo_c,pg_catalog")
            cursor.execute(sql if self.engine == "sqlite" else sql.replace("?", "%s"), tuple(params))
            names = [entry[0] for entry in cursor.description]
            return [dict(zip(names, row)) for row in cursor.fetchall()]
        finally:
            connection.rollback()
            connection.close()

    def execute_owned_fault(self, statements):
        from private_native_coordination import trigger_statements
        assert statements in (trigger_statements(self.engine, True), trigger_statements(self.engine, False))
        connection = self.connection()
        try:
            cursor = connection.cursor()
            if self.engine == "pg":
                cursor.execute("SET LOCAL search_path TO pushgo_c,pg_catalog")
            for statement in statements:
                cursor.execute(statement)
            connection.commit()
        finally:
            connection.close()

    def snapshot(self):
        return {table: self.rows(f"SELECT * FROM {table}") for table in
                ("messages", "targets", "devices", "channel_subscriptions", "ledger_usage")}

    def drop_owned_after_snapshot(self):
        if self.helper:
            subprocess.run([sys.executable, str(self.helper), "drop", self.engine,
                            self.assigned["database"]], check=True, capture_output=True)


class ActualCandidate:
    def __init__(self, binary, expected_sha, store, peer, output, tls_label="leaf"):
        self.binary, self.sha, self.store, self.peer, self.output = binary, expected_sha, store, peer, output
        self.http_port, self.tcp_port = unused_port(), unused_port()
        self.base = f"http://127.0.0.1:{self.http_port}"
        self.auth = os.urandom(24).hex()  # Generated C7 fixture shared auth; never production.
        self.tls_label, self.starts, self.pids = tls_label, 0, []
        self.process = None

    def start(self):
        assert hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.sha
        self.starts += 1
        self.log_path = self.output / f"candidate-start-{self.starts:02d}.log"
        self.stream = self.log_path.open("xb")
        from synthetic_tls_material import leaf_pem_for_anonymous_pipe
        descriptor, writer = os.pipe()
        env = os.environ.copy()
        env["C7_SYNTHETIC_SHARED_AUTH"] = self.auth
        command = [str(self.binary), "--db-url", self.store.url, "--http-addr", f"127.0.0.1:{self.http_port}",
                   "--mock-endpoint", self.peer.endpoint, "--public-base-url", self.base,
                   "--shared-token-env", "C7_SYNTHETIC_SHARED_AUTH", "--private-enabled",
                   "--private-tcp-addr", f"127.0.0.1:{self.tcp_port}", "--private-tls-cert",
                   str(ROOT / "synthetic-tls-public" / (self.tls_label + ".pem")),
                   "--private-tls-key", f"/dev/fd/{descriptor}"]
        try:
            self.process = subprocess.Popen(command, env=env, pass_fds=(descriptor,),
                    stdout=self.stream, stderr=subprocess.STDOUT, start_new_session=True)
            self.pids.append(self.process.pid)
        finally:
            os.close(descriptor)
        try:
            material = leaf_pem_for_anonymous_pipe(self.tls_label)
            os.write(writer, material)
            del material  # Memory only; no key path, key logging, or persisted key.
        finally:
            os.close(writer)
        def ready():
            raw = self.log_path.read_text()
            if self.process.poll() is not None:
                raise RuntimeError(f"actual candidate startup exit {self.process.returncode}; see {self.log_path.name}")
            return raw if "READY pid=" in raw and "PRIVATE_READY tcp_addr=" in raw else None
        wait_fact(ready, "actual candidate HTTP and Private listeners ready", 20)
        profile = self.request("GET", "/gateway/profile")
        assert profile["private_channel_enabled"] and profile["transport"]["tcp_enabled"]
        assert profile["transport"]["tcp_port"] == self.tcp_port
        assert not profile["transport"]["quic_enabled"] and not profile["transport"]["wss_enabled"]
        save(self.output / f"actual-profile-{self.starts:02d}.json", profile)

    def request(self, method, path, body=None):
        payload = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=payload, method=method,
                  headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.auth})
        with urllib.request.urlopen(request, timeout=10) as response:
            value = json.loads(response.read())
        assert value["success"] is True
        return value["data"]

    def post_message(self, request):
        value = self.request("POST", "/message", request)
        save(self.output / ("http-accept-" + request["op_id"] + ".json"), {"request": request, "response": value})
        return value

    def wait_expected_exit(self, code, diagnostic, seconds):
        assert self.process.wait(seconds) == code
        self.stream.close()
        raw = self.log_path.read_text()
        assert diagnostic in raw
        return {"actual_pid": self.process.pid, "exit": code, "diagnostic": diagnostic, "log": self.log_path.name}

    def denied_old_capability(self, old_owner, delivery):
        pull = self.request("POST", "/v2/messages/pull", {"device_key": old_owner, "delivery_id": delivery["delivery_id"]})
        ack = self.request("POST", "/v2/messages/ack", {"device_key": old_owner, "delivery_ids": [delivery["delivery_id"]]})
        assert pull["items"] == [] and ack["removed_count"] == 0
        return {"pull": pull, "ack": ack}

    def stats(self):
        request = urllib.request.Request(self.base + "/__fixture/stats", headers={"Authorization": "Bearer " + self.auth})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read())

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(15)
        if hasattr(self, "stream") and not self.stream.closed:
            self.stream.close()
        for pid in self.pids:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            raise AssertionError(f"owned candidate PID remains alive: {pid}")
        return {"owned_pids": self.pids, "all_owned_pids_absent": True, "final_exit": self.process.returncode if self.process else None}


def export_room(device, phase, output):
    dest = output / phase
    dest.mkdir()
    for suffix in ("", "-wal", "-shm"):
        try:
            content = device.call("exec-out", "run-as", device.package, "cat", "databases/c7_private.db" + suffix)
        except subprocess.CalledProcessError:
            if suffix == "":
                raise
            continue  # WAL/SHM may legitimately be checkpointed absent after stop.
        (dest / ("c7_private.db" + suffix)).write_bytes(content)
    source = sqlite3.connect(dest / "c7_private.db")
    backup = sqlite3.connect(dest / "coherent-room.sqlite")
    try:
        source.backup(backup)
        backup.row_factory = sqlite3.Row
        snapshot = {table: [dict(row) for row in backup.execute(f"SELECT * FROM {table}")] for table in
                    ("messages", "inbound_delivery_ledger", "inbound_delivery_ack_outbox")}
        expected = 2 if phase.startswith("phase1") else 3 if phase.startswith("phase2") else 1 if phase.startswith("phase3") else 1 if phase.startswith("numeric-metadata") else 0 if phase.startswith("tls-negative") else None
        save(dest / "room-snapshot-before-assertions.json", snapshot)
        if expected is not None:
            assert len(snapshot["messages"]) == expected
            assert len(snapshot["inbound_delivery_ledger"]) == expected
        save(dest / "room-snapshot.json", snapshot)
        if expected:
            save(dest / "body-hash-evidence.json", verify_room_hashes(dest / "room-snapshot.json", output / "checkpoints"))
    finally:
        source.close()
        backup.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--apk-identity", type=Path, default=ROOT / "apk-final-identity.json")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--engine", choices=("sqlite", "pg", "mysql"), required=True)
    parser.add_argument("--case-receipt", type=Path)
    parser.add_argument("--case-label", choices=("native_client",), default="native_client")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--lease-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-authorized", action="store_true")
    parser.add_argument("--numeric-metadata", action="store_true")
    parser.add_argument("--tls-negative", choices=("wrong-ca", "wrong-host", "wrong-pin"))
    arguments = parser.parse_args()
    assert arguments.window_authorized, "root runtime window required"
    assert not arguments.tls_negative or arguments.engine == "sqlite", "TLS negatives require independent freshSQLite output"
    assert not (arguments.tls_negative and arguments.numeric_metadata)
    assert not arguments.numeric_metadata or arguments.engine == "sqlite", "numeric fourth method uses one independent fresh SQLite case"
    assert arguments.output.resolve().is_relative_to(ROOT)
    arguments.output.mkdir(exist_ok=False, parents=True)
    assert arguments.serial == "emulator-5580", "only root-owned C8 emulator lease"
    assert arguments.lease_receipt.resolve().is_relative_to(C8)
    lease = json.loads(arguments.lease_receipt.read_text())
    assert lease["kind"] == "emulator" and lease["status"] in ("acquired", "renewed") and lease["token_held_in_caller_context"] is True
    assert lease["expires_at"] > time.time(), "expired cooperative resource lease"
    device = Device(Path("/Users/ethan/Library/Android/sdk/platform-tools/adb"), arguments.serial,
                    "io.ethan.pushgo.c7evidence", arguments.output)
    assert device.call("shell", "getprop", "ro.kernel.qemu").decode().strip() == "1"
    assert device.call("shell", "getprop", "ro.build.version.sdk").decode().strip() == "37"
    artifact_manifest = arguments.apk_identity.resolve()
    allowed_manifests = {(ROOT / "apk-final-identity.json").resolve()}
    assert artifact_manifest in allowed_manifests, "only exact C8 frozen artifact manifests allowed"
    identity = json.loads(artifact_manifest.read_text())
    for key in ("main_apk", "test_apk"):
        path = Path(identity[key])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == identity[key + "_sha256"]
        device.call("install", "-r", "-t", str(path), timeout=60)
    # Installed-package identity is a separate required oracle before native flow.
    installed_path = device.call("shell", "pm", "path", device.package).decode().strip().removeprefix("package:")
    installed = device.call("exec-out", "cat", installed_path)
    assert hashlib.sha256(installed).hexdigest() == identity["main_apk_sha256"]
    with zipfile.ZipFile(io.BytesIO(installed)) as archive:
        installed_so = hashlib.sha256(archive.read("lib/arm64-v8a/libpushgo_quinn_jni.so")).hexdigest()
    assert installed_so == identity["compiler_so_sha256"]
    save(arguments.output / "installed-artifact-identity.json", {"main_apk_sha256": identity["main_apk_sha256"], "installed_so_sha256": installed_so, "test_apk_sha256": identity["test_apk_sha256"]})
    store = ActualStore(arguments.engine, arguments.case_receipt, arguments.output, arguments.case_label)
    if arguments.engine == "mysql":
        mysql_budget("native_private_before", arguments.output, store.helper.parent / "budget_snapshot.py")
    candidate = relay = coordinator_server = None
    reverses = []
    outcome = {"status": "FAILED", "engine": arguments.engine, "binary_sha256": arguments.binary_sha256, "gateway_source_commit": arguments.source_commit}
    save(arguments.output / "lane-identity.json", {"gateway_binary_sha256": arguments.binary_sha256, "gateway_source_commit": arguments.source_commit, "apk_identity": identity, "store_assignment": getattr(store, "assigned", {"engine": "sqlite", "path": str(store.sqlite)}) if arguments.engine == "sqlite" else store.assigned, "store_container_status": getattr(store, "status", None), "source_files": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (ROOT / "source").glob("*") if path.is_file()}, "trust_patch_sha256": hashlib.sha256((ROOT / "qa-transport-ca.patch").read_bytes()).hexdigest(), "test_trust_only": True, "scope": "exact49152-byte legal HTTP request; complete Private DELIVER above old32KiB; real upgraded JNI/Room/streamACK"})
    try:
        with C3Mock(arguments.output / "synthetic-provider") as peer:
            candidate = ActualCandidate(arguments.binary, arguments.binary_sha256, store, peer, arguments.output,
                                        arguments.tls_negative or "leaf")
            candidate.start()
            relay = OpaqueTlsRelay(("127.0.0.1", candidate.tcp_port))
            relay.start()
            coordinator = NativeCoordinator(store, candidate, relay, arguments.output / "checkpoints")
            coordinator_server = coordinator.server()
            server_thread = threading.Thread(target=coordinator_server.serve_forever)
            server_thread.start()
            reverses = [(candidate.http_port, candidate.http_port), (candidate.tcp_port, relay.port),
                        (coordinator_server.server_port, coordinator_server.server_port)]
            for android, host in reverses:
                device.call("reverse", f"tcp:{android}", f"tcp:{host}")
            values = {"c7GatewayUrl": candidate.base, "c7ControlUrl": f"http://127.0.0.1:{coordinator_server.server_port}",
                      "c7GatewayToken": candidate.auth, "c7MergeProviderToken": "c7-native-merge-" + os.urandom(16).hex()}
            if arguments.numeric_metadata:
                device.call("shell", "pm", "clear", device.package)
                device.method("numericMetadataLegalHttp48kPersistsEverySemanticValueBeforeAck", values)
                device.stop()
                export_room(device, "numeric-metadata-stopped-room", arguments.output)
                outcome.update({"native_methods": 1, "skips": 0, "numeric_metadata_semantic_oracle": True})
            elif arguments.tls_negative:
                device.call("shell", "pm", "clear", device.package)
                values["c7TlsFailureKind"] = arguments.tls_negative.replace("-", "_")
                first_tls_error = None
                try:
                    device.method("tlsRejectsWrongCaHostOrLeafPinBeforePrivateDelivery", values)
                except Exception as error:
                    first_tls_error = repr(error)
                    raise
                finally:
                    export_errors = []
                    try:
                        device.stop()
                    except Exception as error:
                        export_errors.append({"stop": repr(error)})
                    # Fixed C7 test-generated observer receipt only; preserve the
                    # actual transient event sequence even if assertion failed.
                    filename = "c7-tls-observer-" + arguments.tls_negative.replace("-", "_") + ".json"
                    try:
                        observed = device.call("exec-out", "run-as", device.package, "cat", "files/" + filename)
                        (arguments.output / "actual-native-tls-status-sequence.json").write_bytes(observed)
                    except Exception as error:
                        export_errors.append({"observer_export": repr(error)})
                    if export_errors:
                        save(arguments.output / "tls-observer-export-error.json", export_errors)
                        if first_tls_error is None:
                            raise RuntimeError("TLS observer export failed; see preserved receipt")
                outcome["tls_negative"] = arguments.tls_negative
                export_room(device, "tls-negative-stopped-room", arguments.output)
            else:
                outcome.update(run_phases(device, values, coordinator,
                  lambda phase: export_room(device, phase, arguments.output), candidate.start, window_authorized=True))
            save(arguments.output / "actual-final-db-snapshot.json", store.snapshot())
            save(arguments.output / "actual-private-resource-stats.json", candidate.stats())
            outcome["status"] = "PASSED"
    except Exception as error:
        outcome["first_error"] = repr(error)
        try:
            save(arguments.output / "first-failure-actual-db-snapshot.json", store.snapshot())
        except Exception as observation_error:
            outcome["failure_snapshot_observation_error"] = repr(observation_error)
        raise
    finally:
        cleanup_errors = []
        operations = [("owned_app_stop", device.stop)]
        if "first_error" in outcome:
            operations += [("first_failure_stopped_room", lambda: export_room(device, "first-failure-stopped-room", arguments.output))]
        operations += [("owned_adb_reverse_" + str(android), lambda android=android: device.call("reverse", "--remove", f"tcp:{android}")) for android, host in reverses]
        if coordinator_server:
            operations += [("coordinator_shutdown", coordinator_server.shutdown), ("coordinator_close", coordinator_server.server_close), ("coordinator_thread", lambda: server_thread.join(5))]
        if relay:
            operations += [("opaque_relay", relay.close)]
        if candidate:
            operations += [("candidate_quiet", candidate.close)]
        for label, operation in operations:
            try:
                value = operation()
                if value is not None:
                    outcome[label] = value
            except Exception as error:
                cleanup_errors.append({"operation": label, "error": repr(error)})
        if arguments.engine == "mysql":
            try:
                mysql_budget("native_private_after", arguments.output, store.helper.parent / "budget_snapshot.py")
            except Exception as error:
                cleanup_errors.append({"operation": "mysql_budget_after", "error": repr(error)})
        if cleanup_errors:
            outcome["cleanup_errors"] = cleanup_errors
            outcome["status"] = "FAILED"
        save(arguments.output / "result.json", outcome)
        if cleanup_errors and "first_error" not in outcome:
            raise RuntimeError("owned cleanup or resource budget failed; see result.json")
    store.drop_owned_after_snapshot()


if __name__ == "__main__":
    main()
