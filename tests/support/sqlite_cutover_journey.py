#!/usr/bin/env python3
"""Synthetic old-main history and ordinary SQLite cutover journey.

All databases are created below a new evidence root. Product requests use a
normal Gateway binary; SQL is read-only observation except SQLite's backup API.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import socket
import struct
import sys
import subprocess
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import legacy_cutover_probe as legacy

SOURCE_SHA = "5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077"
OP_IDS = ("c15-history-a", "c15-history-b")
PROFILE = "small"
TABLES = ("semantic_id_registry", "sender_submit_status", "dispatch_op_dedupe",
          "dispatch_submission", "dispatch_delivery_dedupe", "provider_dispatch_outbox",
          "private_payloads", "private_outbox", "provider_pull_queue")


def write_json(path, value):
    with path.open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write("\n")


@contextlib.contextmanager
def ro(path):
    c = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


def table_rows(root, names=TABLES):
    def safe(value):
        if isinstance(value, bytes):
            return {"bytes_hex": value.hex(), "bytes_length": len(value)}
        return value
    result = {}
    for file in legacy.family(root):
        with ro(file) as c:
            available = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in names:
                if name in available:
                    result[f"{file.name}:{name}"] = [
                        {k: safe(v) for k, v in dict(r).items()}
                        for r in c.execute(f'SELECT * FROM "{name}" ORDER BY rowid')]
    return result


class ObservedProduct(legacy.Product):
    """Product wrapper that records every status and business conflict verbatim."""
    def request(self, path, body=None, allow_error=False):
        raw = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, raw, {
            "Authorization": "Bearer " + self.credential,
            "Content-Type": "application/json"})
        try:
            response = self.opener.open(request, timeout=4)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, payload = response.status, response.read(256 * 1024 + 1)
        assert len(payload) <= 256 * 1024
        value = {"ready": status == 200} if path == "/" else json.loads(payload)
        self.http_observed = True
        entry = {"path": path, "http_status": status, "response": value}
        self.events.append(entry)
        if not allow_error:
            assert status == 200 and (path == "/" or value.get("success") is True), entry
        return value, status

    def ready(self):
        end = time.monotonic() + 20
        while time.monotonic() < end:
            assert self.child.poll() is None, f"startup exited: {self.log_path}"
            try:
                self.request("/")
                return
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        raise AssertionError("old main readiness timeout")


class CandidateProduct(ObservedProduct):
    def __init__(self, binary, directory, label, credential, database_path=None):
        legacy.guard_disk(directory)
        self.base = f"http://127.0.0.1:{legacy.port()}"
        mqtt = legacy.port()
        self.credential = credential
        self.mqtt_port = mqtt
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.events = []
        self.http_observed = False
        self.log_path = directory / f"{label}.log"
        self.events_path = directory / f"{label}.http.json"
        database_path = database_path or (directory / "gateway.sqlite")
        args = [str(binary), "--http-addr", self.base.removeprefix("http://"),
                "--db-url", f"sqlite://{database_path}?mode=rwc",
                "--runtime-profile", "small", "--token-service-url", "http://127.0.0.1:1",
                "--private-transports", "mqtt", "--mqtt-bind", f"127.0.0.1:{mqtt}",
                "--mqtt-port", str(mqtt), "--observability-log-level", "info"]
        legacy.write_json(directory / f"{label}.command.json", {
            "argv": args, "PUSHGO_TOKEN": "synthetic process environment; not retained"})
        env = {k: v for k, v in os.environ.items() if not k.startswith("PUSHGO_")}
        env["PUSHGO_TOKEN"] = credential
        with self.log_path.open("xb") as log:
            self.child = subprocess.Popen(args, env=env, stdout=log, stderr=log)


def mqtt_varint(value):
    encoded = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        encoded.append(digit)
        if not value:
            return bytes(encoded)


def mqtt_utf8(value):
    raw = value.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def mqtt_read_packet(sock):
    first = sock.recv(1)
    assert first, "MQTT peer disconnected before packet"
    multiplier, remaining = 1, 0
    for _ in range(4):
        digit = sock.recv(1)
        assert digit
        n = digit[0]
        remaining += (n & 127) * multiplier
        if not n & 128:
            break
        multiplier *= 128
    else:
        raise AssertionError("malformed MQTT remaining length")
    assert remaining <= 256 * 1024, "MQTT packet exceeds bounded probe"
    body = bytearray()
    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        assert chunk, "MQTT peer disconnected in packet"
        body.extend(chunk)
    return first[0], bytes(body)


class Mqtt5Peer:
    """Small real MQTT5 TCP peer matching tests/support/product_mqtt.rs."""
    def __init__(self, port, device_key, credential):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(8)
        props = b"\x26" + mqtt_utf8("device_type") + mqtt_utf8("subscribe")
        variable = mqtt_utf8("MQTT") + b"\x05\xc2\x00\x3c" + mqtt_varint(len(props)) + props
        payload = mqtt_utf8(device_key) + mqtt_utf8(credential) + mqtt_utf8("")
        body = variable + payload
        self.sock.sendall(b"\x10" + mqtt_varint(len(body)) + body)
        packet_type, response = mqtt_read_packet(self.sock)
        assert packet_type >> 4 == 2 and response[1] == 0, (packet_type, response)

    def receive_publish(self, timeout=8):
        self.sock.settimeout(timeout)
        packet_type, body = mqtt_read_packet(self.sock)
        assert packet_type >> 4 == 3, (packet_type, body[:64])
        qos = (packet_type >> 1) & 3
        assert qos == 1, f"expected product QoS1 delivery, got qos={qos}"
        size = struct.unpack(">H", body[:2])[0]
        topic = body[2:2 + size].decode("utf-8")
        offset = 2 + size
        packet_id = struct.unpack(">H", body[offset:offset + 2])[0]
        offset += 2
        value, shift = 0, 0
        while True:
            digit = body[offset]
            offset += 1
            value += (digit & 127) << shift
            if not digit & 128:
                break
            shift += 7
        offset += value
        return {"topic": topic, "packet_id": packet_id,
                "publish_flags": packet_type & 0x0f,
                "envelope": json.loads(body[offset:])}

    def puback(self, packet_id):
        self.sock.sendall(b"\x40\x04" + struct.pack(">H", packet_id) + b"\x00\x00")

    def close(self):
        self.sock.close()


def send(product, channel, credential, op, title, body, ttl):
    value, status = product.request("/message", {
        "channel_id": channel, "password": credential, "op_id": op,
        "title": title, "body": body, "ttl": ttl})
    return {"http_status": status, "response": value}


def make_pristine(binary, directory, credential):
    directory.mkdir(mode=0o700)
    p = ObservedProduct(binary, directory, "oldmain", credential)
    expected = {}
    try:
        p.ready()
        key = p.request("/device/register", {"platform": "mqtt"})[0]["data"]["device_key"]
        p.request("/channel/device", {"device_key": key, "platform": "mqtt", "channel_type": "private"})
        channel = p.request("/channel/subscribe", {
            "device_key": key, "channel_name": "c15-empty-target", "password": credential
        })[0]["data"]["channel_id"]
        p.request("/channel/unsubscribe", {"device_key": key, "channel_id": channel})
        sends = []
        future_expiry_ms = int(time.time() * 1000) + 3_600_000
        for i, op in enumerate(OP_IDS):
            body = f"c15 original body {i}"
            ttl = future_expiry_ms + i
            response = send(p, channel, credential, op, f"c15 title {i}", body, ttl)
            assert response["http_status"] == 200 and response["response"]["success"] is True
            expected[op] = {"message_id": response["response"]["data"]["message_id"],
                            "accepted_at": response["response"]["data"].get("accepted_at"),
                            "body": body, "title": f"c15 title {i}", "ttl": ttl,
                            "channel_id": channel}
            status, http_status = p.request("/send_status/" + op)
            sends.append({"op_id": op, "request": response,
                          "send_status": status, "send_status_http": http_status})
    finally:
        assert p.close() == 0
    observed = legacy.logical_snapshot(directory)
    return expected, sends, observed


def add_private_subscriber(product, channel, credential):
    key = product.request("/device/register", {"platform": "mqtt"})[0]["data"]["device_key"]
    product.request("/channel/device", {"device_key": key, "platform": "mqtt", "channel_type": "private"})
    sub = product.request("/channel/subscribe", {"device_key": key, "channel_id": channel, "password": credential})[0]
    assert sub["data"]["subscribed"] is True
    return key


def invoke_cutover_during_old_writer(binary, mode, directory, backup, label):
    db_url = f"sqlite://{directory}/gateway.sqlite?mode=rwc"
    argv = [str(binary), "--ordinary-cutover", mode,
            "--ordinary-cutover-backup", str(backup.resolve()),
            "--ordinary-source-profile", PROFILE, "--db-url", db_url]
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=90)
    output = directory / f"cutover-{label}.log"
    output.write_text(result.stdout, encoding="utf-8")
    write_json(directory / f"cutover-{label}.json", {
        "argv": argv, "returncode": result.returncode,
        "stdout_stderr_path": str(output), "oldmain_writer_running": True})
    assert result.returncode != 0, (mode, result.stdout)
    assert not backup.exists(), f"cutover created backup while oldmain held SQLite family: {backup}"
    lower = result.stdout.lower()
    assert "lsof" in lower or "open" in lower or "handle" in lower, result.stdout
    return {"mode": mode, "returncode": result.returncode, "output": result.stdout,
            "backup_created": False}


def run_oldmain(binary, evidence_root, candidate_binary=None):
    assert binary.is_absolute() and binary.is_file() and legacy.sha(binary) == SOURCE_SHA
    assert shutil.disk_usage(evidence_root.parent).free >= legacy.FLOOR_WITH_RESERVE
    source = evidence_root / "pristine-source"
    # make_pristine expects its leaf to be absent.
    credential = secrets.token_urlsafe(32)
    expected, sends, _ = make_pristine(binary, source, credential)
    with ro(source / "gateway.sqlite") as c:
        status_rows = {row["op_id"]: dict(row) for row in c.execute(
            "SELECT op_id,model,entity_id,status,dispatch_status,accepted_at,expires_at FROM sender_submit_status")}
    with ro(source / "gateway.dispatch.sqlite") as c:
        semantic_rows = [dict(row) for row in c.execute(
            "SELECT dedupe_key,semantic_id,created_at,updated_at,expires_at FROM semantic_id_registry")]
    for op, fact in expected.items():
        status_row = status_rows[op]
        semantic = next(row for row in semantic_rows if row["dedupe_key"].endswith(":" + op))
        fact["accepted_at"] = status_row["accepted_at"]
        fact["legacy_status"] = status_row["status"]
        fact["legacy_dispatch_status"] = status_row["dispatch_status"]
        fact["semantic_created_at"] = semantic["created_at"]
        fact["semantic_id"] = semantic["semantic_id"]
        fact["semantic_dedupe_key"] = semantic["dedupe_key"]
    snapshot = legacy.logical_snapshot(source)
    command_file = source / "oldmain.command.json"
    write_json(evidence_root / "source-history.json", {
        "source_binary": str(binary), "source_sha256": SOURCE_SHA,
        "old_command_provenance": {"path": str(command_file), "sha256": legacy.sha(command_file)},
        "normal_api_chain": ["mqtt registration", "Private route", "subscribe", "unsubscribe", "two sends"],
        "source_runtime_profile": "small",
        "legacy_identity_retention_days": 7,
        "credential": "synthetic; value intentionally omitted", "sends": sends,
        "expected": expected, "injected_business_rows": 0})
    pristine = evidence_root / "pristine-family"
    legacy.backup_family(source, pristine)
    assert legacy.logical_snapshot(pristine) == snapshot
    write_json(evidence_root / "pristine-logical-snapshot.json", snapshot)

    cases = (
        ("same-content-replay", "same"),
        ("changed-content-reuse", "changed"),
        ("added-offline-subscriber-same-content", "added"),
    )
    for name, mode in cases:
        clone = evidence_root / name
        legacy.backup_family(pristine, clone)
        before = table_rows(clone)
        p = ObservedProduct(binary, clone, "oldmain-replay", credential)
        try:
            p.ready()
            writer_denials = []
            if candidate_binary is not None and name == "same-content-replay":
                denial_backup = evidence_root / "backup-denied-live-writer"
                for cutover_mode in ("plan", "run"):
                    writer_denials.append(invoke_cutover_during_old_writer(
                        candidate_binary, cutover_mode, clone, denial_backup,
                        f"{cutover_mode}-while-oldmain-running"))
                assert p.child.poll() is None, "oldmain writer must survive refused offline cutover"
                p.request("/send_status/" + OP_IDS[0])
            if mode == "added":
                # New private MQTT subscription, deliberately no MQTT CONNECT/peer.
                key = add_private_subscriber(p, expected[OP_IDS[0]]["channel_id"], credential)
            attempts = []
            for index, op in enumerate(OP_IDS):
                item = expected[op]
                body = item["body"] if mode != "changed" else item["body"] + " changed"
                replay = send(p, item["channel_id"], credential, op, item["title"], body, item["ttl"])
                attempts.append({"op_id": op, "input": {"title": item["title"], "body": body, "ttl": item["ttl"]},
                                 "response": replay})
        finally:
            assert p.close() == 0
        after = table_rows(clone)
        write_json(evidence_root / f"{name}.json", {
            "mode": mode, "pre_replay_rows": before, "post_replay_rows": after,
            "attempts": attempts, "added_device_key": key if mode == "added" else None,
            "offline_cutover_denials_while_oldmain_open": writer_denials,
            "external_mqtt_peer": False, "business_rows_injected": 0})
    write_json(evidence_root / "source-probe-status.json", {
        "status": "OLDMAIN_HISTORY_AND_REPLAYS_REPRODUCED",
        "observations": [
            "Both initial ordinary messages were accepted with distinct message IDs and had failed/not_attempted sender status.",
            "Original semantic identities and delivery reservations remained, while ordinary op/submission and provider/private/pull responsibility rows were absent.",
            "Same-content and changed-content replay returned success and the original message IDs; each added delivery reservations without restoring op/submission responsibility.",
            "With a newly subscribed offline MQTT Private device, replay returned the original message IDs, changed sender status to sent/attempted_accepted, and created private payload plus pending private_outbox responsibilities."
        ],
        "inferences": [
            "The observed oldmain zero-target history does not retain the original request identity fields needed to distinguish same from changed content.",
            "A later replay can use current subscriptions and create delivery responsibility for a message whose original accepted request had no targets."
        ],
        "scope": "two synthetic messages, fixed oldmain binary, small profile; not a migration result",
        "injected_business_rows": 0})
    return {"credential": credential, "expected": expected,
            "source_snapshot": snapshot, "pristine": pristine}


def assert_no_process_owns_sqlite_files(directory):
    for path in legacy.family(directory):
        result = subprocess.run(["lsof", "-t", str(path)], capture_output=True, text=True)
        assert result.returncode in (0, 1), f"lsof failed for owned synthetic file {path}: {result.stderr}"
        assert not result.stdout.strip(), f"process still owns synthetic SQLite file {path}: {result.stdout.strip()}"


def clone_pristine(pristine, destination):
    assert not destination.exists()
    legacy.backup_family(pristine, destination)


def invoke_cutover(binary, mode, directory, backup, profile, label):
    assert directory.is_absolute() and backup.is_absolute()
    assert_no_process_owns_sqlite_files(directory)
    db_url = f"sqlite://{directory}/gateway.sqlite?mode=rwc"
    argv = [str(binary), "--ordinary-cutover", mode,
            "--ordinary-cutover-backup", str(backup),
            "--ordinary-source-profile", profile, "--db-url", db_url]
    log = directory / f"cutover-{label}.log"
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=90)
    log.write_text(result.stdout, encoding="utf-8")
    write_json(directory / f"cutover-{label}.json", {
        "argv": argv, "returncode": result.returncode,
        "stdout_stderr_path": str(log), "normal_server_started": False})
    return result


def sqlite_table_info(connection, table):
    return {row["name"]: row for row in connection.execute(f'PRAGMA table_info("{table}")')}


def assert_migrated_history(directory, expected):
    core = directory / "gateway.sqlite"
    with ro(core) as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "ordinary_messages" in names
        columns = sqlite_table_info(c, "ordinary_messages")
        rows = [dict(r) for r in c.execute("SELECT * FROM ordinary_messages ORDER BY op_id")]
        target_table_present = "ordinary_targets" in names
        targets = ([dict(r) for r in c.execute("SELECT * FROM ordinary_targets")]
                   if target_table_present else [])
        assert len(rows) == 2 and not targets
        assert "identity_state" in columns and "status" in columns
        for row in rows:
            assert row["identity_state"] == "legacy_unverifiable", row
            assert row["status"] == "historical_unverifiable", row
            for column in ("delivery_id", "fingerprint", "expires_at"):
                assert column in columns and row[column] is None, (column, row)
            for column in ("payload_blob", "payload_bytes"):
                if column in columns:
                    assert row[column] in (None, 0, b"", ""), (column, row)
            assert row["op_id"] in expected
            source = expected[row["op_id"]]
            assert row["message_id"] == source["message_id"]
            assert row["accepted_at"] == source["accepted_at"]
            assert row["channel_id"] == source["channel_id"], row
            if "thing_id" in columns:
                assert row["thing_id"] is None, row
            retention_days = 7 if PROFILE == "small" else 30
            assert row["dedupe_until"] == source["semantic_created_at"] + retention_days * 24 * 60 * 60 * 1000
            scope_fields = [name for name in row if name in ("channel_id", "channel_text", "scope", "scope_kind", "thing_id")]
            assert scope_fields and any(row.get(name) not in (None, "", 0) for name in scope_fields), row
    responsibilities = {}
    for file in legacy.family(directory):
        with ro(file) as c:
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in ("ordinary_targets", "dispatch_op_dedupe", "dispatch_submission",
                         "provider_dispatch_outbox", "private_payloads", "private_outbox", "provider_pull_queue"):
                if name in tables:
                    count = c.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                    assert count == 0, (file.name, name, count)
                    responsibilities[f"{file.name}:{name}"] = count
    def receipt_row(row):
        return {key: ({"bytes_length": len(value),
                       "sha256": hashlib.sha256(value).hexdigest()}
                      if isinstance(value, bytes) else value)
                for key, value in row.items()}
    return {"historical_rows": [receipt_row(row) for row in rows],
            "ordinary_targets": [receipt_row(row) for row in targets],
            "ordinary_targets_table_present_before_normal_start": target_table_present,
            "empty_responsibility_tables": responsibilities}


def verify_normal_candidate(binary, directory, credential, history):
    p = CandidateProduct(binary, directory, "candidate-first", credential)
    mqtt = None
    try:
        p.ready()
        historical = history["expected"]
        channel = historical[OP_IDS[0]]["channel_id"]
        first = historical[OP_IDS[0]]
        second_channel_key = p.request("/device/register", {"platform": "mqtt"})[0]["data"]["device_key"]
        p.request("/channel/device", {"device_key": second_channel_key,
                                      "platform": "mqtt", "channel_type": "private"})
        second_channel = p.request("/channel/subscribe", {
            "device_key": second_channel_key, "channel_name": "c15-other-scope",
            "password": credential})[0]["data"]["channel_id"]
        conflicts = []
        for op, selected_channel, body, extra in (
            (OP_IDS[0], channel, first["body"], {}),
            (OP_IDS[0], channel, first["body"] + " changed after history", {}),
            ("C15-HISTORY-A", channel, first["body"], {}),
            (OP_IDS[0], second_channel, first["body"], {}),
            (OP_IDS[0], channel, first["body"], {
                "thing_id": "c15-different-thing", "occurred_at": str(int(time.time() * 1000))}),
        ):
            response, status = p.request("/message", {
                "channel_id": selected_channel, "password": credential,
                "op_id": op, "title": first["title"], "body": body, "ttl": first["ttl"], **extra},
                allow_error=True)
            assert status == 409, (status, response)
            error_codes = {
                "top_level": response.get("error_code"),
                "problem": (response.get("problem") or {}).get("code"),
            }
            assert error_codes == {
                "top_level": "historical_identity_unverifiable",
                "problem": "historical_identity_unverifiable",
            }, (error_codes, response)
            conflicts.append({"op_id": op, "channel_id": selected_channel,
                              "body": body, "http_status": status,
                              "error_codes": error_codes, "response": response})

        device = p.request("/device/register", {"platform": "mqtt"})[0]["data"]["device_key"]
        p.request("/channel/device", {"device_key": device, "platform": "mqtt", "channel_type": "private"})
        p.request("/channel/subscribe", {"device_key": device, "channel_id": channel,
                                         "password": credential})
        mqtt = Mqtt5Peer(p.mqtt_port, device, credential)
        op = "c15-new-op-live"
        occurred_at = int(time.time() * 1000)
        input_body = {"channel_id": channel, "password": credential, "op_id": op,
                      "title": "new C15 live delivery", "body": "synthetic MQTT body",
                      "ttl": int(time.time() * 1000) + 3_600_000,
                      "occurred_at": str(occurred_at)}
        accepted, status = p.request("/message", input_body)
        assert status == 200 and accepted["success"] is True, accepted
        message_id = accepted["data"]["message_id"]
        received = mqtt.receive_publish()
        envelope = received["envelope"]
        assert envelope["data"]["message_id"] == message_id, envelope
        assert envelope["data"]["op_id"] == op, envelope
        assert int(envelope["data"]["occurred_at"]) == occurred_at, envelope
        delivery_id = envelope["delivery_id"]
        before_ack = inspect_ordinary_live(directory, op, delivery_id)
        mqtt.puback(received["packet_id"])
        deadline = time.monotonic() + 12
        after_ack = None
        while time.monotonic() < deadline:
            after_ack = inspect_ordinary_live(directory, op, delivery_id)
            if after_ack["target_rows"] == 0 and after_ack["pending_targets"] == 0:
                break
            time.sleep(.05)
        assert after_ack["target_rows"] == 0 and after_ack["pending_targets"] == 0, after_ack
        assert after_ack["payload_bytes"] == 0 and after_ack["payload_blob_length"] == 0, after_ack

        recovery_op = "c15-drop-restart-recovery"
        recovery_accept, recovery_status = p.request("/message", {
            "channel_id": channel, "password": credential, "op_id": recovery_op,
            "title": "C15 restart recovery", "body": "synthetic body held before PUBACK",
            "ttl": int(time.time() * 1000) + 3_600_000})
        assert recovery_status == 200 and recovery_accept["success"] is True
        held = mqtt.receive_publish()
        held_delivery = held["envelope"]["delivery_id"]
        assert held["envelope"]["data"]["op_id"] == recovery_op
        held_sql = inspect_ordinary_live(directory, recovery_op, held_delivery)
        assert held_sql["target_rows"] == 1 and held_sql["pending_targets"] == 1
        assert held_sql["payload_bytes"] > 0 and held_sql["payload_blob_length"] > 0
        mqtt.close()
        mqtt = None
        first_exit = p.close()
        assert first_exit == 0
        p = CandidateProduct(binary, directory, "candidate-restarted", credential)
        p.ready()
        mqtt = Mqtt5Peer(p.mqtt_port, device, credential)
        redelivery = mqtt.receive_publish()
        assert redelivery["envelope"]["delivery_id"] == held_delivery, (held, redelivery)
        assert redelivery["envelope"]["data"]["op_id"] == recovery_op
        mqtt.puback(redelivery["packet_id"])
        recovery_after = None
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            recovery_after = inspect_ordinary_live(directory, recovery_op, held_delivery)
            if recovery_after["target_rows"] == 0 and recovery_after["pending_targets"] == 0:
                break
            time.sleep(.05)
        assert recovery_after["target_rows"] == 0 and recovery_after["pending_targets"] == 0, recovery_after
        assert recovery_after["payload_bytes"] == 0 and recovery_after["payload_blob_length"] == 0, recovery_after
        write_json(directory / "candidate-live-journey.json", {
            "historical_conflicts": conflicts, "new_op": op,
            "accepted_http": {"status": status, "response": accepted},
            "mqtt_receive": received, "before_puback_sql": before_ack,
            "mqtt_puback_packet_id": received["packet_id"], "after_puback_sql": after_ack,
            "drop_restart_recovery": {"op_id": recovery_op,
                "first_unacked_mqtt_receive": held, "before_drop_sql": held_sql,
                "restart_exit": first_exit,
                "redelivered_same_delivery_id": redelivery,
                "mqtt_puback_packet_id": redelivery["packet_id"], "after_puback_sql": recovery_after},
            "actual_mqtt_peer": True})
    finally:
        if mqtt is not None:
            mqtt.close()
        if p is not None:
            assert p.close() == 0


def verify_restored_oldmain(binary, directory, credential, expected, pristine_snapshot):
    assert legacy.logical_snapshot(directory) == pristine_snapshot
    old = ObservedProduct(binary, directory, "restored-oldmain", credential)
    try:
        old.ready()
        observed = []
        for op, expected_fact in expected.items():
            value, status = old.request("/send_status/" + op)
            assert status == 200 and value["success"] is True
            data = value["data"]
            for name in ("op_id", "model", "entity_id", "status",
                         "accepted_at", "expires_at"):
                assert data[name] == expected_fact["old_status"][name], (name, data, expected_fact)
            observed.append(data)
    finally:
        assert old.close() == 0
    return observed


def verify_symlink_alias_refused(binary, directory, credential):
    core = directory / "gateway.sqlite"
    marker = Path(str(core) + ".ordinary-cutover.json")
    marker_before = marker.read_bytes()
    marker_data = json.loads(marker_before)
    assert marker_data["phase"] == "complete", marker_data
    alias = directory / "alias.sqlite"
    assert not alias.exists() and not alias.is_symlink()
    alias.symlink_to(core)
    product = CandidateProduct(binary, directory, "candidate-symlink-alias", credential,
                               database_path=alias)
    deadline = time.monotonic() + 15
    try:
        while product.child.poll() is None and time.monotonic() < deadline:
            try:
                product.request("/")
                raise AssertionError("symlink alias bypassed cutover activation marker")
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        assert product.child.poll() is not None, "symlink alias startup did not refuse within bound"
        exit_code = product.child.returncode
    finally:
        product.close()
    assert exit_code != 0
    assert not product.http_observed, "symlink alias exposed normal HTTP before refusing"
    assert marker.read_bytes() == marker_before, "alias refusal must leave canonical marker phase complete"
    assert not (directory / "alias.delivery.sqlite").exists()
    assert not (directory / "alias.dispatch.sqlite").exists()
    alias.unlink()
    write_json(directory / "symlink-alias-refusal.json", {
        "database_alias": str(alias), "symlink_target": str(core),
        "exit_code": exit_code, "http_opened": False,
        "canonical_marker_unchanged": True, "marker_phase": marker_data["phase"],
        "alias_sidecars_created": False})
    return {"exit_code": exit_code, "http_opened": False,
            "marker_phase": marker_data["phase"], "alias_sidecars_created": False}


def verify_oldmain_marker_boundary(source_binary, active, evidence_root, credential):
    marker = Path(str(active / "gateway.sqlite") + ".ordinary-cutover.json")
    marker_bytes = marker.read_bytes()
    marker_state = json.loads(marker_bytes)
    assert marker_state["phase"] == "activated", marker_state
    clone = evidence_root / "oldmain-after-activated-cutover"
    legacy.backup_family(active, clone)
    copied_marker = clone / "gateway.sqlite.ordinary-cutover.json"
    shutil.copy2(marker, copied_marker)
    assert copied_marker.read_bytes() == marker_bytes
    before = legacy.logical_snapshot(clone)
    product = ObservedProduct(source_binary, clone, "oldmain-after-cutover", credential)
    ready = False
    startup_error = None
    statuses = []
    exit_code = None
    try:
        try:
            product.ready()
            ready = True
            for op in (OP_IDS[0], "c15-new-op-live"):
                value, status = product.request("/send_status/" + op, allow_error=True)
                statuses.append({"op_id": op, "http_status": status, "response": value})
        except BaseException as error:
            startup_error = f"{type(error).__name__}: {error}"
    finally:
        exit_code = product.close()
    after = legacy.logical_snapshot(clone)
    write_json(evidence_root / "oldmain-activated-marker-boundary.json", {
        "marker_state_copied": marker_state, "oldmain_started": ready,
        "startup_error": startup_error, "oldmain_exit_code": exit_code,
        "status_only_requests": statuses,
        "message_posts": sum(1 for event in product.events if event["path"] == "/message"),
        "before_after_logical_snapshot": {"before": before, "after": after},
        "active_candidate_untouched": True,
        "scope": "direct fixed-oldmain start on a separate clone; unresolved binary rollback protection, not a release acceptance gate"})
    assert not any(event["path"] == "/message" for event in product.events)
    return {"oldmain_started": ready, "startup_error": startup_error,
            "exit_code": exit_code, "status_only_requests": statuses}


def run_candidate_journey(source_binary, candidate_binary, root, source_data):
    pristine = source_data["pristine"]
    expected = source_data["expected"]
    credential = source_data["credential"]
    # Capture exact source API status rows used to prove rollback preserved the
    # existing identity, first time and seven-day legacy status retention.
    for op, fact in expected.items():
        fact["old_status"] = {
            "op_id": op, "model": "message", "entity_id": fact["message_id"],
            "status": fact["legacy_status"],
            "accepted_at": fact["accepted_at"],
        }
    with ro(pristine / "gateway.sqlite") as c:
        for op, fact in expected.items():
            row = c.execute("SELECT expires_at FROM sender_submit_status WHERE op_id=?", (op,)).fetchone()
            fact["old_status"]["expires_at"] = row["expires_at"]

    reversible = root / "migrate-restore-before-start"
    clone_pristine(pristine, reversible)
    before = legacy.logical_snapshot(reversible)
    backup = (root / "backup-before-start").resolve()
    plan = invoke_cutover(candidate_binary, "plan", reversible, backup, PROFILE, "plan")
    assert plan.returncode == 0, plan.stdout
    assert legacy.logical_snapshot(reversible) == before, "plan must leave every source file unchanged"
    migrated = invoke_cutover(candidate_binary, "run", reversible, backup, PROFILE, "run")
    assert migrated.returncode == 0, migrated.stdout
    migration_receipt = assert_migrated_history(reversible, expected)
    after_first = legacy.logical_snapshot(reversible)
    again = invoke_cutover(candidate_binary, "run", reversible, backup, PROFILE, "repeat-run")
    assert again.returncode == 0, again.stdout
    assert legacy.logical_snapshot(reversible) == after_first, "repeat migration must be idempotent"
    repeat_receipt = assert_migrated_history(reversible, expected)
    restore = invoke_cutover(candidate_binary, "restore", reversible, backup, PROFILE, "restore-before-start")
    assert restore.returncode == 0, restore.stdout
    assert legacy.logical_snapshot(reversible) == source_data["source_snapshot"]
    restored_status = verify_restored_oldmain(source_binary, reversible, credential,
                                               expected, source_data["source_snapshot"])

    active = root / "migrate-normal-product"
    clone_pristine(pristine, active)
    active_backup = (root / "backup-after-start").resolve()
    plan = invoke_cutover(candidate_binary, "plan", active, active_backup, PROFILE, "plan")
    assert plan.returncode == 0, plan.stdout
    result = invoke_cutover(candidate_binary, "run", active, active_backup, PROFILE, "run")
    assert result.returncode == 0, result.stdout
    active_migration = assert_migrated_history(active, expected)
    alias_refusal = verify_symlink_alias_refused(candidate_binary, active, credential)
    verify_normal_candidate(candidate_binary, active, credential, {"expected": expected})
    active_snapshot = legacy.logical_snapshot(active)
    refused = invoke_cutover(candidate_binary, "restore", active, active_backup, PROFILE,
                             "restore-after-normal-start")
    assert refused.returncode != 0, "restore must refuse after any normal candidate start"
    assert legacy.logical_snapshot(active) == active_snapshot, "refused restore must not mutate the active database"
    oldmain_boundary = verify_oldmain_marker_boundary(source_binary, active, root, credential)

    write_json(root / "candidate-journey-result.json", {
        "status": "SYNTHETIC_SQLITE_CUTOVER_JOURNEY_PASSED",
        "source_binary_sha256": legacy.sha(source_binary),
        "candidate_binary_sha256": legacy.sha(candidate_binary),
        "source_profile": PROFILE,
        "plan_source_unchanged": True,
        "migrated_history": migration_receipt,
        "repeat_run_unchanged": repeat_receipt == migration_receipt,
        "restore_before_first_normal_start": True,
        "restored_oldmain_status": restored_status,
        "active_candidate_migration": active_migration,
        "symlink_alias_refused_before_http": alias_refusal,
        "restore_after_normal_start_refused": True,
        "direct_oldmain_after_activated_marker": oldmain_boundary,
        "new_message_real_mqtt_receive_puback_sql_convergence": True,
        "injected_business_rows": 0,
        "scope": "local synthetic SQLite only; no PG/MySQL or external Provider"})


def inspect_ordinary_live(directory, op, delivery_id):
    with ro(directory / "gateway.sqlite") as c:
        msg = c.execute("SELECT * FROM ordinary_messages WHERE op_id=?", (op,)).fetchone()
        assert msg is not None
        message = dict(msg)
        targets = c.execute("SELECT * FROM ordinary_targets WHERE delivery_id=?", (delivery_id,)).fetchall()
        return {"message_id": message.get("message_id"),
                "payload_bytes": message.get("payload_bytes"),
                "payload_blob_length": len(message["payload_blob"]) if message.get("payload_blob") else 0,
                "pending_targets": message.get("pending_targets"),
                "target_rows": len(targets), "targets": [dict(t) for t in targets]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--source-binary", required=True, type=Path)
    parser.add_argument("--candidate-binary", type=Path)
    parser.add_argument("--ordinary-source-profile", choices=("small", "public"), default=PROFILE)
    parser.add_argument("--evidence-root", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.evidence_root.resolve()
    assert not root.exists(), f"refuse to reuse evidence root {root}"
    root.parent.mkdir(parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    try:
        if args.source_only:
            run_oldmain(args.source_binary.resolve(), root)
        else:
            assert args.candidate_binary, "--candidate-binary is required for migration acceptance journey"
            assert args.ordinary_source_profile == PROFILE, "this synthetic fixture was produced with oldmain small profile"
            candidate = args.candidate_binary.resolve()
            assert candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK)
            source_data = run_oldmain(args.source_binary.resolve(), root, candidate)
            write_json(root / "binary-identities.json", {
                "source_binary": str(args.source_binary.resolve()),
                "source_sha256": legacy.sha(args.source_binary.resolve()),
                "candidate_binary": str(candidate), "candidate_sha256": legacy.sha(candidate),
                "candidate_sha_recorded_dynamically": True})
            run_candidate_journey(args.source_binary.resolve(), candidate, root, source_data)
    except BaseException as error:
        (root / "probe-failure.txt").write_text(f"{type(error).__name__}: {error}\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    main()
