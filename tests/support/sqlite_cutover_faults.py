#!/usr/bin/env python3
"""C15-only synthetic SIGKILL test. Injected histories are explicitly NOT API data."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time

import legacy_cutover_probe as legacy


def snapshot(root):
    result = {}
    for path in legacy.family(root):
        with legacy.read_db(path) as c:
            tables = {}
            for row in c.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"):
                name, schema = row
                digest, count = hashlib.sha256(schema.encode()), 0
                cursor = c.execute('SELECT * FROM "' + name.replace('"', '""') + '" ORDER BY rowid')
                while rows := cursor.fetchmany(256):
                    for item in rows:
                        digest.update(repr(tuple(item)).encode())
                        count += 1
                tables[name] = {"count": count, "sha256": digest.hexdigest()}
            result[path.name] = tables
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-binary", type=Path, required=True)
    parser.add_argument("--source-family", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    root, source = args.evidence_root.resolve(), args.source_family.resolve()
    assert "c15-sqlite-history-20261017" in source.parts, "C15 synthetic source only"
    legacy.guard_disk(root.parent)
    os.umask(0o077)
    root.mkdir()
    database = root / "injected-source"
    legacy.backup_family(source, database)
    # Widen only the injection window: source schema stays byte-for-byte the
    # fixed-main shape, but these 512 histories are clearly artificial records.
    created = int(time.time() * 1000) - 1000
    with contextlib.closing(sqlite3.connect(database / "gateway.sqlite")) as core:
        channel = core.execute("SELECT channel_id FROM sender_submit_status WHERE model='message' LIMIT 1").fetchone()[0]
        for i in range(512):
            core.execute("INSERT INTO sender_submit_status(op_id,channel_id,model,entity_id,status,dispatch_status,accepted_at,updated_at,expires_at) VALUES(?,?,'message',?,'failed','not_attempted',?,?,?)",
                         (f"c15-fault-{i}", channel, f"{2**120+i:032x}", created, created+1, created+7*86400000))
        core.commit()
    # Canonical lower-base32 scope is copied from a real API-created identity.
    with contextlib.closing(sqlite3.connect(database / "gateway.dispatch.sqlite")) as dispatch:
        prefix = dispatch.execute("SELECT dedupe_key FROM semantic_id_registry WHERE dedupe_key LIKE 'semantic:%:message:%' LIMIT 1").fetchone()[0].split(":")[1]
        for i in range(512):
            dispatch.execute("INSERT INTO semantic_id_registry(dedupe_key,semantic_id,created_at,updated_at) VALUES(?,?,?,?)",
                             (f"semantic:{prefix}:message:-:c15-fault-{i}", f"{2**120+i:032x}", created, created))
        dispatch.commit()
    before = snapshot(database)
    legacy.write_json(root / "injection.json", {"injected_histories": 512, "origin": "explicit SQL fault-window injection into a clone of this round's normal-old-main source", "source": str(source), "created_at": created, "before": before})
    backup = root / "backup"
    binary = args.candidate_binary.resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith("PUSHGO_")}
    commands = []

    def command(action, backup_dir):
        return [str(binary), "--db-url", f"sqlite://{database}/gateway.sqlite?mode=rwc",
                "--ordinary-cutover", action, "--ordinary-cutover-backup", str(backup_dir),
                "--ordinary-source-profile", "small"]

    argv = command("run", backup)
    with (root / "killed-run.log").open("xb") as log:
        child = subprocess.Popen(argv, env=env, stdout=log, stderr=log)
        marker = database / "gateway.sqlite.ordinary-cutover.json"
        observed = None
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline and child.poll() is None:
                try:
                    value = json.loads(marker.read_text())
                    if value["phase"] == "prepared":
                        observed = value
                        child.send_signal(signal.SIGKILL)
                        break
                except (FileNotFoundError, json.JSONDecodeError):
                    pass
                time.sleep(.001)
            assert observed, "fault window not observed; not a passing interruption test"
        finally:
            if child.poll() is None and observed is None:
                child.kill()
            killed_exit = child.wait(timeout=5)
    assert killed_exit == -signal.SIGKILL
    after_kill = json.loads(marker.read_text())
    assert after_kill["phase"] == "prepared", "missed pre-completion fault window"
    commands.append({"argv": argv, "exit_code": killed_exit, "injection": "SIGKILL after durable prepared was observed"})
    for action in ("run",):
        argv = command(action, backup)
        result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=20)
        (root / "repeat-incomplete.log").write_text(result.stdout+result.stderr)
        assert result.returncode != 0 and "restore" in result.stdout+result.stderr
        commands.append({"argv": argv, "exit_code": result.returncode, "expected": "incomplete cutover rejected"})
    argv = [str(binary), "--db-url", f"sqlite://{database}/gateway.sqlite?mode=rwc", "--http-addr", f"127.0.0.1:{legacy.port()}", "--private-transports", "false", "--token-service-url", "http://127.0.0.1:1"]
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=20)
    (root / "incomplete-normal-start.log").write_text(result.stdout+result.stderr)
    assert result.returncode != 0 and "cutover incomplete" in result.stdout+result.stderr
    commands.append({"argv": argv, "exit_code": result.returncode, "expected": "normal startup rejected before Storage"})
    argv = command("restore", backup)
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
    (root / "restore.log").write_text(result.stdout+result.stderr)
    assert result.returncode == 0, result.stdout+result.stderr
    assert snapshot(database) == before, "full table field hashes must match pre-cutover source"
    commands.append({"argv": argv, "exit_code": result.returncode})
    argv = command("run", root / "backup-after-recovery")
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
    (root / "rerun-after-restore.log").write_text(result.stdout+result.stderr)
    assert result.returncode == 0, result.stdout+result.stderr
    with legacy.read_db(database / "gateway.sqlite") as core:
        migrated = core.execute("SELECT COUNT(*) FROM ordinary_messages WHERE identity_state='legacy_unverifiable'").fetchone()[0]
        assert migrated == 514
        assert core.execute("SELECT COUNT(*) FROM ordinary_messages WHERE delivery_id IS NOT NULL OR fingerprint IS NOT NULL OR expires_at IS NOT NULL OR payload_bytes!=0").fetchone()[0] == 0
    commands.append({"argv": argv, "exit_code": result.returncode})
    legacy.write_json(root / "result.json", {"status": "PASSED", "commands": commands, "binary_sha256": legacy.sha(binary), "harness_sha256": legacy.sha(Path(__file__)), "actual_process_interruption": "SIGKILL with prepared phase remaining", "migrated_histories_after_restore": migrated, "original_API_histories": 2, "explicitly_injected_histories": 512, "full_pre_cutover_logical_state_restored": True, "power_loss_test": False})


if __name__ == "__main__":
    main()
