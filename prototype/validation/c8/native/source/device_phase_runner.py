"""Invoke already-built C7 tests on an already-leased device; no emulator start.

Root-owned lifecycle integration imports run_phases after final binary freezing,
fresh synthetic DB setup and existing emulator ownership verification. Synthetic
instrumentation arguments are supplied in memory; no credential-store inspection.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path


CLASS = "io.ethan.pushgo.CandidatePrivateC7DeviceTest"
METHODS = (
    "phase1RealPrivatePersistsBeforeRejectedServerAck",
    "phase2NewProcessReplaysReconnectsUnsubscribesAndPreparesTransfer",
    "phase3FreshRealOwnerCoalescesAndConsumesRetainedPrivateDelivery",
)


class Device:
    def __init__(self, adb: Path, serial: str, package: str, output: Path):
        if not package.endswith(".c7evidence"):
            raise ValueError("only isolated C7 application ID may be operated")
        self.adb, self.serial, self.package = str(adb), serial, package
        self.output = output
        output.mkdir(parents=True, exist_ok=True)

    def call(self, *args, timeout=30):
        return subprocess.run([self.adb, "-s", self.serial, *args], check=True,
                              capture_output=True, timeout=timeout).stdout

    def stop(self):
        self.call("shell", "am", "force-stop", self.package)
        # Instrumentation targets main PID. It must be absent before export.
        result = subprocess.run([self.adb, "-s", self.serial, "shell", "pidof", self.package],
                                capture_output=True, timeout=10)
        if result.stdout.strip():
            raise AssertionError("C7 application process still alive after owned stop")

    def method(self, name: str, arguments: dict):
        args = ["shell", "am", "instrument", "-w", "-r", "-e", "class", f"{CLASS}#{name}"]
        for key, value in arguments.items():
            # adb shell parses a shell command. Restrict synthetic arguments to
            # data with no shell metacharacters rather than relying on quoting.
            value = str(value)
            if not re.fullmatch(r"[A-Za-z0-9_./:=+@%-]*", value):
                raise ValueError(f"unsafe instrumentation argument: {key}")
            args += ["-e", key, value]
        args += [self.package + ".test/io.ethan.pushgo.test.PushGoAndroidJUnitRunner"]
        result = subprocess.run([self.adb, "-s", self.serial, *args], capture_output=True, timeout=150)
        raw = result.stdout + result.stderr
        (self.output / f"{name}.txt").write_bytes(raw)
        text = raw.decode(errors="replace")
        if result.returncode or "OK (1 test)" not in text or any(
                marker in text for marker in ("FAILURES", "INSTRUMENTATION_FAILED", "INSTRUMENTATION_STATUS_CODE: -3", "INSTRUMENTATION_STATUS_CODE: -4")):
            raise AssertionError(f"first native invocation failed: {name}; inspect preserved output")

    def json_file(self, name: str):
        if name not in ("c7-owner-transfer.json", "c7-private-session.json"):
            raise ValueError("unknown owned synthetic receipt")
        return json.loads(self.call("exec-out", "run-as", self.package, "cat", "files/" + name))


def run_phases(device: Device, arguments: dict, coordinator, export_room,
               restart_same_candidate, *, window_authorized: bool):
    """Mandatory callbacks operate the actual frozen candidate and coherent Room.

    export_room(phase) must copy stopped main+WAL+SHM, form a coherent backup,
    and assert exact canonical bodies/scoped ledger using its native SQLite.
    restart_same_candidate() must preserve the fresh case DB and real identity,
    verify binary SHA again, await HTTP+PRIVATE_READY and update the raw relay
    upstream if listener port changes. It must not recreate the DB or extend any
    production ACK/scheduling timeout. Exceptions stop immediately; no retries.
    """
    if not window_authorized:
        raise RuntimeError("root exclusive native runtime window not authorized")
    device.call("shell", "pm", "clear", device.package)
    device.method(METHODS[0], arguments)
    device.stop()
    export_room("phase1-stopped-before-server-restart")
    coordinator.remove_owned_fault_after_export()
    restart_same_candidate()
    device.method(METHODS[1], arguments)
    device.stop()
    export_room("phase2-stopped-before-clear")
    transfer = device.json_file("c7-owner-transfer.json")
    (device.output / "owner-transfer.json").write_text(json.dumps(transfer, indent=2))
    device.call("shell", "pm", "clear", device.package)
    winner_arguments = dict(arguments)
    transfer_bytes = json.dumps(transfer).encode()
    assert 0 < len(transfer_bytes) <= 131072
    # Fixed debug-QA app-private input only; exact bytes through stdin, no large shell argv.
    subprocess.run([device.adb, "-s", device.serial, "exec-in", "run-as", device.package,
                    "sh", "-c", "mkdir -p files && cat > files/c8-owner-transfer-input.json"],
                   input=transfer_bytes, check=True, capture_output=True, timeout=30)
    winner_arguments["c8OwnerTransferBytes"] = str(len(transfer_bytes))
    winner_arguments["c8OwnerTransferSha256"] = hashlib.sha256(transfer_bytes).hexdigest()
    (device.output / "transfer-file-identity.json").write_text(json.dumps({
        "bytes": len(transfer_bytes), "sha256": hashlib.sha256(transfer_bytes).hexdigest(),
        "fixed_app_private_file": "files/c8-owner-transfer-input.json"}, indent=2))
    device.method(METHODS[2], winner_arguments)
    device.stop()
    export_room("phase3-current-owner-stopped")
    if coordinator.first_error:
        raise AssertionError(coordinator.first_error)
    return {"native_methods": 3, "skips": 0,
            "pure_wire_lost_ack": "NOT RUN; actual server DB ACK failure plus ordinary socket reconnect",
            "private_http_outbox": "not a Private recovery oracle"}
