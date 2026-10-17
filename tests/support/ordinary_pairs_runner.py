#!/usr/bin/env python3
"""Run only frozen normal Gateway binaries; preserve every attempt and fail closed."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid

ORDER = (("M", "P", "C"), ("C", "P", "M"), ("P", "M", "C"))
TEST = "normal_sqlite_two_mqtt_fixed_paired_workload"
RESERVE = int(4.5 * 2**30)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_new(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2)
        f.write("\n")
    path.chmod(0o600)


def passed_receipt(receipt):
    return (receipt.get("exit_code") == 0 and receipt.get("evidence_valid") is True
            and receipt.get("binary_unchanged") is True and not receipt.get("stop"))


def prepare_parents(plan):
    """Establish and test every parent before launching even the first process."""
    for spec in plan:
        for key in ("directory", "receipt", "log"):
            path = Path(spec[key])
            assert path.is_absolute() and ".." not in path.parts, (key, str(path))
            assert not path.exists() and not path.is_symlink(), ("refuse overwrite", str(path))
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            assert path.parent.resolve() == path.parent, ("noncanonical parent", str(path))
            probe = path.parent / (".write-probe-" + uuid.uuid4().hex)
            try:
                with probe.open("x") as f:
                    f.write("isolated C13 writability probe\n")
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                probe.unlink(missing_ok=True)


def verify_run(directory, mode):
    """HTTP or an empty table alone can never satisfy this positive oracle."""
    path = Path(directory) / "journey.jsonl"
    if not path.is_file():
        return False, "journey missing"
    try:
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        events = {}
        for row in rows:
            assert isinstance(row["elapsed_us"], int)
            events.setdefault(row["kind"], []).append(row["data"])
        n = 3 if mode == "preflight" else 136
        configuration = events["configuration"][0]
        result = events["result"][-1]
        control = events["control_preflight"][0]
        assert configuration["mode"] == mode and configuration["qa"] is False
        assert (configuration["messages"], configuration["targets"]) == (n, 2*n)
        assert control["passed"] is True and control["selected_targets"] == 2
        assert control["canonical_active_subscriptions"] == 2
        assert events["shutdown_complete"][-1]["success"] is True
        assert events["shutdown_complete"][-1]["exit_code"] == 0
        assert result["passed"] is True and result["mode"] == mode
        assert result["messages"] == n and result["targets"] == 2*n
        for key, expected in (("persisted_messages", n), ("received_targets", 2*n),
                              ("puback_targets", 2*n), ("positive_terminal_targets", 2*n),
                              ("body_released", n), ("residual_targets", 0), ("unfinished", 0), ("failed", 0)):
            assert result[key] == expected, (key, result.get(key), expected)
        for kind, expected in (("planned_offer", n), ("http_started", n), ("http_accepted", n),
                               ("ack_commit_visible_upper_bound", 2*n),
                               ("body_release_commit_visible_upper_bound", n)):
            assert len(events.get(kind, [])) == expected, (kind, len(events.get(kind, [])), expected)
        for kind in ("peer_receive", "ack_sent"):
            actual = events.get(kind, [])
            assert len({(e["op_id"], e["device_key"]) for e in actual}) == 2*n, kind
            assert len(actual) >= 2*n, kind
            if mode == "preflight":
                assert len(actual) == 2*n, ("unexpected duplicate in tiny preflight", kind)
        assert len(events["peer_connected"]) == 2
        assert len(events["database_configuration"]) == 3
        assert events["database_sample"][-1]["pending_targets"] == 0
        assert events["database_sample"][-1]["payload_count"] == 0
        assert events["idle_complete"] and events["phase_resources"] and events["resources"]
        assert not any(events.get(k) for k in ("error", "http_failed"))
        if mode == "preflight":
            assert not events.get("duplicate_peer_receive")
        for name in ("gateway.log", "gateway.config.json", "gateway.sqlite",
                     "gateway.delivery.sqlite", "gateway.dispatch.sqlite"):
            assert (Path(directory) / name).is_file(), name
        return True, None
    except (AssertionError, KeyError, ValueError, TypeError) as error:
        return False, f"incomplete/invalid evidence: {type(error).__name__}: {error}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--worktree", type=Path, required=True)
    parser.add_argument("--mode", choices=("preflight", "formal"), required=True)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--preflight-report", type=Path)
    args = parser.parse_args()
    assert args.campaign.replace("-", "").isalnum(), "simple fresh campaign label required"
    out = args.output.resolve(strict=True)
    audit = out / "audit"
    ids = json.loads(args.manifest.read_text())
    for version in ("M", "P", "C", "harness"):
        binary = Path(ids[version]["path"])
        assert binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK)
        assert digest(binary) == ids[version]["sha256"], version
    if args.mode == "formal":
        assert args.preflight_report, "all three preflights required before timing"
        pf = json.loads(args.preflight_report.read_text())
        assert pf["mode"] == "preflight" and pf["all_pass"] is True
        assert pf["manifest_sha256"] == digest(args.manifest)
        assert pf["runner_sha256"] == digest(Path(__file__))
        assert {r["version"] for r in pf["completed"]} == {"M", "P", "C"}
        for r in pf["completed"]:
            assert passed_receipt(r)
            assert verify_run(r["directory"], "preflight")[0]
    order = (("M", "P", "C"),) if args.mode == "preflight" else ORDER
    plan = []
    for group, versions in enumerate(order, 0 if args.mode == "preflight" else 1):
        for version in versions:
            name = f"g{group}-{version}"
            plan.append({"group":group,"version":version,
                         "directory":str(out/"evidence"/args.campaign/name),
                         "receipt":str(audit/f"{args.campaign}-{name}.receipt.json"),
                         "log":str(audit/f"{args.campaign}-{name}.log")})
    prepare_parents(plan)
    assert shutil.disk_usage(out).free >= RESERVE, "resource STOP before launch"
    plan_path = audit / f"{args.campaign}-plan.json"
    write_new(plan_path, plan)
    env = {k:v for k,v in os.environ.items() if not k.startswith(("PUSHGO_", "C12_", "C13_"))}
    env["C12_TEST_SECRET"] = uuid.uuid4().hex
    env["C13_RUN_MODE"] = args.mode
    completed = []
    for spec in plan:
        name = f"g{spec['group']}-{spec['version']}"
        free = shutil.disk_usage(out).free
        if free < RESERVE:
            print("RESOURCE STOP before " + name, flush=True)
            break
        version = spec["version"]
        env.update(C12_GATEWAY_BINARY=ids[version]["path"],
                   C12_LEDGER_KIND="main" if version == "M" else "ordinary",
                   C12_PAIR_DIRECTORY=spec["directory"])
        cmd = [ids["harness"]["path"], TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"]
        receipt = {"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   **spec, "mode":args.mode, "command":cmd, "gateway_binary":ids[version],
                   "harness_binary":ids["harness"], "runner_sha256":digest(Path(__file__)),
                   "manifest_sha256":digest(args.manifest), "plan_sha256":digest(plan_path),
                   "free_bytes_before":free, "load_average_before":os.getloadavg(),
                   "expected_outputs":[str(Path(spec["directory"])/p) for p in
                                       ("journey.jsonl","gateway.config.json","gateway.log","gateway.sqlite",
                                        "gateway.delivery.sqlite","gateway.dispatch.sqlite")],
                   "credentials":"random synthetic value, process environment only; never in receipt"}
        rp = Path(spec["receipt"])
        write_new(rp, receipt)  # An interrupted attempt has no success flag.
        print("START " + args.campaign + "/" + name, flush=True)
        start = time.monotonic()
        minimum, stop = free, None
        with Path(spec["log"]).open("x") as log:
            process = subprocess.Popen(cmd, cwd=args.worktree, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            while process.poll() is None:
                minimum = min(minimum, shutil.disk_usage(out).free)
                if minimum < RESERVE or time.monotonic()-start > (60 if args.mode == "preflight" else 115):
                    stop = "resource floor+growth reserve" if minimum < RESERVE else "outer hard timeout"
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    break
                time.sleep(.5)
        code = process.wait()
        valid, reason = verify_run(spec["directory"], args.mode)
        receipt.update(exit_code=code, elapsed_seconds=time.monotonic()-start,
                       minimum_free_bytes=minimum, stop=stop, evidence_valid=valid,
                       evidence_error=reason, load_average_after=os.getloadavg(),
                       binary_unchanged=digest(ids[version]["path"]) == ids[version]["sha256"],
                       log_sha256=digest(spec["log"]))
        rp.write_text(json.dumps(receipt, indent=2)+"\n")
        completed.append(receipt)
        print(json.dumps({"run":name,"exit":code,"evidence_valid":valid,"error":reason,
                          "seconds":round(receipt["elapsed_seconds"], 2),"stop":stop}), flush=True)
        if code != 0 or stop or not valid or not receipt["binary_unchanged"]:
            break
        time.sleep(3)
    result = {"mode":args.mode,"campaign":args.campaign,"planned":len(plan),
              "manifest_sha256":digest(args.manifest),"runner_sha256":digest(Path(__file__)),
              "completed":completed,"not_run":plan[len(completed):],
              "all_pass":len(completed) == len(plan) and all(passed_receipt(r) for r in completed)}
    write_new(audit/f"{args.campaign}-result.json", result)
    print(json.dumps({k:result[k] for k in ("mode","planned","all_pass")}), flush=True)
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
