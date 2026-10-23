#!/usr/bin/env python3
"""Sample gateway process and host resource metrics into CSV/JSONL."""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import platform
import subprocess
import time
from typing import Any

from common import BenchConfig, HttpClient, db_file_from_url, env_float, utc_millis


FIELDS = [
    "ts_ms",
    "pid",
    "proc_cpu_percent",
    "proc_rss_bytes",
    "proc_threads",
    "proc_fd_count",
    "system_cpu_percent",
    "system_load_1m",
    "system_load_5m",
    "system_load_15m",
    "system_mem_available_bytes",
    "tcp_established",
    "tcp_time_wait",
    "tcp_close_wait",
    "db_bytes",
    "db_wal_bytes",
    "net_rx_bytes",
    "net_tx_bytes",
    "disk_read_bytes",
    "disk_write_bytes",
    "diagnostics_private_connections",
    "diagnostics_private_outbox_total",
    "diagnostics_unavailable",
]


def run_text(cmd: list[str], timeout: float = 2.0) -> str | None:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout
        ).strip()
    except Exception:
        return None


def ps_metrics(pid: int) -> dict[str, Any]:
    if platform.system() == "Darwin":
        out = run_text(["ps", "-p", str(pid), "-o", "%cpu=,rss="])
    else:
        out = run_text(["ps", "-p", str(pid), "-o", "%cpu=,rss=,nlwp="])
    if not out:
        return {
            "proc_cpu_percent": "unavailable",
            "proc_rss_bytes": "unavailable",
            "proc_threads": "unavailable",
        }
    parts = out.split()
    try:
        cpu = float(parts[0])
    except Exception:
        cpu = "unavailable"
    try:
        rss = int(float(parts[1]) * 1024)
    except Exception:
        rss = "unavailable"
    threads: int | str
    if platform.system() == "Darwin":
        thread_out = run_text(["ps", "-M", str(pid)])
        threads = max(0, len(thread_out.splitlines()) - 1) if thread_out else "unavailable"
    else:
        try:
            threads = int(parts[2])
        except Exception:
            threads = "unavailable"
    return {
        "proc_cpu_percent": cpu,
        "proc_rss_bytes": rss,
        "proc_threads": threads,
    }


def fd_count(pid: int) -> int | str:
    proc_fd = pathlib.Path(f"/proc/{pid}/fd")
    if proc_fd.exists():
        try:
            return len(list(proc_fd.iterdir()))
        except Exception:
            return "unavailable"
    out = run_text(["lsof", "-nP", "-p", str(pid)])
    if not out:
        return "unavailable"
    return max(0, len(out.splitlines()) - 1)


def mem_available_bytes() -> int | str:
    meminfo = pathlib.Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    if platform.system() == "Darwin":
        vm = run_text(["vm_stat"])
        page_size = 4096
        if vm:
            free_pages = 0
            for line in vm.splitlines():
                if "page size of" in line:
                    try:
                        page_size = int(line.split("page size of", 1)[1].split()[0])
                    except Exception:
                        pass
                if line.startswith(("Pages free:", "Pages inactive:", "Pages speculative:")):
                    try:
                        free_pages += int(line.split(":", 1)[1].strip().rstrip("."))
                    except Exception:
                        pass
            if free_pages:
                return free_pages * page_size
    return "unavailable"


def system_cpu_percent() -> float | str:
    out = run_text(["ps", "-A", "-o", "%cpu="])
    if not out:
        return "unavailable"
    total = 0.0
    found = False
    for line in out.splitlines():
        try:
            total += float(line.strip())
            found = True
        except ValueError:
            continue
    return total if found else "unavailable"


def tcp_states(pid: int) -> dict[str, int | str]:
    states = {"ESTABLISHED": 0, "TIME_WAIT": 0, "CLOSE_WAIT": 0}
    if platform.system() == "Darwin":
        out = run_text(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP"])
        if out:
            for line in out.splitlines()[1:]:
                for state in states:
                    if f"({state})" in line:
                        states[state] += 1
            return {
                "tcp_established": states["ESTABLISHED"],
                "tcp_time_wait": states["TIME_WAIT"],
                "tcp_close_wait": states["CLOSE_WAIT"],
            }
    out = run_text(["ss", "-tanp"])
    if out:
        pid_marker = f"pid={pid},"
        for line in out.splitlines():
            if pid_marker not in line:
                continue
            for state in states:
                if line.startswith(state):
                    states[state] += 1
        return {
            "tcp_established": states["ESTABLISHED"],
            "tcp_time_wait": states["TIME_WAIT"],
            "tcp_close_wait": states["CLOSE_WAIT"],
        }
    return {
        "tcp_established": "unavailable",
        "tcp_time_wait": "unavailable",
        "tcp_close_wait": "unavailable",
    }


def db_sizes(db_url: str) -> dict[str, int | str]:
    db_file = db_file_from_url(db_url)
    if not db_file:
        return {"db_bytes": "unavailable", "db_wal_bytes": "unavailable"}
    wal_file = pathlib.Path(str(db_file) + "-wal")
    return {
        "db_bytes": db_file.stat().st_size if db_file.exists() else 0,
        "db_wal_bytes": wal_file.stat().st_size if wal_file.exists() else 0,
    }


def net_bytes() -> dict[str, int | str]:
    proc = pathlib.Path("/proc/net/dev")
    if proc.exists():
        rx = 0
        tx = 0
        for line in proc.read_text(encoding="utf-8", errors="ignore").splitlines()[2:]:
            if ":" not in line:
                continue
            values = line.split(":", 1)[1].split()
            rx += int(values[0])
            tx += int(values[8])
        return {"net_rx_bytes": rx, "net_tx_bytes": tx}
    out = run_text(["netstat", "-ib"])
    if out:
        rx = 0
        tx = 0
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 10 and parts[0] != "lo0":
                try:
                    rx += int(parts[6])
                    tx += int(parts[9])
                except Exception:
                    pass
        if rx or tx:
            return {"net_rx_bytes": rx, "net_tx_bytes": tx}
    return {"net_rx_bytes": "unavailable", "net_tx_bytes": "unavailable"}


def disk_bytes() -> dict[str, int | str]:
    diskstats = pathlib.Path("/proc/diskstats")
    if diskstats.exists():
        reads = 0
        writes = 0
        for line in diskstats.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 14:
                reads += int(parts[5]) * 512
                writes += int(parts[9]) * 512
        return {"disk_read_bytes": reads, "disk_write_bytes": writes}
    return {"disk_read_bytes": "unavailable", "disk_write_bytes": "unavailable"}


def diagnostics_sample(client: HttpClient) -> tuple[dict[str, Any], dict[str, Any] | None]:
    metrics = {
        "diagnostics_private_connections": "unavailable",
        "diagnostics_private_outbox_total": "unavailable",
        "diagnostics_unavailable": True,
    }
    raw: dict[str, Any] = {}
    for path in ("/diagnostics/private/metrics", "/diagnostics/private/memory"):
        res = client.request("GET", path)
        raw[path] = res
    metrics_res = raw["/diagnostics/private/metrics"]
    memory_res = raw["/diagnostics/private/memory"]
    if metrics_res.get("ok"):
        data = ((metrics_res.get("response") or {}).get("data") or {})
        for key in (
            "active_connections",
            "connected_devices",
            "connection_count",
            "private_connection_count",
        ):
            if key in data:
                metrics["diagnostics_private_connections"] = data[key]
                break
        metrics["diagnostics_unavailable"] = False
    if memory_res.get("ok"):
        data = ((memory_res.get("response") or {}).get("data") or {})
        for key in ("private_outbox_total", "outbox_total", "pending_total"):
            if key in data:
                metrics["diagnostics_private_outbox_total"] = data[key]
                break
        metrics["diagnostics_unavailable"] = False
    return metrics, raw


def sample(pid: int, config: BenchConfig, client: HttpClient) -> tuple[dict[str, Any], dict | None]:
    load = os.getloadavg() if hasattr(os, "getloadavg") else ("unavailable",) * 3
    row: dict[str, Any] = {
        "ts_ms": utc_millis(),
        "pid": pid,
        "system_cpu_percent": system_cpu_percent(),
        "system_load_1m": load[0],
        "system_load_5m": load[1],
        "system_load_15m": load[2],
        "system_mem_available_bytes": mem_available_bytes(),
    }
    row.update(ps_metrics(pid))
    row["proc_fd_count"] = fd_count(pid)
    row.update(tcp_states(pid))
    row.update(db_sizes(config.db_url))
    row.update(net_bytes())
    row.update(disk_bytes())
    diagnostics, raw = diagnostics_sample(client)
    row.update(diagnostics)
    for field in FIELDS:
        row.setdefault(field, "unavailable")
    return row, raw


def monitor(pid: int, config: BenchConfig, out_csv: pathlib.Path, interval: float) -> None:
    client = HttpClient(config, timeout=2.0)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    diagnostics_path = out_csv.with_suffix(".diagnostics.jsonl")
    with out_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        while True:
            row, raw = sample(pid, config, client)
            writer.writerow(row)
            handle.flush()
            if raw:
                with diagnostics_path.open("a", encoding="utf-8") as diag_handle:
                    diag_handle.write(json.dumps({"ts_ms": row["ts_ms"], "raw": raw}) + "\n")
            time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=None)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--interval", type=float, default=env_float("PUSHGO_BENCH_INTERVAL", 1.0))
    args = parser.parse_args()
    config = BenchConfig.from_env("resource-monitor")
    pid = args.pid or config.pid
    if not pid:
        raise SystemExit("PUSHGO_BENCH_PID or --pid is required")
    monitor(pid, config, args.out, max(0.2, args.interval))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
