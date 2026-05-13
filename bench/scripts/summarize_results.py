#!/usr/bin/env python3
"""Summarize PushGo gateway benchmark result directories."""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
from typing import Any


def load_json(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def numeric_values(rows: list[dict[str, str]], field: str) -> list[float]:
    values = []
    for row in rows:
        raw = row.get(field)
        if raw in (None, "", "unavailable", "True", "False"):
            continue
        try:
            values.append(float(raw))
        except ValueError:
            continue
    return values


def summarize_resources(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {"available": False}
    with path.open("r", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    summary: dict[str, Any] = {"available": True, "samples": len(rows)}
    for field in (
        "proc_cpu_percent",
        "proc_rss_bytes",
        "proc_threads",
        "proc_fd_count",
        "system_cpu_percent",
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
    ):
        values = numeric_values(rows, field)
        if values:
            summary[field] = {
                "avg": sum(values) / len(values),
                "max": max(values),
                "min": min(values),
            }
        else:
            summary[field] = "unavailable"
    return summary


def infer_bottleneck(http: dict[str, Any], resources: dict[str, Any]) -> list[str]:
    notes = []
    if http.get("error_rate", 0) > 0.01:
        notes.append("error_rate_gt_1_percent")
    if http.get("latency_ms", {}).get("p99", 0) > max(1000, http.get("latency_ms", {}).get("p50", 0) * 10):
        notes.append("p99_tail_latency_spike")
    cpu = resources.get("proc_cpu_percent")
    if isinstance(cpu, dict) and cpu.get("max", 0) >= 85:
        notes.append("gateway_cpu_peak_high")
    rss = resources.get("proc_rss_bytes")
    if isinstance(rss, dict) and rss.get("max", 0) > rss.get("min", 0) * 1.5 and rss.get("max", 0) - rss.get("min", 0) > 64 * 1024 * 1024:
        notes.append("rss_growth_candidate")
    fd = resources.get("proc_fd_count")
    if isinstance(fd, dict) and fd.get("max", 0) > fd.get("min", 0) + 128:
        notes.append("fd_growth_candidate")
    wal = resources.get("db_wal_bytes")
    if isinstance(wal, dict) and wal.get("max", 0) > 256 * 1024 * 1024:
        notes.append("sqlite_wal_large")
    return notes or ["no_obvious_bottleneck_from_summary"]


def summarize_dir(path: pathlib.Path) -> dict[str, Any] | None:
    http = load_json(path / "summary.json")
    if not http:
        return None
    resources = summarize_resources(path / "resources.csv")
    return {
        "dir": str(path),
        "scenario": http.get("scenario", path.name),
        "http": {
            "requests": http.get("requests"),
            "success": http.get("success"),
            "failed": http.get("failed"),
            "error_rate": http.get("error_rate"),
            "rps": http.get("rps"),
            "latency_ms": http.get("latency_ms"),
            "http_classes": http.get("http_classes"),
            "http_status": http.get("http_status"),
        },
        "resources": resources,
        "bottleneck_flags": infer_bottleneck(http, resources),
        "scope": http.get("provider_capacity_scope"),
    }


def write_markdown(out: pathlib.Path, summaries: list[dict[str, Any]]) -> None:
    lines = [
        "# PushGo Gateway Benchmark Summary",
        "",
        "This summary is intentionally simple. Raw HTTP results, resource CSV samples, diagnostics JSONL, and per-scenario summaries remain in each result directory.",
        "",
        "Capacity scopes must be read separately:",
        "",
        "1. Gateway HTTP inbound capacity: measured by request status/RPS/latency.",
        "2. Gateway internal dispatch capacity: inferred from private dispatch/outbox, DB/WAL, diagnostics, and resource samples.",
        "3. Real APNS/FCM/WNS provider delivery capacity: unavailable unless real provider configuration is deliberately supplied. Mock/private results are not provider capacity.",
        "",
        "| Scenario | Requests | Error rate | RPS | P95 ms | P99 ms | Resource samples | Bottleneck flags |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in summaries:
        http = item["http"]
        lat = http.get("latency_ms") or {}
        resources = item["resources"]
        lines.append(
            "| {scenario} | {requests} | {error_rate:.4f} | {rps:.2f} | {p95:.2f} | {p99:.2f} | {samples} | {flags} |".format(
                scenario=item["scenario"],
                requests=http.get("requests") or 0,
                error_rate=float(http.get("error_rate") or 0),
                rps=float(http.get("rps") or 0),
                p95=float(lat.get("p95") or 0),
                p99=float(lat.get("p99") or 0),
                samples=resources.get("samples", 0) if resources.get("available") else 0,
                flags=", ".join(item["bottleneck_flags"]),
            )
        )
    lines.extend(
        [
            "",
            "## Next Triage",
            "",
            "- If HTTP p99 rises before CPU/RSS, inspect storage locks, target lookup/cache, and dispatch lifecycle writes.",
            "- If CPU peaks with stable DB/WAL, inspect JSON validation, tracing level, and payload construction.",
            "- If WAL grows or checkpointing lags, rerun the same scenario with SQLite connection and WAL checkpoint settings varied.",
            "- If fd/TCP states grow during WSS/spike/soak, inspect websocket/session shutdown and client retry behavior.",
            "",
        ]
    )
    out.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("docs/performance/pushgo-gateway-benchmark-summary.json"))
    args = parser.parse_args()
    summaries: list[dict[str, Any]] = []
    for root in args.paths:
        if (root / "summary.json").exists():
            item = summarize_dir(root)
            if item:
                summaries.append(item)
        else:
            for child in sorted(root.iterdir() if root.exists() else []):
                if child.is_dir():
                    item = summarize_dir(child)
                    if item:
                        summaries.append(item)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_markdown(args.out.with_suffix(".md"), summaries)
    print(args.out)
    print(args.out.with_suffix(".md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
