#!/usr/bin/env python3
"""Run PushGo gateway benchmark scenarios and collect raw metrics."""

from __future__ import annotations

import argparse
import base64
import csv
import math
import os
import pathlib
import queue
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
from typing import Any, Callable

from common import (
    BenchConfig,
    HttpClient,
    append_jsonl,
    benchmark_text,
    ensure_seed,
    env_int,
    event_close_payload,
    event_create_payload,
    event_update_payload,
    extract_data,
    message_payload,
    thing_create_payload,
    thing_update_payload,
    url_query,
    utc_millis,
    write_json,
)


Operation = Callable[[int], list[dict[str, Any]]]
RESOURCE_FIELDS = [
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


SCENARIOS: dict[str, dict[str, str]] = {
    "baseline_auth": {
        "purpose": "Measure framework, middleware, auth reject path, error response, and tracing baseline cost.",
        "pressure_model": "Mixed GET traffic over /healthz, /readyz, /channel/exists with normal, missing, and wrong bearer tokens.",
        "expected_bottlenecks": "Axum middleware, token comparison, request-id/tracing emission, JSON error response serialization.",
        "metrics": "HTTP status split, RPS, latency percentiles, process CPU/RSS/fd/TCP, diagnostics availability.",
        "judgement": "4xx auth responses should remain stable; p95 should not diverge sharply from authenticated health checks at low RPS.",
        "next_steps": "If auth latency is high, inspect middleware tracing/log level and constant token comparison hot path.",
    },
    "message_small_hot": {
        "purpose": "Find single-channel small-message ingress and dispatch enqueue limit.",
        "pressure_model": "POST /message to one hot channel with small JSON bodies.",
        "expected_bottlenecks": "Channel password lookup, semantic id/op_id dedupe, SQLite write lock, dispatch target lookup, private enqueue.",
        "metrics": "HTTP latency/status plus DB/WAL growth, CPU, RSS, fd, diagnostics private outbox/connection counters.",
        "judgement": "Sustained 2xx with flat p95 and bounded WAL; rising p99 or 5xx marks a bottleneck candidate.",
        "next_steps": "Correlate p99 rise with WAL growth, dispatch queue settings, and target cache TTL.",
    },
    "message_large_markdown": {
        "purpose": "Expose JSON/body-limit, markdown body normalization, and payload serialization cost.",
        "pressure_model": "POST /message with large markdown bodies near PUSHGO_BENCH_PAYLOAD_SIZE.",
        "expected_bottlenecks": "Body limit, JSON parsing, metadata/custom data encoding, DB write amplification.",
        "metrics": "413/4xx/5xx split, latency percentiles, RSS, DB/WAL growth, CPU peak.",
        "judgement": "Payloads below Axum 32 KiB limit should succeed; above-limit 413 must be fast and stable.",
        "next_steps": "If RSS or latency climbs with stable size, inspect body extraction and custom_data encoding.",
    },
    "message_complex_payload": {
        "purpose": "Measure validation cost for metadata/tags/severity/ttl/url/images/ciphertext combinations.",
        "pressure_model": "POST /message with complex JSON and rotating op_id values.",
        "expected_bottlenecks": "Payload validation, metadata encoding, provider/private payload construction.",
        "metrics": "RPS, p95/p99, 4xx validation rate, CPU, DB/WAL, dispatch diagnostics.",
        "judgement": "Complex payload p95 should be explainably higher than small payload, without error-rate growth.",
        "next_steps": "Compare with message_small_hot to isolate parse/validation overhead.",
    },
    "message_duplicate_op": {
        "purpose": "Measure idempotency/dedupe overhead under repeated op_id submissions.",
        "pressure_model": "POST /message to one channel with the same op_id across workers.",
        "expected_bottlenecks": "Semantic id lookup, dedupe table contention, completion guard storage.",
        "metrics": "2xx/409-like behavior if introduced, p99 latency, DB/WAL size, CPU.",
        "judgement": "Repeated op_id should stay fast and stable; rising p99 suggests dedupe contention.",
        "next_steps": "Inspect semantic id and dispatch lifecycle storage access paths.",
    },
    "message_multi_channel": {
        "purpose": "Compare hot-channel pressure with evenly distributed multi-channel writes.",
        "pressure_model": "POST /message across multiple seeded channels in round-robin.",
        "expected_bottlenecks": "Target cache miss rate, channel password validation, SQLite write concurrency.",
        "metrics": "Per-status totals, latency percentiles, DB/WAL, CPU/RSS, diagnostics.",
        "judgement": "Multi-channel should reduce hotspot contention; worse results point to global storage limits.",
        "next_steps": "Compare target cache TTL and SQLite connection count matrix runs.",
    },
    "dispatch_private_broadcast": {
        "purpose": "Find private dispatch fanout and outbox enqueue limit.",
        "pressure_model": "One message per operation to one channel with many private subscribers.",
        "expected_bottlenecks": "Dispatch target query/cache, private outbox inserts, queue capacity, worker saturation.",
        "metrics": "HTTP p95/p99, DB/WAL growth, private diagnostics, RSS, fd/TCP states.",
        "judgement": "Latency or WAL growth proportional to subscribers is expected; nonlinear p99 is the breakpoint.",
        "next_steps": "Vary worker count, queue capacity, and target cache TTL.",
    },
    "provider_unreachable_mock": {
        "purpose": "Exercise provider-route dispatch failure cost without reporting it as real APNS/FCM/WNS capacity.",
        "pressure_model": "Seed APNS-style provider routes with mock tokens, then POST /message while the gateway is configured with an unreachable or mock token/provider service.",
        "expected_bottlenecks": "Provider payload build, provider queue/cache path, upstream timeout/error handling, invalid-token cleanup path.",
        "metrics": "HTTP 2xx/5xx or accepted=false split, latency percentiles, provider diagnostics if available, CPU, DB/WAL growth.",
        "judgement": "Failures should be fast, bounded, and explicit; slow p99 suggests provider timeout/backoff settings dominate ingress.",
        "next_steps": "Run with PUSHGO_TOKEN_SERVICE_URL pointed at a local failing/mock service, then compare with private dispatch results.",
    },
    "device_subscription_churn": {
        "purpose": "Measure device registration, route update, subscribe, unsubscribe, and route restoration cost.",
        "pressure_model": "Sequential register -> channel/device -> subscribe -> unsubscribe per operation.",
        "expected_bottlenecks": "Device operation guard, route persistence, subscription writes/audit rows.",
        "metrics": "HTTP latency/status, CPU, WAL growth, fd count.",
        "judgement": "4xx should be zero; p99 spikes indicate device guard or write contention.",
        "next_steps": "Inspect device_operation_guards and subscription audit persistence.",
    },
    "offline_pull_ack": {
        "purpose": "Measure offline queue pull, empty pull, single/batch-like pull, and ACK write cost.",
        "pressure_model": "Send message -> /messages/pull -> /messages/ack, with periodic empty pulls.",
        "expected_bottlenecks": "Provider/private outbox query, limit handling, ACK status update, DB indexes.",
        "metrics": "Pull item count, ack removed rate, p95/p99, WAL growth, CPU.",
        "judgement": "Empty pulls should be cheap; ack p99 growth indicates update/index pressure.",
        "next_steps": "Inspect provider_pull/private_outbox access paths and pull limit settings.",
    },
    "offline_empty_pull": {
        "purpose": "Measure empty offline queue pull cost without message writes.",
        "pressure_model": "Repeated /messages/pull for a registered private device with no pending messages.",
        "expected_bottlenecks": "Outbox lookup and empty-result serialization.",
        "metrics": "Pull status/latency, CPU, DB read pressure, TCP/fd stability.",
        "judgement": "Empty pulls should stay low-latency with no WAL growth.",
        "next_steps": "If empty pulls are slow, inspect private outbox query indexes.",
    },
    "offline_pull_ack_batch": {
        "purpose": "Measure larger write -> pull -> many ack batches.",
        "pressure_model": "Per operation sends PUSHGO_BENCH_PULL_BATCH_SIZE messages, pulls the batch, then ACKs returned delivery ids.",
        "expected_bottlenecks": "Bulk outbox insert/query, response serialization, ACK update loop, WAL growth.",
        "metrics": "Total HTTP latency/status across send/pull/ack, DB/WAL growth, CPU/RSS.",
        "judgement": "Batch size increases should not create nonlinear ACK p99 or WAL growth.",
        "next_steps": "If batch ACK dominates, inspect ack_provider_item and private outbox indexes.",
    },
    "event_lifecycle": {
        "purpose": "Measure /event/create, repeated /event/update, /event/close lifecycle pressure.",
        "pressure_model": "Create -> two updates -> close per operation against one hot channel.",
        "expected_bottlenecks": "State merge, semantic id, event DB writes, notification dispatch per state change.",
        "metrics": "Per-endpoint status/latency, CPU, WAL growth, dispatch diagnostics.",
        "judgement": "Lifecycle p95 should remain bounded; close/update failures point to id resolution or state validation.",
        "next_steps": "Separate create-only and update-only if lifecycle p99 bends early.",
    },
    "event_create_only": {
        "purpose": "Isolate event create and op dedupe finalization pressure.",
        "pressure_model": "POST /event/create with unique op_id values against one seeded hot channel.",
        "expected_bottlenecks": "Semantic id allocation, event insert, op dedupe finalization, notification dispatch.",
        "metrics": "Create status/latency, 5xx samples, CPU, DB/WAL growth, diagnostics.",
        "judgement": "Create-only should not return `failed to finalize op dedupe` at tested concurrency.",
        "next_steps": "If 500 appears, inspect create semantic/op dedupe transaction boundaries.",
    },
    "event_update_hot": {
        "purpose": "Isolate repeated updates against one fixed event.",
        "pressure_model": "Seed one event, then POST /event/update with unique op_id values for the same event_id.",
        "expected_bottlenecks": "Hot event update contention, profile merge, op dedupe finalization, notification dispatch.",
        "metrics": "Update status/latency, 5xx samples, CPU, DB/WAL growth, diagnostics.",
        "judgement": "Hot update should not create 5xx; p99 growth indicates hot-row or dedupe contention.",
        "next_steps": "If update-only fails, compare with multi-event lifecycle to isolate hot event contention.",
    },
    "event_close_only": {
        "purpose": "Isolate event close finalization pressure.",
        "pressure_model": "Pre-create an event pool, then POST /event/close once per event with unique op_id values.",
        "expected_bottlenecks": "Close state update, op dedupe finalization, notification dispatch.",
        "metrics": "Close status/latency, 5xx samples, CPU, DB/WAL growth, diagnostics.",
        "judgement": "Close-only should not return dedupe finalization 500 under tested concurrency.",
        "next_steps": "If close-only fails, inspect close transaction and dedupe finalization path.",
    },
    "thing_lifecycle": {
        "purpose": "Measure /thing/create, high-frequency update, message association, archive, delete object-model pressure.",
        "pressure_model": "Create -> message with thing_id -> two updates -> archive -> delete per operation.",
        "expected_bottlenecks": "Thing profile merge, attrs/metadata validation, DB writes, dispatch notification cost.",
        "metrics": "Per-endpoint status/latency, DB/WAL growth, RSS/CPU.",
        "judgement": "Repeated object updates should not leak memory or produce rising error rate.",
        "next_steps": "Inspect thing state merge and storage write amplification.",
    },
    "thing_single_hot_update": {
        "purpose": "Measure hotspot updates against one existing thing.",
        "pressure_model": "Create one thing, then repeatedly POST /thing/update for the same thing_id.",
        "expected_bottlenecks": "Single object write contention, semantic op dedupe, profile merge, SQLite row/index pressure.",
        "metrics": "Update status/latency, CPU, DB/WAL growth, RSS/fd stability.",
        "judgement": "A hot thing should not produce 5xx or nonlinear p99 at moderate RPS.",
        "next_steps": "Compare with multi-thing lifecycle to isolate hot-object contention.",
    },
    "compat_ingress": {
        "purpose": "Measure ntfy, ServerChan, and Bark compatibility parsing and conversion cost.",
        "pressure_model": "Round-robin /ntfy, /serverchan, /bark compatibility requests.",
        "expected_bottlenecks": "Path/query/form parsing, compat key parsing, conversion into MessageIntent.",
        "metrics": "Per-path status split, latency, CPU, DB/WAL growth.",
        "judgement": "Compat overhead should be close to /message for equivalent payload size.",
        "next_steps": "Compare path-level p95 and inspect compat conversion if one path dominates.",
    },
    "private_wss_profile": {
        "purpose": "Check private WSS profile path and websocket handshake/hold capacity when local WSS is enabled.",
        "pressure_model": "GET /gateway/profile and repeated raw /private/ws websocket handshakes held for PUSHGO_BENCH_WS_HOLD_SECONDS.",
        "expected_bottlenecks": "Profile serialization, ws upgrade path, fd/TCP state churn.",
        "metrics": "HTTP 101/4xx/5xx split, fd count, TCP states, RSS.",
        "judgement": "Without private WSS enabled, 503 is expected and must be reported as unavailable, not failure.",
        "next_steps": "For real long-connection tests, pair this with a protocol-aware private client.",
    },
    "ramp_message": {
        "purpose": "Find latency/error-rate breakpoint under stepped load.",
        "pressure_model": "Internal phases at 10%, 25%, 50%, 100%, 150% of PUSHGO_BENCH_RPS on /message.",
        "expected_bottlenecks": "SQLite write lock, dispatch queue, CPU saturation, target lookup cache misses.",
        "metrics": "Phase-level RPS/latency/status and resource samples.",
        "judgement": "Breakpoint is first phase where p95/p99 or error rate rises materially and does not recover.",
        "next_steps": "Run parameter matrix around the phase immediately before the breakpoint.",
    },
    "spike_message": {
        "purpose": "Observe behavior under short burst traffic and recovery.",
        "pressure_model": "Brief high-RPS /message spike followed by normal rate.",
        "expected_bottlenecks": "Request backlog, queue capacity, DB WAL flush, connection churn.",
        "metrics": "Spike vs recovery latency, 5xx/too_busy, CPU/RSS/TCP states.",
        "judgement": "System should recover after spike; persistent p99/error elevation is stability risk.",
        "next_steps": "Inspect queue capacity, worker count, and DB checkpoint behavior.",
    },
    "soak_message": {
        "purpose": "Observe stability risks over a longer steady run.",
        "pressure_model": "Steady /message traffic; default script duration is env-driven, README recommends 10m/30m.",
        "expected_bottlenecks": "Memory/fd leaks, WAL growth, TCP state buildup, queue backlog.",
        "metrics": "Trend of RSS/fd/TCP/DB/WAL plus latency/error rate.",
        "judgement": "RSS/fd/TCP/WAL should not grow without bound at fixed RPS.",
        "next_steps": "If a metric trends upward, inspect ownership path for the corresponding resource.",
    },
}


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil((p / 100.0) * len(ordered)) - 1))
    return ordered[idx]


def summarize(results: list[dict[str, Any]], started: float, ended: float) -> dict[str, Any]:
    latencies = [float(item["latency_ms"]) for item in results if item.get("latency_ms") is not None]
    status_counts: dict[str, int] = {}
    endpoint_counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status", 0))
        status_counts[status] = status_counts.get(status, 0) + 1
        endpoint = f"{item.get('method')} {item.get('path')}"
        endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
    total = len(results)
    success = sum(1 for item in results if item.get("ok"))
    failed = total - success
    elapsed = max(0.001, ended - started)
    return {
        "started_at_ms": int(started * 1000),
        "ended_at_ms": int(ended * 1000),
        "elapsed_seconds": elapsed,
        "requests": total,
        "success": success,
        "failed": failed,
        "error_rate": failed / total if total else 0,
        "rps": total / elapsed,
        "latency_ms": {
            "avg": statistics.fmean(latencies) if latencies else 0,
            "p50": percentile(latencies, 50),
            "p90": percentile(latencies, 90),
            "p95": percentile(latencies, 95),
            "p99": percentile(latencies, 99),
            "max": max(latencies) if latencies else 0,
        },
        "http_status": status_counts,
        "http_classes": {
            "2xx": sum(v for k, v in status_counts.items() if k.startswith("2")),
            "3xx": sum(v for k, v in status_counts.items() if k.startswith("3")),
            "4xx": sum(v for k, v in status_counts.items() if k.startswith("4")),
            "5xx": sum(v for k, v in status_counts.items() if k.startswith("5")),
            "transport_error": status_counts.get("0", 0),
        },
        "endpoint_counts": endpoint_counts,
    }


def start_monitor(config: BenchConfig) -> subprocess.Popen | None:
    if not config.pid:
        return None
    out = config.result_dir / "resources.csv"
    script = pathlib.Path(__file__).with_name("resource_monitor.py")
    return subprocess.Popen(
        [sys.executable, str(script), "--pid", str(config.pid), "--out", str(out)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def websocket_probe(config: BenchConfig, hold_seconds: float) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(config.base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /private/ws HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Protocol: pushgo-private.v1\r\n"
    )
    if config.token:
        request += f"Authorization: Bearer {config.token}\r\n"
    request += "\r\n"
    started = time.perf_counter()
    status = 0
    error = None
    response_head = ""
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=5.0)
        sock.sendall(request.encode("ascii"))
        sock.settimeout(5.0)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            raw += chunk
        response_head = raw.decode("utf-8", errors="replace")
        first_line = response_head.splitlines()[0] if response_head.splitlines() else ""
        parts = first_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        if status == 101 and hold_seconds > 0:
            time.sleep(hold_seconds)
    except Exception as exc:  # noqa: BLE001 - benchmark probe records all failures.
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return {
        "method": "WS",
        "path": "/private/ws",
        "status": status,
        "ok": status == 101 and error is None,
        "latency_ms": (time.perf_counter() - started) * 1000.0,
        "error": error,
        "response": {"head": response_head[:512]} if response_head else None,
    }


def stop_monitor(proc: subprocess.Popen | None) -> None:
    if not proc:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def ensure_resource_file(config: BenchConfig) -> None:
    path = config.result_dir / "resources.csv"
    if path.exists():
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESOURCE_FIELDS)
        writer.writeheader()
        row = {field: "unavailable" for field in RESOURCE_FIELDS}
        row["ts_ms"] = utc_millis()
        row["pid"] = config.pid or "unavailable"
        row["diagnostics_unavailable"] = True
        writer.writerow(row)


def run_load(
    operation: Operation,
    config: BenchConfig,
    *,
    duration: float | None = None,
    rps: float | None = None,
) -> list[dict[str, Any]]:
    duration = config.duration if duration is None else duration
    rps = config.rps if rps is None else rps
    work: queue.Queue[int | None] = queue.Queue(maxsize=max(1, config.vus * 4))
    results: list[dict[str, Any]] = []
    lock = threading.Lock()

    def worker() -> None:
        while True:
            item = work.get()
            if item is None:
                work.task_done()
                break
            try:
                rows = operation(item)
            except Exception as exc:  # noqa: BLE001 - record benchmark operation failure.
                rows = [
                    {
                        "method": "operation",
                        "path": "internal",
                        "status": 0,
                        "ok": False,
                        "latency_ms": 0,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                ]
            now = utc_millis()
            with lock:
                for row in rows:
                    row.setdefault("ts_ms", now)
                    results.append(row)
            work.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(config.vus)]
    for thread in threads:
        thread.start()

    end = time.monotonic() + duration
    interval = 1.0 / rps if rps > 0 else 0.0
    next_at = time.monotonic()
    i = 0
    while time.monotonic() < end:
        work.put(i)
        i += 1
        if interval > 0:
            next_at += interval
            sleep_for = next_at - time.monotonic()
            if sleep_for > 0:
                time.sleep(sleep_for)
    work.join()
    for _ in threads:
        work.put(None)
    for thread in threads:
        thread.join(timeout=2)
    return results


def scenario_operation(name: str, client: HttpClient, config: BenchConfig) -> Operation:
    if name == "baseline_auth":
        paths = [
            ("GET", "/healthz", "normal"),
            ("GET", "/readyz", "normal"),
            ("GET", "/channel/exists?channel_id=00000000000000000000000000000000", "normal"),
            ("GET", "/readyz", "missing"),
            ("GET", "/readyz", "wrong"),
        ]

        def op(i: int) -> list[dict[str, Any]]:
            method, path, token_mode = paths[i % len(paths)]
            return [client.request(method, path, token_mode=token_mode)]

        return op

    if name in {
        "message_small_hot",
        "message_large_markdown",
        "message_complex_payload",
        "message_duplicate_op",
        "spike_message",
        "soak_message",
        "ramp_message",
    }:
        seed = ensure_seed(client, config, channels=1, devices=1, scenario=name)
        channel = seed["channels"][0]
        variant = {
            "message_large_markdown": "large_markdown",
            "message_complex_payload": "complex",
            "message_duplicate_op": "duplicate",
        }.get(name, "small")
        duplicate_op = f"bench-duplicate-{utc_millis()}" if name == "message_duplicate_op" else None

        def op(i: int) -> list[dict[str, Any]]:
            size = config.payload_size
            if name == "message_large_markdown":
                size = max(config.payload_size, 24 * 1024)
            body = message_payload(
                channel["channel_id"],
                channel["password"],
                i,
                payload_size=size,
                variant=variant,
                op_id=duplicate_op,
            )
            return [client.request("POST", "/message", body)]

        return op

    if name == "message_multi_channel":
        channels = max(2, env_int("PUSHGO_BENCH_CHANNELS", 8))
        seed = ensure_seed(client, config, channels=channels, devices=channels, scenario=name)

        def op(i: int) -> list[dict[str, Any]]:
            channel = seed["channels"][i % len(seed["channels"])]
            body = message_payload(
                channel["channel_id"],
                channel["password"],
                i,
                payload_size=config.payload_size,
                variant="multi_channel",
            )
            return [client.request("POST", "/message", body)]

        return op

    if name == "dispatch_private_broadcast":
        devices = max(10, env_int("PUSHGO_BENCH_DEVICE_COUNT", max(config.vus * 10, 50)))
        seed = ensure_seed(client, config, channels=1, devices=devices, scenario=name)
        channel = seed["channels"][0]

        def op(i: int) -> list[dict[str, Any]]:
            body = message_payload(
                channel["channel_id"],
                channel["password"],
                i,
                payload_size=config.payload_size,
                variant="broadcast",
            )
            return [client.request("POST", "/message", body)]

        return op

    if name == "provider_unreachable_mock":
        devices = max(1, env_int("PUSHGO_BENCH_DEVICE_COUNT", max(config.vus, 4)))
        seed = ensure_seed(
            client,
            config,
            channels=1,
            devices=devices,
            private_route=False,
            scenario=name,
        )
        channel = seed["channels"][0]

        def op(i: int) -> list[dict[str, Any]]:
            body = message_payload(
                channel["channel_id"],
                channel["password"],
                i,
                payload_size=config.payload_size,
                variant="provider_unreachable",
            )
            return [client.request("POST", "/message", body)]

        return op

    if name == "device_subscription_churn":
        base_channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]

        def op(i: int) -> list[dict[str, Any]]:
            requested_key = f"bench-churn-device-{i}-{utc_millis()}"
            register = client.request(
                "POST",
                "/device/register",
                {"device_key": requested_key, "platform": "ios"},
            )
            device_key = extract_data(register).get("device_key") or requested_key
            rows = [register]
            rows.append(
                client.request(
                    "POST",
                    "/channel/device",
                    {"device_key": device_key, "platform": "ios", "channel_type": "private"},
                )
            )
            rows.append(
                client.request(
                    "POST",
                    "/channel/subscribe",
                    {
                        "device_key": device_key,
                        "channel_id": base_channel["channel_id"],
                        "password": base_channel["password"],
                    },
                )
            )
            rows.append(
                client.request(
                    "POST",
                    "/channel/unsubscribe",
                    {"device_key": device_key, "channel_id": base_channel["channel_id"]},
                )
            )
            return rows

        return op

    if name == "offline_pull_ack":
        seed = ensure_seed(client, config, channels=1, devices=1, scenario=name)
        channel = seed["channels"][0]
        device_key = seed["devices"][0]["device_key"]

        def op(i: int) -> list[dict[str, Any]]:
            rows = [
                client.request(
                    "POST",
                    "/message",
                    message_payload(
                        channel["channel_id"],
                        channel["password"],
                        i,
                        payload_size=config.payload_size,
                        variant="pull_ack",
                    ),
                )
            ]
            pulled = client.request("POST", "/messages/pull", {"device_key": device_key})
            rows.append(pulled)
            items = (((pulled.get("response") or {}).get("data") or {}).get("items") or [])
            if items:
                rows.append(
                    client.request(
                        "POST",
                        "/messages/ack",
                        {"device_key": device_key, "delivery_id": items[0]["delivery_id"]},
                    )
                )
            if i % 5 == 0:
                rows.append(client.request("POST", "/messages/pull", {"device_key": device_key}))
            return rows

        return op

    if name == "offline_empty_pull":
        seed = ensure_seed(client, config, channels=1, devices=1, scenario=name)
        device_key = seed["devices"][0]["device_key"]

        def op(i: int) -> list[dict[str, Any]]:
            return [client.request("POST", "/messages/pull", {"device_key": device_key})]

        return op

    if name == "offline_pull_ack_batch":
        seed = ensure_seed(client, config, channels=1, devices=1, scenario=name)
        channel = seed["channels"][0]
        device_key = seed["devices"][0]["device_key"]
        batch_size = max(1, env_int("PUSHGO_BENCH_PULL_BATCH_SIZE", 16))

        def op(i: int) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for n in range(batch_size):
                rows.append(
                    client.request(
                        "POST",
                        "/message",
                        message_payload(
                            channel["channel_id"],
                            channel["password"],
                            i * batch_size + n,
                            payload_size=config.payload_size,
                            variant="pull_ack_batch",
                        ),
                    )
                )
            pulled = client.request("POST", "/messages/pull", {"device_key": device_key})
            rows.append(pulled)
            items = (((pulled.get("response") or {}).get("data") or {}).get("items") or [])
            for item in items:
                rows.append(
                    client.request(
                        "POST",
                        "/messages/ack",
                        {"device_key": device_key, "delivery_id": item["delivery_id"]},
                    )
                )
            return rows

        return op

    if name == "event_lifecycle":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]

        def op(i: int) -> list[dict[str, Any]]:
            rows = [client.request("POST", "/event/create", event_create_payload(channel["channel_id"], channel["password"], i))]
            event_id = extract_data(rows[0]).get("event_id")
            if event_id:
                rows.append(client.request("POST", "/event/update", event_update_payload(channel["channel_id"], channel["password"], event_id, i, 1)))
                rows.append(client.request("POST", "/event/update", event_update_payload(channel["channel_id"], channel["password"], event_id, i, 2)))
                rows.append(client.request("POST", "/event/close", event_close_payload(channel["channel_id"], channel["password"], event_id, i)))
            return rows

        return op

    if name == "event_create_only":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]

        def op(i: int) -> list[dict[str, Any]]:
            return [
                client.request(
                    "POST",
                    "/event/create",
                    event_create_payload(channel["channel_id"], channel["password"], i),
                )
            ]

        return op

    if name == "event_update_hot":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]
        created = client.request(
            "POST",
            "/event/create",
            event_create_payload(channel["channel_id"], channel["password"], 0),
        )
        event_id = extract_data(created).get("event_id")
        if not event_id:
            raise RuntimeError(f"event/create seed failed: {created}")

        def op(i: int) -> list[dict[str, Any]]:
            return [
                client.request(
                    "POST",
                    "/event/update",
                    event_update_payload(
                        channel["channel_id"], channel["password"], event_id, i, i
                    ),
                )
            ]

        return op

    if name == "event_close_only":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]
        pool_size = max(config.vus * 2, int(config.rps * config.duration * 1.1) + 1)
        event_ids: list[str] = []
        for i in range(pool_size):
            created = client.request(
                "POST",
                "/event/create",
                event_create_payload(channel["channel_id"], channel["password"], i),
            )
            event_id = extract_data(created).get("event_id")
            if event_id:
                event_ids.append(event_id)
        if not event_ids:
            raise RuntimeError("event close pool seed failed")
        cursor = {"value": 0}
        cursor_lock = threading.Lock()

        def op(i: int) -> list[dict[str, Any]]:
            with cursor_lock:
                idx = cursor["value"]
                cursor["value"] += 1
            if idx >= len(event_ids):
                return [
                    {
                        "method": "operation",
                        "path": "event_close_pool_exhausted",
                        "status": 0,
                        "ok": False,
                        "latency_ms": 0,
                        "error": "event close pool exhausted",
                    }
                ]
            return [
                client.request(
                    "POST",
                    "/event/close",
                    event_close_payload(
                        channel["channel_id"], channel["password"], event_ids[idx], i
                    ),
                )
            ]

        return op

    if name == "thing_lifecycle":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]

        def op(i: int) -> list[dict[str, Any]]:
            rows = [client.request("POST", "/thing/create", thing_create_payload(channel["channel_id"], channel["password"], i))]
            thing_id = extract_data(rows[0]).get("thing_id")
            if thing_id:
                rows.append(
                    client.request(
                        "POST",
                        "/message",
                        message_payload(
                            channel["channel_id"],
                            channel["password"],
                            i,
                            payload_size=config.payload_size,
                            variant="thing_message",
                            thing_id=thing_id,
                        ),
                    )
                )
                rows.append(client.request("POST", "/thing/update", thing_update_payload(channel["channel_id"], channel["password"], thing_id, i, 1)))
                rows.append(client.request("POST", "/thing/update", thing_update_payload(channel["channel_id"], channel["password"], thing_id, i, 2)))
                archive = thing_update_payload(channel["channel_id"], channel["password"], thing_id, i, 3)
                rows.append(client.request("POST", "/thing/archive", archive))
                delete = thing_update_payload(channel["channel_id"], channel["password"], thing_id, i, 4)
                delete["deleted_at"] = utc_millis()
                rows.append(client.request("POST", "/thing/delete", delete))
            return rows

        return op

    if name == "thing_single_hot_update":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]
        created = client.request(
            "POST",
            "/thing/create",
            thing_create_payload(channel["channel_id"], channel["password"], 0),
        )
        thing_id = extract_data(created).get("thing_id")
        if not thing_id:
            raise RuntimeError(f"thing/create seed failed: {created}")

        def op(i: int) -> list[dict[str, Any]]:
            return [
                client.request(
                    "POST",
                    "/thing/update",
                    thing_update_payload(
                        channel["channel_id"], channel["password"], thing_id, i, i
                    ),
                )
            ]

        return op

    if name == "compat_ingress":
        channel = ensure_seed(client, config, channels=1, devices=1, scenario=name)["channels"][0]
        compat_key = f"{channel['channel_id']}:{channel['password']}"
        encoded_key = compat_key.replace("/", "%2F")

        def op(i: int) -> list[dict[str, Any]]:
            choice = i % 4
            if choice == 0:
                query = url_query(
                    {
                        "title": f"ntfy bench {i}",
                        "priority": "4",
                        "tags": "bench,ntfy",
                        "op_id": f"bench-ntfy-{i}-{utc_millis()}",
                    }
                )
                return [
                    client.request(
                        "POST",
                        f"/ntfy/{encoded_key}?{query}",
                        raw_body=benchmark_text(config.payload_size, "ntfy").encode("utf-8"),
                        headers={"Content-Type": "text/plain"},
                    )
                ]
            if choice == 1:
                query = url_query(
                    {
                        "title": f"serverchan bench {i}",
                        "desp": benchmark_text(config.payload_size, "serverchan"),
                        "op_id": f"bench-serverchan-{i}-{utc_millis()}",
                    }
                )
                return [client.request("GET", f"/serverchan/{encoded_key}?{query}")]
            if choice == 2:
                query = url_query(
                    {
                        "level": "timeSensitive",
                        "tags": "bench,bark",
                        "op_id": f"bench-bark-{i}-{utc_millis()}",
                    }
                )
                return [client.request("GET", f"/bark/{encoded_key}/Bench%20body?{query}")]
            return [
                client.request(
                    "POST",
                    "/bark/push",
                    {
                        "device_key": compat_key,
                        "title": f"bark v2 bench {i}",
                        "body": benchmark_text(config.payload_size, "bark"),
                        "level": "active",
                        "tags": ["bench", "bark"],
                        "op_id": f"bench-bark-v2-{i}-{utc_millis()}",
                    },
                )
            ]

        return op

    if name == "private_wss_profile":
        hold_seconds = max(0.0, float(os.environ.get("PUSHGO_BENCH_WS_HOLD_SECONDS", "0.5")))

        def op(i: int) -> list[dict[str, Any]]:
            rows = [client.request("GET", "/gateway/profile")]
            rows.append(websocket_probe(config, hold_seconds))
            return rows

        return op

    raise KeyError(f"unknown scenario: {name}")


def run_named_scenario(name: str, config: BenchConfig) -> dict[str, Any]:
    client = HttpClient(config)
    metadata = SCENARIOS[name]
    write_json(config.result_dir / "config.json", config.as_public_dict())
    write_json(config.result_dir / "scenario.json", {"name": name, **metadata})
    monitor = start_monitor(config)
    started = time.time()
    try:
        operation = scenario_operation(name, client, config)
        if name == "ramp_message":
            all_results: list[dict[str, Any]] = []
            for factor in (0.10, 0.25, 0.50, 1.0, 1.50):
                phase_rps = max(1.0, config.rps * factor)
                phase_duration = max(2.0, config.duration / 5.0)
                phase_started = time.time()
                phase_results = run_load(operation, config, duration=phase_duration, rps=phase_rps)
                phase_summary = summarize(phase_results, phase_started, time.time())
                phase_summary["phase_rps_target"] = phase_rps
                append_jsonl(config.result_dir / "phases.jsonl", phase_summary)
                all_results.extend(phase_results)
            results = all_results
        elif name == "spike_message":
            normal = run_load(operation, config, duration=max(2.0, config.duration * 0.25), rps=config.rps)
            spike = run_load(operation, config, duration=max(2.0, config.duration * 0.20), rps=max(config.rps * 5, config.rps + 1))
            recover = run_load(operation, config, duration=max(2.0, config.duration * 0.25), rps=config.rps)
            results = normal + spike + recover
        else:
            results = run_load(operation, config)
    finally:
        stop_monitor(monitor)
        ensure_resource_file(config)
    ended = time.time()
    for row in results:
        append_jsonl(config.result_dir / "http-results.jsonl", row)
    summary = summarize(results, started, ended)
    summary["scenario"] = name
    summary["scenario_metadata"] = metadata
    summary["provider_capacity_scope"] = (
        "private/mock/local only; this scenario does not measure real APNS/FCM/WNS provider delivery"
    )
    write_json(config.result_dir / "summary.json", summary)
    write_summary_markdown(config.result_dir / "summary.md", summary)
    return summary


def write_summary_markdown(path: pathlib.Path, summary: dict[str, Any]) -> None:
    meta = summary["scenario_metadata"]
    lines = [
        f"# {summary['scenario']}",
        "",
        f"- Purpose: {meta['purpose']}",
        f"- Pressure model: {meta['pressure_model']}",
        f"- Expected bottlenecks: {meta['expected_bottlenecks']}",
        f"- Metrics: {meta['metrics']}",
        f"- Judgement: {meta['judgement']}",
        f"- Next steps: {meta['next_steps']}",
        "",
        "## Result",
        "",
        f"- Requests: {summary['requests']}",
        f"- Success: {summary['success']}",
        f"- Failed: {summary['failed']}",
        f"- Error rate: {summary['error_rate']:.4f}",
        f"- RPS: {summary['rps']:.2f}",
        f"- Avg latency ms: {summary['latency_ms']['avg']:.2f}",
        f"- P50/P90/P95/P99 ms: {summary['latency_ms']['p50']:.2f} / {summary['latency_ms']['p90']:.2f} / {summary['latency_ms']['p95']:.2f} / {summary['latency_ms']['p99']:.2f}",
        f"- Max latency ms: {summary['latency_ms']['max']:.2f}",
        f"- HTTP classes: {summary['http_classes']}",
        f"- HTTP status: {summary['http_status']}",
        "",
        "Provider delivery scope: Gateway HTTP/private dispatch results are not real APNS/FCM/WNS capacity unless real provider credentials and endpoints are deliberately configured.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def list_scenarios() -> None:
    for name, metadata in SCENARIOS.items():
        print(f"{name}: {metadata['purpose']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", help="Scenario name")
    parser.add_argument("--list", action="store_true", help="List scenarios")
    parser.add_argument("--out-name", help="Result directory leaf name")
    args = parser.parse_args()
    if args.list:
        list_scenarios()
        return 0
    if not args.scenario:
        parser.error("scenario is required unless --list is used")
    if args.scenario not in SCENARIOS:
        parser.error(f"unknown scenario {args.scenario!r}; use --list")
    config = BenchConfig.from_env(args.out_name or args.scenario)
    summary = run_named_scenario(args.scenario, config)
    print(config.result_dir)
    print(
        f"{args.scenario}: requests={summary['requests']} success={summary['success']} "
        f"failed={summary['failed']} p95={summary['latency_ms']['p95']:.2f}ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
