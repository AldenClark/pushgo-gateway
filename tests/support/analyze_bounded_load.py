#!/usr/bin/env python3
"""Summarize one bounded normal-product load run without changing its evidence."""
import argparse
import collections
import hashlib
import json
import math
from pathlib import Path


def quantiles(values, denominator):
    ordered = sorted(values)
    if denominator < len(ordered):
        raise ValueError("denominator cannot be smaller than the observed sample count")

    def at_rank(fraction):
        rank = math.ceil(fraction * denominator)
        return ordered[rank - 1] if 1 <= rank <= len(ordered) else None

    return {
        "samples": len(ordered),
        "denominator": denominator,
        "missing": max(0, denominator - len(ordered)),
        "method": "nearest rank ceil(p*denominator); percentile is null when incomplete samples reach its rank",
        **{
            label: at_rank(fraction)
            for label, fraction in (("p50_ms", .50), ("p95_ms", .95), ("p99_ms", .99))
        },
    }


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_dir = args.run_directory.resolve(strict=True)
    journey = run_dir / "journey.jsonl"
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    rows = [json.loads(line) for line in journey.read_text().splitlines()]
    events = collections.defaultdict(list)
    for row in rows:
        events[row["kind"]].append(row)
    config = events["configuration"][0]["data"]
    plan = config["load_plan"]
    load_start = events["load_started"][0]["data"]["planned_offer_start_us"]
    planned = {r["data"]["op_id"]: r["data"] for r in events["planned_offer"]}
    starts = {r["data"]["op_id"]: r["data"]["actual_http_start_us"] for r in events["http_started"]}
    accepted = {r["data"]["op_id"]: r["elapsed_us"] for r in events["http_accepted"]}
    persisted = {r["data"]["op_id"]: r["elapsed_us"] for r in events["persist_commit_visible_upper_bound"]}
    devices = {r["data"]["device_key"]: r["data"]["peer"] for r in events["peer_connected"]}

    def target_times(kind):
        values = {}
        for row in events[kind]:
            data = row["data"]
            key = (data["op_id"], data["device_key"])
            values.setdefault(key, row["elapsed_us"])
        return values

    received = target_times("peer_receive")
    ack_sent = target_times("ack_sent")
    committed = target_times("ack_commit_visible_upper_bound")
    expected_ops = [f"delivery-load-{i:05}" for i in range(config["messages"])]
    target_keys = list(devices)
    expected_targets = {(op, key) for op in expected_ops for key in target_keys}
    fully_completed = [
        op for op in expected_ops
        if all((op, key) in committed for key in target_keys)
    ]
    identities = {}
    conflicts = []
    for row in rows:
        data = row["data"]
        op = data.get("op_id")
        if op and any(data.get(key) is not None for key in ("message_id", "delivery_id", "body_hash")):
            old = identities.setdefault(op, {})
            for key in ("message_id", "delivery_id", "body_hash"):
                if data.get(key) is not None:
                    if key in old and old[key] != data[key]:
                        conflicts.append({"op_id": op, "field": key})
                    old[key] = data[key]

    def latency(start_map, end_map, keys, begin):
        values = [
            (end_map[key] - begin(key, start_map)) / 1000
            for key in keys if key in start_map and key in end_map
        ]
        if any(value < 0 for value in values):
            raise ValueError("negative latency sample")
        return quantiles(values, len(keys))

    stages = []
    stage_latency = {}
    for stage in plan["stages"]:
        ops = [
            op for op, value in planned.items()
            if value["stage"] == stage["name"]
        ]
        indices = [int(op.rsplit("-", 1)[1]) for op in ops]
        start_offset = min((planned[op]["planned_offer_us"] for op in ops), default=load_start)
        last_offset = max((planned[op]["planned_offer_us"] for op in ops), default=start_offset)
        stage_seconds = stage["messages"] / stage["rate_per_second"]
        actual_starts = [starts[op] for op in ops if op in starts]
        stages.append({
            **stage,
            "planned_duration_seconds": stage_seconds,
            "planned_schedule_span_seconds": (last_offset - start_offset) / 1e6 if ops else 0,
            "actual_http_started": len(actual_starts),
            "actual_http_start_span_seconds": (max(actual_starts) - min(actual_starts)) / 1e6 if len(actual_starts) > 1 else 0,
            "actual_start_rate_over_planned_duration_per_second": len(actual_starts) / stage_seconds,
            "p95_offer_to_actual_http_start_ms": quantiles(
                [(starts[op] - planned[op]["planned_offer_us"]) / 1000 for op in ops if op in starts],
                len(ops),
            )["p95_ms"],
            "message_index_range": [min(indices), max(indices)] if indices else None,
        })
        stage_latency[stage["name"]] = {
            "offer_to_http_accept": latency(planned, accepted, ops, lambda op, m: m[op]["planned_offer_us"]),
            "http_start_to_accept": latency(starts, accepted, ops, lambda op, m: m[op]),
            "offer_to_persistence_visibility": latency(planned, persisted, ops, lambda op, m: m[op]["planned_offer_us"]),
        }

    ack_keys = sorted(expected_targets)
    planned_target_offers = {
        key: planned[key[0]]["planned_offer_us"] for key in ack_keys
    }
    offer_to_commit = latency(
        planned_target_offers, committed, ack_keys, lambda key, m: m[key]
    )
    ack_to_commit = latency(ack_sent, committed, ack_keys, lambda key, m: m[key])
    load_end = max((r["elapsed_us"] for r in events["all_http_complete"]), default=None)
    db_rows = events["database_sample"]
    end_backlog = None
    if load_end is not None:
        end_sample = next((r for r in db_rows if r["elapsed_us"] >= load_end), None)
        if end_sample:
            end_backlog = end_sample["data"]["pending_targets"]
    drained = events.get("drained", [{}])[0].get("data", {}) if events.get("drained") else {}
    resource_rows = events["resources"]
    gateway_samples = [r["data"]["gateway"] for r in resource_rows]
    harness_samples = [r["data"]["harness_including_peers_and_observer"] for r in resource_rows]
    result = events.get("result", [{}])[-1].get("data", {}) if events.get("result") else {}
    final_ack = max(committed.values(), default=None)
    plan_seconds = sum(stage["messages"] / stage["rate_per_second"] for stage in plan["stages"])
    completed_seconds = (final_ack - load_start) / 1e6 if final_ack is not None else None
    cpu_window = None
    phase = {r["data"].get("phase"): r for r in events["phase_resources"]}
    if "low_started" in phase:
        start = phase["low_started"]
        drained_phase = phase.get("drained_idle_started")
        end = drained_phase or phase.get("all_http_complete")
        if end is not None:
            cpu_window = {
                "wall_seconds": (end["elapsed_us"] - start["elapsed_us"]) / 1e6,
                "gateway_cpu_seconds": end["data"]["gateway"]["cpu_seconds"] - start["data"]["gateway"]["cpu_seconds"],
                "gateway_rss_start_kib": start["data"]["gateway"]["rss_kib"],
                "gateway_rss_end_kib": end["data"]["gateway"]["rss_kib"],
                "complete_drain_observed": drained_phase is not None,
                "scope": "offer through durable drain" if drained_phase is not None else "partial offer window through all HTTP responses; durable drain incomplete",
                "not_energy_or_device_power": True,
            }

    report = {
        "status": "PASS" if result.get("passed") is True and not conflicts and len(committed) == len(expected_targets) else "INCOMPLETE_OR_FAILED",
        "run_directory": str(run_dir),
        "journey_sha256": digest(journey),
        "product_binary": config["binary"],
        "product_binary_blake3": config["binary_blake3"],
        "mode": config["mode"],
        "target_devices": config["target_devices"],
        "http_concurrency_cap": config["http_concurrency_max"],
        "plan": plan,
        "stage_execution": stages,
        "terminal_result": result,
        "counts": {
            "planned_offers": len(planned),
            "actual_http_starts": len(starts),
            "accepted": len(accepted),
            "persisted_visibility_samples": len(persisted),
            "raw_mqtt_receives": len(events["peer_receive"]),
            "unique_received_targets": len(received),
            "raw_ack_writes": len(events["ack_sent"]),
            "unique_ack_written_targets": len(ack_sent),
            "durably_committed_targets": len(committed),
            "fully_completed_messages": len(fully_completed),
            "duplicate_receive_markers": len(events["duplicate_peer_receive"]),
            "identity_conflicts": conflicts,
            "http_errors": len(events["http_failed"]),
            "background_errors": len(events["error"]),
        },
        "throughput": {
            "planned_messages_per_second_over_configured_schedule": config["messages"] / plan_seconds,
            "actual_http_accepts_per_second_from_load_start": len(accepted) / ((max(accepted.values()) - load_start) / 1e6) if accepted and max(accepted.values()) > load_start else None,
            "fully_acknowledged_messages_per_second_from_load_start": len(fully_completed) / completed_seconds if completed_seconds and completed_seconds > 0 else None,
            "fully_acknowledged_target_records_per_second_from_load_start": len(committed) / completed_seconds if completed_seconds and completed_seconds > 0 else None,
            "planned_offer_window_seconds": plan_seconds,
            "load_to_final_durable_ack_seconds": completed_seconds,
            "definitions": "offers are absolute scheduled starts; completion requires each target's MQTT PUBACK plus durable ledger terminal state; no per-request sequential self-throttle",
        },
        "latency": {
            "all_offer_to_http_accept_ms": latency(planned, accepted, expected_ops, lambda op, m: m[op]["planned_offer_us"]),
            "all_http_start_to_accept_ms": latency(starts, accepted, expected_ops, lambda op, m: m[op]),
            "offer_to_persistence_visibility_upper_bound_ms": latency(planned, persisted, expected_ops, lambda op, m: m[op]["planned_offer_us"]),
            "offer_to_durable_ack_visibility_upper_bound_ms": offer_to_commit,
            "ack_write_to_durable_ack_visibility_upper_bound_ms": ack_to_commit,
            "by_stage": stage_latency,
            "timing_limits": "SQLite observer polling interval is 100ms; persistence and durable ACK samples are upper bounds, not commit timestamps",
        },
        "backlog": {
            "peak_pending_targets": max((r["data"]["pending_targets"] for r in db_rows), default=None),
            "pending_targets_at_first_sample_after_http_offer_end": end_backlog,
            "pending_targets_after_drain": drained.get("residual_targets"),
            "sample_count": len(db_rows),
            "peak_oldest_pending_age_ms": max((r["data"]["oldest_pending_age_ms"] for r in db_rows if r["data"]["oldest_pending_age_ms"] is not None), default=None),
        },
        "resources": {
            "gateway_peak_rss_kib": max((s["rss_kib"] for s in gateway_samples), default=None),
            "harness_peak_rss_kib": max((s["rss_kib"] for s in harness_samples), default=None),
            "gateway_peak_os_threads": max((s["os_thread_count"] for s in gateway_samples if s["os_thread_count"] is not None), default=None),
            "harness_peak_os_threads": max((s["os_thread_count"] for s in harness_samples if s["os_thread_count"] is not None), default=None),
            "run_directory_peak_bytes": max((r["data"]["run_directory_bytes"] for r in resource_rows), default=None),
            "phase_samples": [r["data"] for r in events["phase_resources"]],
            "process_samples": len(resource_rows),
            "task_count_limit": "explicit test-owned tasks are recorded in configuration; Gateway async task count is not instrumented",
            "cpu_during_offer_and_drain": cpu_window,
            "recovery": "post-drain 60s idle; RSS returning to cold-start value is not a success criterion",
        },
        "limitations": [
            "One optimized normal-product build and one SQLite ordinary-ledger configuration; no before/after product-code comparison.",
            "Four synthetic loopback MQTT targets; no real provider service, mobile app, Windows UI, Android device, iOS, or watchOS.",
            "Small synthetic message bodies; this is not the 48 KiB message or 128 KiB frame ceiling test.",
            "OS threads are a proxy; async Gateway task count and energy are not measured.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps({"status": report["status"], "output": str(args.output), "counts": report["counts"], "throughput": report["throughput"]}, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
