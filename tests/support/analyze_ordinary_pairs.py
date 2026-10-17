#!/usr/bin/env python3
"""Read-only analysis for C13's fixed normal-product MQTT comparison.

The input is a run plan, receipts, and journey.jsonl evidence. This program
does not launch Gateway, run SQL, create databases, or retry experiments. It
retains the fixed 136-message / 272-target formal denominators and reports
completed latency samples with their missing counts.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path

MESSAGES = 136
TARGETS = 272
OPS = tuple(f"c12-pair-{number:03}" for number in range(MESSAGES))
PREFLIGHT_OPS = tuple(f"c13-preflight-{number:03}" for number in range(3))
PEERS = ("mqtt-immediate", "mqtt-held")
ORDER = (("M", "P", "C"), ("C", "P", "M"), ("P", "M", "C"))
PHASES = {op: ("low" if i < 8 else "ramp" if i < 24 else "burst") for i, op in enumerate(OPS)}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for part in iter(lambda: handle.read(65536), b""):
            digest.update(part)
    return digest.hexdigest()


def read_json(path: Path | None):
    if path is None or not path.is_file():
        return None
    with path.open() as handle:
        return json.load(handle)


def quantiles(values, denominator, unit="ms"):
    values = sorted(values)
    result = {
        "unit": unit,
        "samples": len(values),
        "denominator": denominator,
        "missing": denominator - len(values),
        "method": "nearest rank ceil(p*n); completed samples only, missing retained separately",
    }
    for label, fraction in (("p50", .50), ("p95", .95), ("p99", .99)):
        result[label] = values[max(0, math.ceil(fraction * len(values)) - 1)] if values else None
    result["max"] = values[-1] if values else None
    return result


def difference(end, start):
    return (end - start) / 1000 if end is not None and start is not None else None


def phase_usage(rows, start_phase, end_phase, process):
    start = next((row for row in rows if row["data"].get("phase") == start_phase), None)
    end = next((row for row in rows if row["data"].get("phase") == end_phase), None)
    if start is None or end is None:
        return None
    seconds = (end["elapsed_us"] - start["elapsed_us"]) / 1e6
    cpu = end["data"][process]["cpu_seconds"] - start["data"][process]["cpu_seconds"]
    return {
        "cpu_seconds": cpu,
        "wall_seconds": seconds,
        "one_core_fraction": cpu / seconds if seconds else None,
        "rss_start_kib": start["data"][process]["rss_kib"],
        "rss_end_kib": end["data"][process]["rss_kib"],
    }


def read_journey(path: Path):
    rows, malformed = [], []
    if not path.is_file():
        return rows, ["journey.jsonl missing; run not started or no evidence produced"]
    with path.open() as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("kind"), str)
                    or not isinstance(row.get("elapsed_us"), int)
                    or not isinstance(row.get("data"), dict)
                ):
                    raise ValueError("missing event timestamp/data")
                rows.append(row)
            except (AttributeError, ValueError, TypeError) as error:
                malformed.append(f"line {line_number}: {type(error).__name__}")
    return rows, malformed


def summarize_run(spec):
    directory = Path(spec["directory"])
    journey = directory / "journey.jsonl"
    rows, malformed = read_journey(journey)
    events = collections.defaultdict(list)
    for row in rows:
        events[row["kind"]].append(row)

    run_mode = events["run_mode"][0]["data"].get("mode") if events["run_mode"] else None
    configuration = events["configuration"][0]["data"] if events["configuration"] else None
    control = events["control_preflight"][0]["data"] if events["control_preflight"] else None
    expected_ops = OPS
    recorded_ops = set(OPS) | set(PREFLIGHT_OPS)
    phases = PHASES
    peers_by_device = {
        row["data"].get("device_key"): row["data"].get("peer")
        for row in events["peer_connected"]
        if row["data"].get("device_key") is not None
    }

    planned, started, accepted, received, acked, committed, released = {}, {}, {}, {}, {}, {}, {}
    duplicates = collections.Counter()
    unexpected, identity_conflicts, negative = [], [], []
    identity = {}
    for row in rows:
        kind, data, stamp = row["kind"], row["data"], row["elapsed_us"]
        op = data.get("op_id")
        if op is not None and op not in recorded_ops:
            unexpected.append({"kind": kind, "op_id": op})
            continue
        target = None
        if "device_key" in data and op is not None:
            peer = data.get("peer", peers_by_device.get(data["device_key"], "unknown"))
            target = (op, peer)
            if peer not in PEERS:
                unexpected.append({"kind": kind, "op_id": op, "peer": peer})

        mapping, key, value = None, None, stamp
        if kind == "planned_offer":
            mapping, key, value = planned, op, data.get("planned_offer_us")
        elif kind == "http_started":
            mapping, key, value = started, op, data.get("actual_http_start_us")
        elif kind == "http_accepted":
            mapping, key = accepted, op
        elif kind == "peer_receive":
            mapping, key = received, target
        elif kind == "ack_sent":
            mapping, key = acked, target
        elif kind == "ack_commit_visible_upper_bound":
            mapping, key = committed, target
        elif kind == "body_release_commit_visible_upper_bound":
            mapping, key = released, op
        if mapping is not None:
            if key in mapping:
                duplicates[kind] += 1
            mapping.setdefault(key, value)
        if kind == "duplicate_peer_receive":
            duplicates[kind] += 1
        if op and data.get("message_id"):
            old = identity.setdefault(op, {})
            for field in ("message_id", "delivery_id", "body_hash"):
                if data.get(field) is not None:
                    if field in old and old[field] != data[field]:
                        identity_conflicts.append({"op_id": op, "field": field})
                    old[field] = data[field]

    receipt_path = Path(spec["receipt"]) if spec.get("receipt") else None
    receipt = read_json(receipt_path)
    receipt_exit = None
    evidence_valid = False
    resource_stop = None
    if isinstance(receipt, dict):
        receipt_exit = receipt.get("exit_code", receipt.get("returncode"))
        evidence_valid = receipt.get("evidence_valid") is True
        stop_fields = ("stop", "resource_stop", "resource_stop_reason", "stop_reason")
        if any(field in receipt for field in stop_fields):
            resource_stop = any(bool(receipt.get(field)) for field in stop_fields)

    valid_targets = tuple((op, peer) for op in expected_ops for peer in PEERS)
    received_count = sum(target in received for target in valid_targets)
    acked_count = sum(target in acked for target in valid_targets)
    terminal_count = sum(target in committed for target in valid_targets)
    accepted_count = sum(op in accepted for op in expected_ops)
    actual_accepted_count = len(accepted)
    release_count = sum(op in released for op in expected_ops)
    persisted_count = None
    results = [row["data"] for row in events["result"]]
    result = results[-1] if results else None
    if isinstance(result, dict) and isinstance(result.get("persisted_messages"), int):
        persisted_count = result["persisted_messages"]

    control_ok = bool(
        control
        and control.get("passed") is True
        and control.get("platform") == "mqtt"
        and control.get("original_device_keys_preserved") == 2
        and control.get("original_device_ids_preserved") == 2
        and control.get("canonical_active_subscriptions") == 2
        and control.get("selected_targets") == 2
    )
    configuration_ok = bool(
        configuration
        and configuration.get("mode") == "formal"
        and configuration.get("qa") is False
        and configuration.get("messages") == MESSAGES
        and configuration.get("targets") == TARGETS
    )
    load_anchor = events["load_started"][0]["data"]["planned_offer_start_us"] if events["load_started"] else None
    schedule_ok = bool(load_anchor is not None and all(
        planned.get(op) == load_anchor + 1000*(i*500 if i < 8 else 4000+(i-8)*125 if i < 24 else 6000+(i-24)*10)
        for i, op in enumerate(OPS)))
    target_two_ok = bool(
        all(row["data"].get("expected_targets") == 2 for row in events["http_accepted"])
        and len(events["http_accepted"]) == MESSAGES
    )
    persisted_ok = persisted_count == MESSAGES
    all_counts_positive = all(
        count == expected
        for count, expected in (
            (len(planned), MESSAGES),
            (len(started), MESSAGES),
            (accepted_count, MESSAGES),
            (persisted_count, MESSAGES),
            (received_count, TARGETS),
            (acked_count, TARGETS),
            (terminal_count, TARGETS),
            (release_count, MESSAGES),
        )
    )

    drained = events["drained"][0]["elapsed_us"] if events["drained"] else None
    late_kinds = (
        "http_accepted",
        "peer_receive",
        "ack_sent",
        "ack_commit_visible_upper_bound",
        "body_release_commit_visible_upper_bound",
    )
    late = collections.Counter(
        row["kind"]
        for row in rows
        if drained is not None and row["elapsed_us"] > drained and row["kind"] in late_kinds
    )
    failures = events["http_failed"] + events["error"]
    duplicate_events = dict(duplicates)
    passed = bool(
        run_mode == "formal"
        and evidence_valid
        and receipt.get("binary_unchanged") is True
        and receipt_exit == 0
        and not resource_stop
        and result
        and result.get("passed") is True
        and result.get("mode") == "formal"
        and result.get("messages") == MESSAGES
        and result.get("targets") == TARGETS
        and result.get("persisted_messages") == MESSAGES
        and result.get("received_targets") == TARGETS
        and result.get("puback_targets") == TARGETS
        and result.get("positive_terminal_targets") == TARGETS
        and result.get("body_released") == MESSAGES
        and result.get("residual_targets") == 0
        and resource_stop is False
        and configuration_ok
        and schedule_ok
        and control_ok
        and target_two_ok
        and persisted_ok
        and all_counts_positive
        and not malformed
        and not unexpected
        and not identity_conflicts
        and not failures
    )
    state = "complete_pass" if passed else ("failed_or_incomplete" if rows else "not_run")

    def samples(items, begin, end):
        values = []
        for item in items:
            a, b = begin(item), end(item)
            if a is not None and b is not None:
                value = difference(b, a)
                if value < 0:
                    negative.append({"item": item, "begin_us": a, "end_us": b})
                values.append(value)
        return values

    admission = {}
    for phase in ("all", "low", "ramp", "burst"):
        ops = expected_ops if phase == "all" else tuple(op for op in expected_ops if phases.get(op) == phase)
        admission[phase] = {
            "planned_to_http_start": quantiles(samples(ops, planned.get, started.get), len(ops)),
            "http_start_to_success": quantiles(samples(ops, started.get, accepted.get), len(ops)),
            "planned_to_success": quantiles(samples(ops, planned.get, accepted.get), len(ops)),
        }

    target_latency = {}
    for phase in ("all", "low", "ramp", "burst"):
        target_latency[phase] = {}
        for peer in ("all", *PEERS):
            cohort = tuple(
                target for target in valid_targets
                if (phase == "all" or phases.get(target[0]) == phase)
                and (peer == "all" or target[1] == peer)
            )
            target_latency[phase][peer] = {
                "planned_to_receive": quantiles(samples(cohort, lambda key: planned.get(key[0]), received.get), len(cohort)),
                "receive_to_ack_sent": quantiles(samples(cohort, received.get, acked.get), len(cohort)),
                "ack_sent_to_commit_visible": quantiles(samples(cohort, acked.get, committed.get), len(cohort)),
                "planned_to_commit_visible": quantiles(samples(cohort, lambda key: planned.get(key[0]), committed.get), len(cohort)),
            }

    passed = passed and not negative
    state = "complete_pass" if passed else ("failed_or_incomplete" if rows else "not_run")

    phase_rows = events["phase_resources"]
    resource_rows = events["resources"]
    combined = resource_rows + phase_rows
    resources = {"phase_snapshots": phase_rows, "sample_count": len(resource_rows)}
    for process in ("gateway", "harness_including_peers_and_observer"):
        readings = [(row["elapsed_us"], row["data"][process]) for row in combined if process in row["data"]]
        resources[process] = {
            "peak_rss_kib": max((value["rss_kib"] for _, value in readings), default=None),
            "last_sample": max(readings, default=None, key=lambda pair: pair[0]),
            "active": phase_usage(phase_rows, "warm_idle_complete", "drained_idle_started", process),
            "warm_idle": phase_usage(phase_rows, "http_warm_complete", "warm_idle_complete", process),
            "post_drain_idle": phase_usage(phase_rows, "drained_idle_started", "idle_complete", process),
        }
    resources["established_tcp_snapshots"] = [
        {"elapsed_us": row["elapsed_us"], **row["data"]["established_tcp"]}
        for row in phase_rows if "established_tcp" in row["data"]
    ]
    resources["tokio_alive_task_data"] = "unavailable; no QA/runtime task instrumentation is used"

    database_rows = events["database_sample"]
    databases = [row["data"] for row in database_rows]
    database = {
        "configurations": [row["data"] for row in events["database_configuration"]],
        "peak_pending_targets": max((row["pending_targets"] for row in databases), default=None),
        "peak_payload_count": max((row["payload_count"] for row in databases), default=None),
        "peak_oldest_pending_age_ms": max(
            (row["oldest_pending_age_ms"] for row in databases if row["oldest_pending_age_ms"] is not None),
            default=None,
        ),
        "peak_expired_payload_count": max((row["expired_payload_count"] for row in databases), default=None),
        "final_sample": database_rows[-1] if database_rows else None,
        "peak_database_logical_bytes": max(
            (sum(file["logical_bytes"] for file in row["data"]["database_files"]) for row in resource_rows),
            default=None,
        ),
        "final_database_files": resource_rows[-1]["data"].get("database_files") if resource_rows else None,
    }

    load = events["load_started"][0]["data"].get("planned_offer_start_us") if events["load_started"] else None
    last_offer = max(planned.values(), default=None)
    first_offer = min(planned.values(), default=None)
    final_accept = max((accepted[op] for op in expected_ops if op in accepted), default=None)
    final_commit = max((committed[key] for key in valid_targets if key in committed), default=None)
    all_http_complete = events["all_http_complete"][0]["elapsed_us"] if events["all_http_complete"] else None

    def rate(count, end):
        if load is None or end is None or end <= load:
            return None
        return {
            "count": count,
            "elapsed_from_load_start_seconds": (end - load) / 1e6,
            "per_second_over_this_finite_window": count * 1e6 / (end - load),
            "interpretation": "finite cohort rate; not sustained capacity",
        }

    boundary = max(last_offer, all_http_complete) if last_offer is not None and all_http_complete is not None else None
    first_end_sample = next(
        (row for row in database_rows if boundary is not None and row["elapsed_us"] >= boundary),
        None,
    )
    input_end_backlog = None
    if first_end_sample is not None:
        input_end_backlog = {
            "pending_targets": first_end_sample["data"].get("pending_targets"),
            "sample_elapsed_us": first_end_sample["elapsed_us"],
            "boundary_elapsed_us": boundary,
            "offset_after_last_scheduled_offer_us": first_end_sample["elapsed_us"] - last_offer,
            "offset_after_all_http_complete_us": first_end_sample["elapsed_us"] - all_http_complete,
            "definition": "first 100ms database sample at or after both final planned offer and all_http_complete; visibility sample, not an instantaneous queue or COMMIT timestamp",
        }

    unknown_http = [op for op in expected_ops if op in started and op not in accepted]
    duplicate_receive_events = len(events["duplicate_peer_receive"])
    counts = {
        "planned_messages_denominator": MESSAGES,
        "planned_targets_denominator": TARGETS,
        "planned_offer_events": len(planned),
        "http_started_events": len(events["http_started"]),
        "actual_http_started_unique": len(started),
        "successful_http_acceptances": actual_accepted_count,
        "persisted_messages_from_result": persisted_count,
        "received_targets": received_count,
        "puback_sent_targets": acked_count,
        "raw_receive_events": len(events["peer_receive"]),
        "raw_puback_events": len(events["ack_sent"]),
        "repeated_target_receives": duplicates.get("peer_receive", 0),
        "repeated_puback_sends": duplicates.get("ack_sent", 0),
        "duplicate_receive_markers": duplicate_receive_events,
        "positive_terminal_targets": terminal_count,
        "released_bodies": release_count,
        "missing_planned_offers": max(0, MESSAGES - len(planned)),
        "missing_http_starts": max(0, MESSAGES - len(started)),
        "missing_acceptances": max(0, MESSAGES - accepted_count),
        "missing_persisted_messages": max(0, MESSAGES - persisted_count) if persisted_count is not None else None,
        "missing_receives": max(0, TARGETS - received_count),
        "missing_pubacks": max(0, TARGETS - acked_count),
        "missing_terminal_targets": max(0, TARGETS - terminal_count),
        "missing_body_releases": max(0, MESSAGES - release_count),
        "http_failed_events": len(events["http_failed"]),
        "background_error_events": len(events["error"]),
        "duplicate_events": sum(duplicates.values()),
        "duplicate_event_kinds": duplicate_events,
        "late_post_drain_events": dict(late),
        "persisted_result_residual_targets": result.get("residual_targets") if result else None,
    }
    return {
        "group": spec["group"],
        "version": spec["version"],
        "directory": str(directory),
        "mode": run_mode,
        "state": state,
        "performance_comparison_eligible": passed and not negative,
        "journey_sha256": sha256(journey) if journey.is_file() else None,
        "receipt": str(receipt_path) if receipt_path else None,
        "receipt_sha256": sha256(receipt_path) if receipt_path and receipt_path.is_file() else None,
        "receipt_exit_code": receipt_exit,
        "receipt_evidence_valid": evidence_valid,
        "receipt_resource_stop": resource_stop,
        "configuration": configuration,
        "fixed_formal_schedule_verified": schedule_ok,
        "control_preflight": control,
        "counts": counts,
        "errors": {
            "malformed_input": malformed,
            "unexpected_ops_or_peers": unexpected,
            "identity_conflicts": identity_conflicts,
            "negative_latency_samples": negative,
            "events": failures,
            "http_started_without_success_response": unknown_http,
            "interpretation": "failed/timeout/no-response admissions may have unknown COMMIT outcome; not assumed rejected or removed from the denominator",
        },
        "results": results,
        "admission_ms": admission,
        "target_ms": target_latency,
        "body_release_ms": quantiles(samples(expected_ops, planned.get, released.get), MESSAGES),
        "resources": resources,
        "database": database,
        "input_end_backlog": input_end_backlog,
        "rates": {
            "planned_rates_messages_per_second": {"low": 2, "ramp": 8, "burst": 100},
            "planned_offer_span_seconds": (last_offer - first_offer) / 1e6 if last_offer is not None and first_offer is not None else None,
            "supply_interarrival_rate_messages_per_second": (len(planned) - 1) * 1e6 / (last_offer - first_offer) if last_offer is not None and first_offer is not None and last_offer > first_offer else None,
            "successful_http_acceptances": rate(accepted_count, final_accept),
            "positive_terminal_targets": rate(terminal_count, final_commit),
            "all_terminal_completion_time_from_load_start_seconds": (final_commit - load) / 1e6 if terminal_count == TARGETS and final_commit is not None and load is not None else None,
            "drain_after_last_scheduled_offer_seconds": (events["drained"][0]["elapsed_us"] - last_offer) / 1e6 if events["drained"] and last_offer is not None else None,
            "scope": "finite mixed-rate cohort; not sustainable capacity or an SLA",
        },
    }


def compact(run):
    gateway = run["resources"]["gateway"]
    admission = run["admission_ms"]["all"]
    return {
        "group": run["group"],
        "version": run["version"],
        "state": run["state"],
        "messages_accepted": run["counts"]["successful_http_acceptances"],
        "persisted_messages": run["counts"]["persisted_messages_from_result"],
        "targets_committed": run["counts"]["positive_terminal_targets"],
        "unfinished": run["counts"]["missing_terminal_targets"],
        "http_start_to_success_p95_ms": admission["http_start_to_success"]["p95"],
        "offer_to_success_p50_ms": admission["planned_to_success"]["p50"],
        "offer_to_success_p95_ms": admission["planned_to_success"]["p95"],
        "offer_to_success_p99_ms": admission["planned_to_success"]["p99"],
        "offer_to_commit_p95_ms": run["target_ms"]["all"]["all"]["planned_to_commit_visible"]["p95"],
        "offer_to_commit_p99_ms": run["target_ms"]["all"]["all"]["planned_to_commit_visible"]["p99"],
        "ack_to_commit_p95_ms": run["target_ms"]["all"]["all"]["ack_sent_to_commit_visible"]["p95"],
        "active_cpu_seconds": gateway["active"]["cpu_seconds"] if gateway["active"] else None,
        "warm_idle_cpu_seconds": gateway["warm_idle"]["cpu_seconds"] if gateway["warm_idle"] else None,
        "idle_cpu_seconds": gateway["post_drain_idle"]["cpu_seconds"] if gateway["post_drain_idle"] else None,
        "peak_rss_mib": gateway["peak_rss_kib"] / 1024 if gateway["peak_rss_kib"] is not None else None,
        "idle_end_rss_mib": gateway["post_drain_idle"]["rss_end_kib"] / 1024 if gateway["post_drain_idle"] else None,
        "peak_pending_targets": run["database"]["peak_pending_targets"],
        "input_end_pending_targets": run["input_end_backlog"]["pending_targets"] if run["input_end_backlog"] else None,
        "drain_seconds": run["rates"]["drain_after_last_scheduled_offer_seconds"],
    }


def paired_results(runs):
    by_key = {(run["group"], run["version"]): run for run in runs}
    metric_names = (
        "http_start_to_success_p95_ms", "offer_to_success_p50_ms", "offer_to_success_p95_ms",
        "offer_to_success_p99_ms", "offer_to_commit_p95_ms", "offer_to_commit_p99_ms",
        "ack_to_commit_p95_ms", "active_cpu_seconds", "warm_idle_cpu_seconds",
        "idle_cpu_seconds", "peak_rss_mib", "idle_end_rss_mib", "drain_seconds",
    )
    rows = []
    for baseline in ("M", "P"):
        for group in (1, 2, 3):
            before, after = by_key.get((group, baseline)), by_key.get((group, "C"))
            eligible = bool(before and after and before["performance_comparison_eligible"] and after["performance_comparison_eligible"])
            a, b = compact(before) if before else {}, compact(after) if after else {}
            metrics = {}
            for metric in metric_names:
                left, right = a.get(metric), b.get(metric)
                metrics[metric] = {
                    "baseline": left,
                    "candidate": right,
                    "absolute_delta": right - left if eligible and left is not None and right is not None else None,
                    "relative_delta": (right - left) / left if eligible and left is not None and left > 0 and right is not None else None,
                }
            rows.append({
                "group": group,
                "comparison": f"{baseline}/C",
                "direction": "C minus baseline; positive is higher",
                "eligible": eligible,
                "metrics": metrics,
            })
    return rows


def number(value):
    return "—" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)


def markdown(report):
    lines = [
        "# C13 fixed normal-product paired results", "",
        "Latency percentiles use completed samples and retain the fixed 136-message / 272-target denominators and missing counts.", "",
        "|Group|Version|State|Accepted / persisted|Committed / unfinished|Start→success p95 ms|Offer→success p50 / p95 / p99 ms|Offer→commit p95 / p99 ms|Active CPU s|Peak / idle RSS MiB|Peak / input-end backlog|Drain s|",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["nine_run_table"]:
        lines.append(
            f"|{row['group']}|{row['version']}|{row['state']}|{row['messages_accepted']} / {row['persisted_messages']}|"
            f"{row['targets_committed']} / {row['unfinished']}|{number(row['http_start_to_success_p95_ms'])}|"
            f"{number(row['offer_to_success_p50_ms'])} / {number(row['offer_to_success_p95_ms'])} / {number(row['offer_to_success_p99_ms'])}|"
            f"{number(row['offer_to_commit_p95_ms'])} / {number(row['offer_to_commit_p99_ms'])}|"
            f"{number(row['active_cpu_seconds'])}|{number(row['peak_rss_mib'])} / {number(row['idle_end_rss_mib'])}|"
            f"{number(row['peak_pending_targets'])} / {number(row['input_end_pending_targets'])}|{number(row['drain_seconds'])}|"
        )
    lines += ["", "Positive paired delta means C is higher. Ineligible pairs have no computed deltas; no statistical significance is claimed.", "",
              "|Comparison|Group|Eligible|Δ start→success p95 ms|Δ offer→success p95 ms|Δ offer→commit p95 ms|Δ active CPU s|Δ peak RSS MiB|",
              "|---|---:|---|---:|---:|---:|---:|---:|"]
    for row in report["paired_differences"]:
        metrics = row["metrics"]
        lines.append(
            f"|{row['comparison']}|{row['group']}|{row['eligible']}|"
            f"{number(metrics['http_start_to_success_p95_ms']['absolute_delta'])}|"
            f"{number(metrics['offer_to_success_p95_ms']['absolute_delta'])}|"
            f"{number(metrics['offer_to_commit_p95_ms']['absolute_delta'])}|"
            f"{number(metrics['active_cpu_seconds']['absolute_delta'])}|"
            f"{number(metrics['peak_rss_mib']['absolute_delta'])}|"
        )
    lines += ["", "Limits:", ""] + [f"- {limit}" for limit in report["limits"]]
    if report["input_warnings"]:
        lines += ["", "Input warnings:", ""] + [f"- {warning}" for warning in report["input_warnings"]]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True, help="existing JSON array of nine run specs")
    parser.add_argument("--output", type=Path, required=True, help="new JSON output path; existing files are refused")
    parser.add_argument("--markdown", type=Path, required=True, help="new Markdown output path; existing files are refused")
    args = parser.parse_args()
    plan = read_json(args.runs)
    if not isinstance(plan, list):
        parser.error("--runs must be an existing JSON array; no experiments will be launched")
    if args.output.resolve() == args.markdown.resolve() or args.output.resolve() == args.runs.resolve() or args.markdown.resolve() == args.runs.resolve():
        parser.error("input and output paths must be distinct")
    for output in (args.output, args.markdown):
        if output.exists():
            parser.error(f"refusing to overwrite existing output: {output}")

    expected_order = [(group, version) for group, versions in enumerate(ORDER, 1) for version in versions]
    actual = [(int(spec["group"]), spec["version"]) for spec in plan]
    if len(set(actual)) != len(actual):
        parser.error("duplicate group/version input; refusing to select a best run")
    warnings = []
    if actual != expected_order:
        warnings.append(f"run-plan order/slots differ from fixed nine-run order; supplied={actual}; expected={expected_order}")
    given = {(int(spec["group"]), spec["version"]): spec for spec in plan}
    runs = []
    for group, version in expected_order:
        spec = given.get((group, version))
        if spec is None:
            base = args.runs.parent.parent
            spec = {
                "group": group,
                "version": version,
                "directory": str(base / "evidence" / f"g{group}-{version}"),
                "receipt": str(base / "audit" / f"run-g{group}-{version}.receipt.json"),
            }
            warnings.append(f"missing plan slot g{group}-{version}; denominator retained and slot is ineligible")
        runs.append(summarize_run(spec))
    pairs = paired_results(runs)
    report = {
        "schema": "c13-normal-paired-analysis-v1",
        "analysis_script_sha256": sha256(Path(__file__)),
        "run_plan_sha256": sha256(args.runs),
        "input_warnings": warnings,
        "fixed_order": [{"group": group, "versions": versions} for group, versions in enumerate(ORDER, 1)],
        "nine_run_table": [compact(run) for run in runs],
        "paired_differences": pairs,
        "runs": runs,
        "limits": [
            "Only formal-mode runs with a valid receipt, no resource stop, positive complete cohort counts, MQTT two-target preflight, and no evidence errors are eligible for comparison.",
            "Offer→success and all other percentiles use completed samples only; every report retains fixed 136-message / 272-target denominators and reports missing samples.",
            "Input-end backlog is the first 100ms database sample after both the final planned offer and all_http_complete; it is a visibility sample with explicit offsets, not an instantaneous queue or COMMIT timestamp.",
            "Offer→COMMIT is an independent100ms read visibility upper bound including polling, read, and scheduling delay. ACK→visible still includes observer delay.",
            "CPU/RSS are process_usage snapshots for Gateway and harness (including MQTT peers and observer). SQLite is embedded in Gateway CPU/RSS, not a separate process measurement.",
            "Established TCP endpoint snapshots are reported only when available from lsof. Tokio live-task counts are unavailable; no QA instrumentation is used.",
            "Finite cohort rates include downstream hold and do not measure sustained capacity or an SLA. Three groups support only descriptive directional comparison, not statistical significance.",
            "Host filesystem, thermal, and background state are not reset. No Provider, native client storage, TLS/WSS/QUIC, or 300s maintenance performance is measured.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists() or args.markdown.exists():
        parser.error("an output appeared during analysis; refusing to overwrite it")
    with args.output.open("x") as handle:
        handle.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    with args.markdown.open("x") as handle:
        handle.write(markdown(report))
    print(json.dumps({
        "output": str(args.output),
        "markdown": str(args.markdown),
        "states": collections.Counter(run["state"] for run in runs),
        "all_nine_complete": all(run["performance_comparison_eligible"] for run in runs),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
