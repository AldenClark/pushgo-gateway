# PushGo Gateway Benchmarking

This directory contains a lightweight benchmark and resource-monitoring setup for `pushgo-gateway`. It is designed to expose bottlenecks, not to produce polished reports.

The scripts do not modify public APIs and do not require a heavy benchmark platform. They use Python standard library HTTP clients plus optional shell wrappers. Raw HTTP results, resource samples, optional legacy diagnostics samples, and simple summaries are written under `bench/results/` by default.

## Environment

Supported benchmark variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PUSHGO_BENCH_BASE_URL` | `http://127.0.0.1:6666` | Gateway URL under test |
| `PUSHGO_BENCH_TOKEN` | empty | Bearer token used by benchmark requests |
| `PUSHGO_BENCH_DB_URL` | `sqlite://target/bench/pushgo-bench.sqlite?mode=rwc` | Bench database URL and DB/WAL size source |
| `PUSHGO_BENCH_CHANNEL_ID` | empty | Existing channel id to reuse; otherwise scripts create mock channels |
| `PUSHGO_BENCH_CHANNEL_PASSWORD` | `bench-password-2026` | Mock channel password |
| `PUSHGO_BENCH_VUS` | `4` | Worker threads / virtual users |
| `PUSHGO_BENCH_RPS` | `20` | Operation rate target |
| `PUSHGO_BENCH_DURATION` | `10` | Scenario duration in seconds |
| `PUSHGO_BENCH_PAYLOAD_SIZE` | `1024` | Payload body target size |
| `PUSHGO_BENCH_RESULT_DIR` | `bench/results` | Result root or exact smoke root |
| `PUSHGO_BENCH_PID` | empty | Gateway PID for resource sampling |
| `PUSHGO_BENCH_WS_HOLD_SECONDS` | `0.5` | Hold time for each raw `/private/ws` handshake in `private_wss_profile` |

Common gateway-side variables for the local benchmark gateway are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PUSHGO_RUNTIME_PROFILE` | `small` | Gateway runtime preset for local bench startup |
| `PUSHGO_PRIVATE_TRANSPORTS` | `wss` | Private transport surface to enable during private-path scenarios |
| `PUSHGO_OBSERVABILITY_LOG_LEVEL` | `warn` | Gateway log verbosity |

Sender payloads must not include `op_id` in gateway `1.2.11+`. The gateway generates `op_id`, returns it in submit responses, and exposes sender-facing lookup at `/send_status/{op_id}`. The benchmark captures that response value in `message_sender_status_lookup`.

## Start A Bench Gateway

Use an isolated SQLite database. Do not point benchmark scripts at production databases.

```bash
export PUSHGO_BENCH_TOKEN=bench-token
bench/scripts/run_gateway.sh
```

In another shell:

```bash
export PUSHGO_BENCH_BASE_URL=http://127.0.0.1:6666
export PUSHGO_BENCH_TOKEN=bench-token
export PUSHGO_BENCH_DB_URL="sqlite://$PWD/target/bench/pushgo-bench.sqlite?mode=rwc"
export PUSHGO_BENCH_PID="$(pgrep -n pushgo-gateway)"
```

Clean bench data:

```bash
rm -f target/bench/pushgo-bench.sqlite target/bench/pushgo-bench.sqlite-*
```

## Smoke Benchmark

Runs a local gateway, then executes the required closed loop for `/readyz`, `/message`, and `/event` with resource monitoring:

```bash
bench/scripts/smoke.sh
```

Smoke defaults are intentionally small: `2` VUs, `4` ops/sec, `3` seconds per scenario. Increase them with the env vars above.

## Single Scenario

```bash
python3 bench/scripts/run_scenario.py --list
python3 bench/scripts/run_scenario.py message_small_hot
```

Each scenario writes:

| File | Meaning |
| --- | --- |
| `config.json` | Sanitized benchmark config |
| `scenario.json` | Purpose, pressure model, expected bottlenecks, metrics, judgement, next triage |
| `*-seed.json` | Mock channel/device/subscription data created through gateway APIs |
| `http-results.jsonl` | Raw request status, latency, path, error, and response body sample |
| `resources.csv` | PID-based resource samples if `PUSHGO_BENCH_PID` is set |
| `resources.diagnostics.jsonl` | Raw diagnostics API samples when available |
| `summary.json` / `summary.md` | Simple aggregate and bottleneck notes |

## Full Run And Matrix

Run all benchmark scenarios:

```bash
bench/scripts/run_all.sh
```

Run the parameter comparison matrix for a core scenario:

```bash
bench/scripts/run_matrix.sh message_small_hot
bench/scripts/run_matrix.sh dispatch_private_broadcast
```

The matrix varies client-side virtual users, request rate, payload size, and benchmark process log level. Server-side runtime profile changes are startup-time settings; restart the gateway with the tested `PUSHGO_RUNTIME_PROFILE` before comparing those runs.

Generate a simple combined summary:

```bash
python3 bench/scripts/summarize_results.py bench/results
```

This writes `docs/performance/pushgo-gateway-benchmark-summary.json` and `.md`.

## Test Data

Generate a standalone mock data file:

```bash
python3 bench/scripts/generate_data.py --channels 8 --devices 500 --messages 64
```

The data contains mock channels, devices, subscriptions, normal messages, markdown bodies, image URLs, event lifecycle payloads, thing attributes, metadata, tags, severity, TTL, URL, and ciphertext fields. Scenario scripts seed live data through `/device/register`, `/channel/device`, and `/channel/subscribe`.

## Scenario Coverage

| Requirement | Scenario(s) |
| --- | --- |
| Baseline `/healthz`, `/readyz`, lightweight API, normal/missing/wrong token | `baseline_auth` |
| Message small/large/complex/ciphertext/status-lookup/multi-channel/hot-channel writes | `message_small_hot`, `message_large_markdown`, `message_complex_payload`, `message_sender_status_lookup`, `message_multi_channel` |
| Dispatch single-channel multi-device broadcast, provider unreachable/mock failure, client pressure | `dispatch_private_broadcast`, `provider_unreachable_mock`, `run_matrix.sh` |
| Event create/update/close and repeated lifecycle | `event_lifecycle` |
| Thing create/update/archive/delete, hot object updates, message associated with thing | `thing_lifecycle` |
| Device register, channel route, subscribe, unsubscribe churn | `device_subscription_churn` |
| Offline pull and ACK, empty and non-empty pulls | `offline_pull_ack` |
| ntfy, ServerChan, Bark compatibility paths | `compat_ingress` |
| Private WSS profile, websocket handshake/hold path when enabled, with fallback pressure covered by pull/ack | `private_wss_profile`, `offline_pull_ack` |
| Stepped load breakpoint | `ramp_message` |
| Spike traffic and recovery | `spike_message` |
| Long-running stability | `soak_message` with `PUSHGO_BENCH_DURATION=600` or `1800` |
| Parameter comparison | `run_matrix.sh` |

Every scenario records purpose, pressure model, likely bottlenecks, collected metrics, judgement standard, and next triage direction in `scenario.json` and `summary.md`.

## Resource Metrics

`resource_monitor.py` samples by PID every second by default:

| Metric group | Fields |
| --- | --- |
| Gateway process | CPU %, RSS, thread count, fd count |
| Host | system CPU %, load average, available memory |
| TCP | ESTABLISHED, TIME_WAIT, CLOSE_WAIT |
| Storage | SQLite DB and WAL byte size |
| IO/network | disk and network counters where the OS exposes them |
| Gateway internals | legacy diagnostics/private metrics and memory snapshots when those endpoints are present |

Unavailable metrics are written as `unavailable` rather than guessed. The current release test contract does not require diagnostics endpoints; use `resources.csv`, HTTP results, and gateway logs as the primary benchmark evidence.

Manual monitor:

```bash
python3 bench/scripts/resource_monitor.py --pid "$PUSHGO_BENCH_PID" --out bench/results/manual-resources.csv
```

## Capacity Scope

Keep these conclusions separate:

1. Gateway HTTP inbound capacity: measured by HTTP status, RPS, latency, and auth/error path results.
2. Gateway internal dispatch capacity: inferred from private dispatch fanout, DB/WAL growth, HTTP latency/status, gateway logs, CPU/RSS/fd/TCP trends, and diagnostics when available.
3. Real APNS/FCM/WNS provider delivery capacity: not measured unless real provider credentials, token service, and provider endpoints are deliberately configured. Private/mock/local results must not be reported as real push provider capacity.

## Reading Results

Use `summary.md` for the fast view, then inspect raw files before making tuning decisions. Treat a bottleneck as credible only when HTTP metrics and resource samples point in the same direction, for example:

- Rising p99 with low CPU and fast errors: inspect storage locks, queue capacity, and target cache.
- Rising CPU with stable DB/WAL: inspect JSON parsing, validation, payload construction, and tracing level.
- Rising RSS/fd/TCP during `private_wss_profile`, `spike_message`, or `soak_message`: inspect connection/session cleanup.
- Large or constantly growing WAL: inspect SQLite write amplification, checkpoints, and connection settings.
