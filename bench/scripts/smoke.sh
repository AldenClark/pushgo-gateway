#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

mkdir -p target/bench bench/results

export PUSHGO_BENCH_BASE_URL="${PUSHGO_BENCH_BASE_URL:-http://127.0.0.1:6666}"
export PUSHGO_BENCH_TOKEN="${PUSHGO_BENCH_TOKEN:-bench-token}"
export PUSHGO_BENCH_DB_URL="${PUSHGO_BENCH_DB_URL:-sqlite://$ROOT/target/bench/pushgo-bench.sqlite?mode=rwc}"
export PUSHGO_BENCH_RESULT_DIR="${PUSHGO_BENCH_RESULT_DIR:-$ROOT/bench/results/smoke-$(date -u +%Y%m%dT%H%M%S)}"
export PUSHGO_BENCH_VUS="${PUSHGO_BENCH_VUS:-2}"
export PUSHGO_BENCH_RPS="${PUSHGO_BENCH_RPS:-4}"
export PUSHGO_BENCH_DURATION="${PUSHGO_BENCH_DURATION:-3}"
export PUSHGO_BENCH_PAYLOAD_SIZE="${PUSHGO_BENCH_PAYLOAD_SIZE:-1024}"
mkdir -p "$PUSHGO_BENCH_RESULT_DIR"

export PUSHGO_DB_URL="$PUSHGO_BENCH_DB_URL"
export PUSHGO_HTTP_ADDR="${PUSHGO_HTTP_ADDR:-127.0.0.1:6666}"
export PUSHGO_TOKEN="$PUSHGO_BENCH_TOKEN"
export PUSHGO_PRIVATE_TRANSPORTS="${PUSHGO_PRIVATE_TRANSPORTS:-wss}"
export PUSHGO_OBSERVABILITY_PROFILE="${PUSHGO_OBSERVABILITY_PROFILE:-ops}"
export PUSHGO_OBSERVABILITY_DIAGNOSTICS_API_ENABLED="${PUSHGO_OBSERVABILITY_DIAGNOSTICS_API_ENABLED:-true}"
export PUSHGO_OBSERVABILITY_STATS_ENABLED="${PUSHGO_OBSERVABILITY_STATS_ENABLED:-true}"
export PUSHGO_OBSERVABILITY_LOG_LEVEL="${PUSHGO_OBSERVABILITY_LOG_LEVEL:-warn}"

cargo build --profile profiling --bin pushgo-gateway >"$PUSHGO_BENCH_RESULT_DIR/build.log" 2>&1
target/profiling/pushgo-gateway >"$PUSHGO_BENCH_RESULT_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
trap 'kill "$GATEWAY_PID" 2>/dev/null || true; wait "$GATEWAY_PID" 2>/dev/null || true' EXIT
export PUSHGO_BENCH_PID="$GATEWAY_PID"

for _ in $(seq 1 60); do
  if curl -fsS -H "Authorization: Bearer $PUSHGO_BENCH_TOKEN" "$PUSHGO_BENCH_BASE_URL/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS -H "Authorization: Bearer $PUSHGO_BENCH_TOKEN" "$PUSHGO_BENCH_BASE_URL/readyz" >/dev/null

python3 bench/scripts/run_scenario.py baseline_auth --out-name baseline_auth
python3 bench/scripts/run_scenario.py message_small_hot --out-name message_small_hot
python3 bench/scripts/run_scenario.py event_lifecycle --out-name event_lifecycle
python3 bench/scripts/summarize_results.py "$PUSHGO_BENCH_RESULT_DIR"

echo "$PUSHGO_BENCH_RESULT_DIR"
