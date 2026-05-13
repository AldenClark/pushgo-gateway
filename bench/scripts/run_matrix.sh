#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SCENARIO="${1:-message_small_hot}"
BASE_RESULT_DIR="${PUSHGO_BENCH_RESULT_DIR:-bench/results/matrix-$(date -u +%Y%m%dT%H%M%S)}"

run_case() {
  local name="$1"
  shift
  echo "== $name =="
  env "$@" PUSHGO_BENCH_RESULT_DIR="$BASE_RESULT_DIR" \
    python3 bench/scripts/run_scenario.py "$SCENARIO" --out-name "$name"
}

for workers in 2 4 8 16; do
  run_case "worker_count_$workers" PUSHGO_DISPATCH_WORKER_COUNT="$workers"
done

for capacity in 256 1024 4096 16384; do
  run_case "queue_capacity_$capacity" PUSHGO_DISPATCH_QUEUE_CAPACITY="$capacity"
done

for sqlite_connections in 1 2 4 8; do
  run_case "sqlite_max_connections_$sqlite_connections" PUSHGO_SQLITE_MAX_CONNECTIONS="$sqlite_connections"
done

for ttl_ms in 200 1000 2000 10000; do
  run_case "targets_cache_ttl_${ttl_ms}ms" PUSHGO_DISPATCH_TARGETS_CACHE_TTL_MS="$ttl_ms"
done

for log_level in warn info debug; do
  run_case "log_level_$log_level" PUSHGO_OBSERVABILITY_LOG_LEVEL="$log_level"
done

python3 bench/scripts/summarize_results.py "$BASE_RESULT_DIR"
