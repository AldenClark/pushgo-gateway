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

for vus in 1 2 4 8; do
  run_case "client_vus_$vus" PUSHGO_BENCH_VUS="$vus"
done

for rps in 5 20 50 100; do
  run_case "client_rps_$rps" PUSHGO_BENCH_RPS="$rps"
done

for payload_size in 512 1024 4096 24576; do
  run_case "payload_${payload_size}b" PUSHGO_BENCH_PAYLOAD_SIZE="$payload_size"
done

for log_level in warn info; do
  run_case "client_log_level_$log_level" PUSHGO_OBSERVABILITY_LOG_LEVEL="$log_level"
done

python3 bench/scripts/summarize_results.py "$BASE_RESULT_DIR"
