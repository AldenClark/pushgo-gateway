#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

mkdir -p target/bench

export PUSHGO_DB_URL="${PUSHGO_BENCH_DB_URL:-sqlite://$ROOT/target/bench/pushgo-bench.sqlite?mode=rwc}"
export PUSHGO_HTTP_ADDR="${PUSHGO_HTTP_ADDR:-127.0.0.1:6666}"
export PUSHGO_TOKEN="${PUSHGO_BENCH_TOKEN:-bench-token}"
export PUSHGO_RUNTIME_PROFILE="${PUSHGO_RUNTIME_PROFILE:-small}"
export PUSHGO_PRIVATE_TRANSPORTS="${PUSHGO_PRIVATE_TRANSPORTS:-wss}"
export PUSHGO_OBSERVABILITY_LOG_LEVEL="${PUSHGO_OBSERVABILITY_LOG_LEVEL:-warn}"

echo "PUSHGO_DB_URL=$PUSHGO_DB_URL"
echo "PUSHGO_HTTP_ADDR=$PUSHGO_HTTP_ADDR"
echo "PUSHGO_RUNTIME_PROFILE=$PUSHGO_RUNTIME_PROFILE"
echo "PUSHGO_PRIVATE_TRANSPORTS=$PUSHGO_PRIVATE_TRANSPORTS"
echo "PUSHGO_TOKEN is configured for benchmark auth"
echo "Start another shell with:"
echo "  export PUSHGO_BENCH_BASE_URL=http://$PUSHGO_HTTP_ADDR"
echo "  export PUSHGO_BENCH_TOKEN=$PUSHGO_TOKEN"
echo "  export PUSHGO_BENCH_DB_URL=$PUSHGO_DB_URL"
echo "  export PUSHGO_BENCH_PID=\$(pgrep -n pushgo-gateway)"

exec cargo run --profile profiling --bin pushgo-gateway
