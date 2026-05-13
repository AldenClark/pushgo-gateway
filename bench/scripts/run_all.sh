#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

SCENARIOS=(
  baseline_auth
  message_small_hot
  message_large_markdown
  message_complex_payload
  message_duplicate_op
  message_multi_channel
  dispatch_private_broadcast
  provider_unreachable_mock
  device_subscription_churn
  offline_pull_ack
  event_lifecycle
  thing_lifecycle
  compat_ingress
  private_wss_profile
  ramp_message
  spike_message
  soak_message
)

for scenario in "${SCENARIOS[@]}"; do
  python3 bench/scripts/run_scenario.py "$scenario"
done

python3 bench/scripts/summarize_results.py "${PUSHGO_BENCH_RESULT_DIR:-bench/results}"
