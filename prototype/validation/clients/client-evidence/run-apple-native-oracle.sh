#!/bin/zsh
set -euo pipefail
C2_CLIENT_ROOT="${0:A:h}"
: "${C2_PHASE:?ingest or recover}"
: "${C2_EVIDENCE_DIR:?fresh evidence directory; reuse only for recover}"
: "${C2_GATEWAY_URL:?required}"
: "${C2_DEVICE_KEY:?required}"
: "${C2_DELIVERY_ID:?required}"
: "${C2_CAPTURED_WAKEUP_PATH:?required}"
: "${C2_EXPECTED_TITLE:?required}"
: "${C2_EXPECTED_BODY:?required}"
export PUSHGO_AUTOMATION_STORAGE_ROOT="${C2_EVIDENCE_DIR}/native-store"
mkdir -p "$PUSHGO_AUTOMATION_STORAGE_ROOT"
exec swift test --package-path "$C2_CLIENT_ROOT/apple-package" --scratch-path "$C2_CLIENT_ROOT/apple-build" --disable-automatic-resolution --skip-update --jobs 2 --filter 'C2WakeupApplicationEntryTests.*capturedWakeupThroughApplicationControllerAndProcessRestart'
