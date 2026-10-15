#!/bin/zsh
set -euo pipefail
: "${C3_APPLE_WORK_ROOT:?explicit external work directory from stage.py required}"
: "${C3_PHASE:?required}"
: "${C3_EVIDENCE_DIR:?required}"
: "${C3_GATEWAY_URL:?required}"
: "${C3_PROVIDER_TOKEN:?synthetic required}"
export PUSHGO_AUTOMATION_STORAGE_ROOT="${C3_EVIDENCE_DIR}/native-store"
mkdir -p "$PUSHGO_AUTOMATION_STORAGE_ROOT"
exec swift test --package-path "$C3_APPLE_WORK_ROOT/package" --scratch-path "$C3_APPLE_WORK_ROOT/build" --disable-automatic-resolution --skip-update --jobs 2 --filter 'C3OrdinaryClientLoopTests.*ordinaryClientLoop'
