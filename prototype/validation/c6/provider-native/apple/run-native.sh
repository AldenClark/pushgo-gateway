#!/bin/zsh
set -euo pipefail
export PUSHGO_AUTOMATION_STORAGE_ROOT="${C3_EVIDENCE_DIR:?}/native-store"
mkdir -p "$PUSHGO_AUTOMATION_STORAGE_ROOT"
exec swift test --package-path "/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-client-loop-gate-20261015/apple/package" --scratch-path "/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-client-loop-gate-20261015/apple/build" --disable-automatic-resolution --skip-update --skip-build --jobs 2 --filter 'C3OrdinaryClientLoopTests.*ordinaryClientLoop'
