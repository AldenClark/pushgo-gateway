#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MANIFEST="$ROOT_DIR/tests/release_smoke_manifest.tsv"
RECEIPT_FILE="${RECEIPT_FILE:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pushgo-gateway-release-smoke-$$.json}"
LOG_DIR="${RECEIPT_FILE%.json}.logs-$(date -u +%Y%m%dT%H%M%SZ)-$$"
CARGO_DEPENDENCY_MODE="${CARGO_DEPENDENCY_MODE:-locked}"
case "$CARGO_DEPENDENCY_MODE" in
  locked) CARGO_DEPENDENCY_ARGS=(--locked) ;;
  frozen) CARGO_DEPENDENCY_ARGS=(--frozen) ;;
  *) echo "invalid CARGO_DEPENDENCY_MODE=$CARGO_DEPENDENCY_MODE (expected locked or frozen)" >&2; exit 2 ;;
esac
DISCOVERED=0
EXECUTED=0
PASSED=0
SOURCE_SHA="$(git rev-parse HEAD)"
if [[ -z "$(git status --porcelain --untracked-files=all)" ]]; then
  SOURCE_DIRTY=false
else
  SOURCE_DIRTY=true
fi
if command -v sha256sum >/dev/null 2>&1; then
  MANIFEST_SHA256="$(sha256sum "$MANIFEST" | awk '{print $1}')"
else
  MANIFEST_SHA256="$(shasum -a 256 "$MANIFEST" | awk '{print $1}')"
fi
mkdir -p "$LOG_DIR"
: > "$LOG_DIR/results.tsv"

write_receipt() {
  local outcome="$1"
  mkdir -p "$(dirname "$RECEIPT_FILE")"
  jq -Rn \
    --arg outcome "$outcome" \
    --arg profile "gateway-release-smoke" \
    --arg source_sha "$SOURCE_SHA" \
    --arg manifest_sha256 "$MANIFEST_SHA256" \
    --arg log_dir "$LOG_DIR" \
    --argjson dirty "$SOURCE_DIRTY" \
    --argjson discovered "$DISCOVERED" \
    --argjson executed "$EXECUTED" \
    --argjson passed "$PASSED" \
    '[inputs | select(length > 0) | split("\t") | {target: .[0], test: .[1], status: .[2], log: .[3]}] as $tests |
     {schema_version: 1, profile: $profile, outcome: $outcome, source_sha: $source_sha,
      dirty: $dirty, manifest_sha256: $manifest_sha256, log_dir: $log_dir,
      discovered_count: $discovered,
      executed_count: $executed, passed_count: $passed, tests: $tests}' \
    < "$LOG_DIR/results.tsv" > "$RECEIPT_FILE"
  printf 'GATEWAY_RELEASE_SMOKE_RECEIPT=%s\nGATEWAY_RELEASE_SMOKE_LOG_DIR=%s\n' "$RECEIPT_FILE" "$LOG_DIR"
}

test_count=0
while IFS=$'\t' read -r target test_name; do
  [[ -z "$target" || "$target" == \#* ]] && continue
  test_count=$((test_count + 1))
  case "$target" in
    lib) cargo_target=(--lib) ;;
    blackbox_private_fallback) cargo_target=(--test blackbox_private_fallback) ;;
    *) echo "unsupported release smoke target in manifest: $target" >&2; exit 2 ;;
  esac
  if cargo test "${CARGO_DEPENDENCY_ARGS[@]}" "${cargo_target[@]}" -- --list \
      | grep -Fx "${test_name}: test" >/dev/null; then
    DISCOVERED=$((DISCOVERED + 1))
  else
    echo "release smoke test was not discovered: target=$target test=$test_name" >&2
    printf '%s\t%s\tnot_discovered\t-\n' "$target" "$test_name" >> "$LOG_DIR/results.tsv"
    write_receipt "discovery_failed"
    exit 1
  fi
done < "$MANIFEST"

if [[ "$test_count" -eq 0 ]]; then
  echo "release smoke manifest is empty: $MANIFEST" >&2
  exit 2
fi

while IFS=$'\t' read -r target test_name; do
  [[ -z "$target" || "$target" == \#* ]] && continue
  case "$target" in
    lib) cargo_target=(--lib) ;;
    blackbox_private_fallback) cargo_target=(--test blackbox_private_fallback) ;;
  esac
  echo "=== RELEASE SMOKE: $target $test_name ==="
  test_slug="$(printf '%s' "$test_name" | tr -c 'A-Za-z0-9_.-' '-')"
  log_file="$LOG_DIR/${target}-${test_slug}.log"
  EXECUTED=$((EXECUTED + 1))
  if CARGO_TERM_COLOR=never cargo test "${CARGO_DEPENDENCY_ARGS[@]}" "${cargo_target[@]}" \
      "$test_name" -- --exact --nocapture > "$log_file" 2>&1; then
    cargo_status=0
  else
    cargo_status=$?
  fi
  cat "$log_file"
  if [[ "$cargo_status" -eq 0 ]] \
      && grep -Fxq "test ${test_name} ... ok" "$log_file" \
      && grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s$' "$log_file"; then
    PASSED=$((PASSED + 1))
    printf '%s\t%s\tpassed\t%s\n' "$target" "$test_name" "$log_file" >> "$LOG_DIR/results.tsv"
  else
    printf '%s\t%s\tfailed\t%s\n' "$target" "$test_name" "$log_file" >> "$LOG_DIR/results.tsv"
    write_receipt "failed"
    echo "release smoke stopped at first non-passing test output: target=$target test=$test_name cargo_status=$cargo_status" >&2
    exit 1
  fi
done < "$MANIFEST"

write_receipt "passed"
printf 'GATEWAY_RELEASE_SMOKE_DISCOVERED=%s\nGATEWAY_RELEASE_SMOKE_EXECUTED=%s\nGATEWAY_RELEASE_SMOKE_PASSED=%s\n' \
  "$DISCOVERED" "$EXECUTED" "$PASSED"
