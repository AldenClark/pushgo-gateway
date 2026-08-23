#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V11_BIN="${V11_BIN:-}"
V12_BIN="${V12_BIN:-$ROOT_DIR/target/release/pushgo-gateway}"
V11_SOURCE_COMMIT="${V11_SOURCE_COMMIT:-6c26f420114823a827caa0274a0bbc3739d91211}"
EVIDENCE_FILE="${EVIDENCE_FILE:-}"
KEEP_FIXTURE="${KEEP_FIXTURE:-0}"

usage() {
  cat <<'EOF'
Usage:
  V12_BIN=/path/to/candidate-v12/pushgo-gateway \
    scripts/v12_single_instance_rollback_drill.sh

Optional:
  V11_BIN=/path/to/audited-v11/pushgo-gateway
  V11_SOURCE_COMMIT=<audited-v11-commit>
  EVIDENCE_FILE=/path/to/rollback-evidence.json

The drill creates only temporary SQLite databases. It proves that:
  1. the v11 artifact fails closed when pointed at a v12 schema;
  2. the failed v11 read-only plan leaves v12 durable work unchanged; and
  3. the v12-aware emergency artifact can inspect the same database and
     preserve the durable provider backlog for hold-or-drain recovery.
  4. a synthetic stopped-writer v11 SQLite snapshot can be restored to an
     isolated clone and remains readable by the exact v11 artifact.

This is not a production migration command. Set KEEP_FIXTURE=1 to retain the
temporary fixture for inspection. When V11_BIN is omitted, the script builds
the audited v11 source commit in the temporary fixture.
EOF
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

hash_sqlite_family() {
  local core_path="$1"
  local stem="${core_path%.sqlite}"
  local path
  for path in \
    "$core_path" \
    "$stem.delivery.sqlite" \
    "$stem.dispatch.sqlite" \
    "$stem.runtime.sqlite"; do
    if [[ -f "$path" ]]; then
      printf '%s  %s\n' "$(hash_file "$path")" "$(basename "$path")"
    fi
  done | if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

backup_sqlite_family() {
  local source_core="$1"
  local backup_core="$2"
  local source_stem="${source_core%.sqlite}"
  local backup_stem="${backup_core%.sqlite}"
  local suffix source_path backup_path
  sqlite3 "$source_core" ".backup '$backup_core'"
  for suffix in delivery dispatch runtime; do
    source_path="$source_stem.$suffix.sqlite"
    backup_path="$backup_stem.$suffix.sqlite"
    if [[ -f "$source_path" ]]; then
      sqlite3 "$source_path" ".backup '$backup_path'"
    fi
  done
}

for command_name in sqlite3 mktemp git cargo tar jq; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
done

if [[ ! -x "$V12_BIN" ]]; then
  usage >&2
  exit 2
fi

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/pushgo-v12-rollback-drill.XXXXXX")"
cleanup() {
  if [[ "$KEEP_FIXTURE" == "1" ]]; then
    echo "fixture retained at $fixture_dir"
    return
  fi
  case "$fixture_dir" in
    "${TMPDIR:-/tmp}"/pushgo-v12-rollback-drill.*) rm -rf -- "$fixture_dir" ;;
    *) echo "refusing to remove unexpected fixture path: $fixture_dir" >&2 ;;
  esac
}
trap cleanup EXIT

if [[ -z "$V11_BIN" ]]; then
  v11_source_dir="$fixture_dir/v11-source"
  v11_target_dir="$fixture_dir/v11-target"
  mkdir -p "$v11_source_dir" "$v11_target_dir"
  resolved_v11_commit="$(git -C "$ROOT_DIR" rev-parse "$V11_SOURCE_COMMIT^{commit}")"
  if [[ "$resolved_v11_commit" != "$V11_SOURCE_COMMIT" ]]; then
    echo "v11 source commit did not resolve exactly: expected=$V11_SOURCE_COMMIT actual=$resolved_v11_commit" >&2
    exit 1
  fi
  git -C "$ROOT_DIR" archive "$resolved_v11_commit" | tar -x -C "$v11_source_dir"
  CARGO_TARGET_DIR="$v11_target_dir" \
    cargo build \
      --manifest-path "$v11_source_dir/Cargo.toml" \
      --locked \
      --release \
      --bin pushgo-gateway
  V11_BIN="$v11_target_dir/release/pushgo-gateway"
fi

if [[ ! -x "$V11_BIN" ]]; then
  usage >&2
  exit 2
fi

core_db="$fixture_dir/gateway.sqlite"
dispatch_db="$fixture_dir/gateway.dispatch.sqlite"
db_url="sqlite://$core_db?mode=rwc"
v11_log="$fixture_dir/v11-plan.log"
v12_log="$fixture_dir/v12-plan.log"

v11_seed_core="$fixture_dir/v11-seed.sqlite"
v11_backup_core="$fixture_dir/v11-backup.sqlite"
v11_restored_core="$fixture_dir/v11-restored.sqlite"
v11_seed_url="sqlite://$v11_seed_core?mode=rwc"
v11_restored_url="sqlite://$v11_restored_core?mode=rwc"

# Generate a synthetic stopped-writer v11 database, snapshot every SQLite
# sidecar, and restore it under a distinct path before validating it.
"$V11_BIN" --db-url "$v11_seed_url" --db-upgrade run >"$fixture_dir/v11-create.log" 2>&1
sqlite3 "$v11_seed_core" \
  "INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('rollback_drill_sentinel', 'preserved');"
backup_sqlite_family "$v11_seed_core" "$v11_backup_core"
backup_sqlite_family "$v11_backup_core" "$v11_restored_core"
restored_v11_before="$(hash_sqlite_family "$v11_restored_core")"
"$V11_BIN" --db-url "$v11_restored_url" --db-upgrade plan >"$fixture_dir/v11-restored-plan.log" 2>&1
restored_v11_after="$(hash_sqlite_family "$v11_restored_core")"
if [[ "$restored_v11_after" != "$restored_v11_before" ]]; then
  echo "v11 read-only plan mutated the restored snapshot clone" >&2
  exit 1
fi
if [[ "$(sqlite3 "$v11_restored_core" "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version';")" != "2026-08-08-gateway-v11" ]] ||
  [[ "$(sqlite3 "$v11_restored_core" "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='rollback_drill_sentinel';")" != "preserved" ]]; then
  echo "restored v11 snapshot clone lost schema or sentinel state" >&2
  exit 1
fi

# This migration executes only against the temporary fixture created above.
"$V12_BIN" --db-url "$db_url" --db-upgrade run >"$fixture_dir/v12-create.log" 2>&1
sqlite3 "$dispatch_db" <<'SQL'
INSERT INTO provider_dispatch_outbox
  (job_id, provider, delivery_id, op_id, dedupe_key, device_key, payload_blob,
   state, attempt_count, next_attempt_at, lease_generation, accepted_at,
   expires_at, updated_at)
VALUES
  ('rollback-drill-job', 'APNS_LIVE_ACTIVITY', 'rollback-drill-delivery', NULL,
   NULL, 'rollback-drill-device', X'7B7D', 'pending', 0, 2000000000000, 0,
   2000000000000, 2000003600000, 2000000000000);
SQL

core_before="$(hash_file "$core_db")"
dispatch_before="$(hash_file "$dispatch_db")"
set +e
"$V11_BIN" --db-url "$db_url" --db-upgrade plan >"$v11_log" 2>&1
v11_result=$?
set -e
if [[ "$v11_result" -eq 0 ]]; then
  echo "v11 unexpectedly accepted the v12 schema" >&2
  cat "$v11_log" >&2
  exit 1
fi
if ! grep -Fq 'target_schema=2026-08-08-gateway-v11' "$v11_log" ||
  ! grep -Eq '2026-08-20-gateway-v12|20260820_001_durable_provider_dispatch_v12' "$v11_log"; then
  echo "v11 did not report the v12 schema mismatch" >&2
  cat "$v11_log" >&2
  exit 1
fi
if [[ "$(hash_file "$core_db")" != "$core_before" || "$(hash_file "$dispatch_db")" != "$dispatch_before" ]]; then
  echo "the rejected v11 compatibility check mutated the v12 fixture" >&2
  exit 1
fi
if [[ "$(sqlite3 "$dispatch_db" "SELECT COUNT(1) FROM provider_dispatch_outbox WHERE job_id='rollback-drill-job' AND state='pending';")" != "1" ]]; then
  echo "the rejected v11 check did not preserve durable work" >&2
  exit 1
fi

"$V12_BIN" --db-url "$db_url" --db-upgrade plan >"$v12_log" 2>&1
if ! grep -Eq 'current schema=2026-08-20-gateway-v12 action=(noop|backfill_current) pending=0' "$v12_log"; then
  echo "v12 emergency artifact could not inspect the v12 schema" >&2
  cat "$v12_log" >&2
  exit 1
fi
if [[ "$(sqlite3 "$dispatch_db" "SELECT COUNT(1) FROM provider_dispatch_outbox WHERE job_id='rollback-drill-job' AND state='pending';")" != "1" ]]; then
  echo "v12 emergency inspection did not preserve durable work" >&2
  exit 1
fi

v11_binary_sha256="$(hash_file "$V11_BIN")"
v12_binary_sha256="$(hash_file "$V12_BIN")"

if [[ -n "$EVIDENCE_FILE" ]]; then
  mkdir -p "$(dirname "$EVIDENCE_FILE")"
  jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg v11_source_commit "$V11_SOURCE_COMMIT" \
    --arg v11_binary_sha256 "$v11_binary_sha256" \
    --arg v12_binary_sha256 "$v12_binary_sha256" \
    --arg restored_v11_family_sha256 "$restored_v11_after" \
    '{
      generated_at: $generated_at,
      synthetic_database: true,
      production_validation: false,
      v11_source_commit: $v11_source_commit,
      v11_schema: "2026-08-08-gateway-v11",
      v12_schema: "2026-08-20-gateway-v12",
      v11_binary_sha256: $v11_binary_sha256,
      v12_binary_sha256: $v12_binary_sha256,
      restored_v11_family_sha256: $restored_v11_family_sha256,
      snapshot_restore_clone: "PASS",
      v11_rejects_v12_schema: "PASS",
      v12_backlog_preserved: "PASS"
    }' >"$EVIDENCE_FILE"
fi

cat <<EOF
v12 single-instance rollback drill: PASS
snapshot_restore_clone=PASS
v11_binary_sha256=$v11_binary_sha256
v12_binary_sha256=$v12_binary_sha256
contract=v11-fails-closed;v12-emergency-artifact-holds-or-drains
EOF
