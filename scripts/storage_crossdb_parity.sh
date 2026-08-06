#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BIN="$ROOT_DIR/target/debug/pushgo-gateway"
REPORT_DIR="${REPORT_DIR:-/tmp/gateway-crossdb-current-report-v2}"
ROUNDS="${ROUNDS:-3}"

MYSQL_CONTAINER="pushgo-mysql-parity"
PG_CONTAINER="pushgo-pg-parity"
MYSQL_PORT="${MYSQL_PORT:-3407}"
PG_PORT="${PG_PORT:-5433}"
MYSQL_DB="pushgo_parity"
PG_DB="pushgo_parity"
CONTAINER_CLI="${CONTAINER_CLI:-auto}"

SQLITE_DB_PATH="/tmp/pushgo-crossdb-parity.sqlite"
SQLITE_DELIVERY_DB_PATH="/tmp/pushgo-crossdb-parity.delivery.sqlite"
SQLITE_DISPATCH_DB_PATH="/tmp/pushgo-crossdb-parity.dispatch.sqlite"
SQLITE_RUNTIME_DB_PATH="/tmp/pushgo-crossdb-parity.runtime.sqlite"
SQLITE_PORT=7661
MYSQL_GATEWAY_PORT=7662
PG_GATEWAY_PORT=7663

SQLITE_URL="sqlite://${SQLITE_DB_PATH}?mode=rwc"
MYSQL_URL="mysql://root:root@127.0.0.1:${MYSQL_PORT}/${MYSQL_DB}"
PG_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/${PG_DB}"

mkdir -p "$REPORT_DIR"
REPORT_DIR=$(cd -- "$REPORT_DIR" && pwd)
SUMMARY_FILE="$REPORT_DIR/summary.txt"
: > "$SUMMARY_FILE"

GW_PIDS=()

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

select_container_cli() {
  case "$CONTAINER_CLI" in
    auto)
      if command -v docker >/dev/null 2>&1; then
        CONTAINER_CLI="docker"
      elif command -v container >/dev/null 2>&1; then
        CONTAINER_CLI="container"
      else
        echo "missing command: docker or container" >&2
        exit 1
      fi
      ;;
    docker | container)
      require_cmd "$CONTAINER_CLI"
      ;;
    *)
      echo "invalid CONTAINER_CLI=$CONTAINER_CLI (expected auto, docker, or container)" >&2
      exit 1
      ;;
  esac
}

container_rm() {
  case "$CONTAINER_CLI" in
    docker) docker rm -f -v "$1" >/dev/null 2>&1 || true ;;
    container) container delete --force "$1" >/dev/null 2>&1 || true ;;
  esac
}

container_exec() {
  local name="$1"
  shift
  case "$CONTAINER_CLI" in
    docker) docker exec "$name" "$@" ;;
    container) container exec "$name" "$@" ;;
  esac
}

container_run_db() {
  local name="$1"
  local port_spec="$2"
  local image="$3"
  shift 3
  case "$CONTAINER_CLI" in
    docker)
      docker run -d --name "$name" "$@" -p "$port_spec" "$image" >/dev/null
      ;;
    container)
      container run -d --name "$name" "$@" -p "$port_spec" "$image" >/dev/null
      ;;
  esac
}

hash_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

hash_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

write_external_backup_manifest() {
  local name="$1"
  local db_url="$2"
  local driver="$3"
  local manifest="$REPORT_DIR/${name}-external-backup.json"
  local artifact="$REPORT_DIR/${name}-external-backup.dump"
  local database_sha256
  local artifact_sha256
  local artifact_bytes
  printf '%s' "${name}-crossdb-backup" > "$artifact"
  database_sha256=$(printf '%s' "$db_url" | hash_text)
  artifact_sha256=$(hash_file "$artifact")
  artifact_bytes=$(wc -c < "$artifact" | tr -d '[:space:]')
  jq -n \
    --arg driver "$driver" \
    --arg database_sha256 "$database_sha256" \
    --arg artifact_uri "file://${artifact}" \
    --arg artifact_sha256 "$artifact_sha256" \
    --argjson artifact_bytes "$artifact_bytes" \
    --argjson completed_at_epoch_seconds "$(date +%s)" \
    '{version: 1, driver: $driver, database_sha256: $database_sha256, artifact_uri: $artifact_uri, artifact_sha256: $artifact_sha256, artifact_bytes: $artifact_bytes, completed_at_epoch_seconds: $completed_at_epoch_seconds}' \
    > "$manifest"
  printf '%s' "$manifest"
}

for c in cargo curl jq sqlite3 diff; do
  require_cmd "$c"
done
select_container_cli

cleanup() {
  for pid in "${GW_PIDS[@]:-}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  container_rm "$MYSQL_CONTAINER"
  container_rm "$PG_CONTAINER"
}
trap cleanup EXIT

wait_http() {
  local base="$1"
  for _ in $(seq 1 120); do
    if curl -fsS "$base/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

start_gateway() {
  local name="$1"
  local db_url="$2"
  local port="$3"
  local log_file="$REPORT_DIR/${name}.log"
  local driver="sqlite"
  case "$db_url" in
    mysql://*) driver="mysql" ;;
    postgres://* | postgresql://* | pg://*) driver="postgres" ;;
  esac
  local backup_manifest
  backup_manifest=$(write_external_backup_manifest "$name" "$db_url" "$driver")
  PUSHGO_HTTP_ADDR="127.0.0.1:${port}" \
  PUSHGO_DB_URL="$db_url" \
  PUSHGO_TOKEN_SERVICE_URL="http://127.0.0.1:9" \
  PUSHGO_DB_UPGRADE_BACKUP_MANIFEST="$backup_manifest" \
  "$BIN" >"$log_file" 2>&1 &
  local pid=$!
  GW_PIDS+=("$pid")
  wait_http "http://127.0.0.1:${port}" || {
    echo "gateway ${name} failed to become ready; see $log_file" >&2
    return 1
  }
}

post_json() {
  local base="$1"
  local path="$2"
  local payload="$3"
  local body_file="$4"
  local raw
  raw=$(curl -sS -w '\n%{http_code}' -H 'content-type: application/json' -d "$payload" "$base$path")
  local code
  code=$(echo "$raw" | tail -n1)
  echo "$raw" | sed '$d' > "$body_file"
  echo "$code"
}

get_json() {
  local base="$1"
  local path="$2"
  local body_file="$3"
  local raw
  raw=$(curl -sS -w '\n%{http_code}' "$base$path")
  local code
  code=$(echo "$raw" | tail -n1)
  echo "$raw" | sed '$d' > "$body_file"
  echo "$code"
}

require_status_200() {
  local status="$1"
  local label="$2"
  local body_file="$3"
  if [[ "$status" != "200" ]]; then
    echo "${label} expected 200 got ${status}" >&2
    cat "$body_file" >&2
    exit 1
  fi
}

record_send_status() {
  local base="$1"
  local op_id="$2"
  local expected_model="$3"
  local expected_entity_id="$4"
  local prefix="$5"
  local body_file="$6"
  local out="$7"

  local status
  status=$(get_json "$base" "/send_status/${op_id}" "$body_file")
  require_status_200 "$status" "${prefix}: send status" "$body_file"
  echo "${prefix}.status_found=$([[ "$(jq -r '.data.op_id' "$body_file")" == "$op_id" ]] && echo true || echo false)" >> "$out"
  echo "${prefix}.model=$(jq -r '.data.model' "$body_file")" >> "$out"
  echo "${prefix}.model_ok=$([[ "$(jq -r '.data.model' "$body_file")" == "$expected_model" ]] && echo true || echo false)" >> "$out"
  echo "${prefix}.entity_id_ok=$([[ "$(jq -r '.data.entity_id' "$body_file")" == "$expected_entity_id" ]] && echo true || echo false)" >> "$out"
  echo "${prefix}.status=$(jq -r '.data.status' "$body_file")" >> "$out"
}

reset_mysql_db() {
  container_exec "$MYSQL_CONTAINER" mysql -uroot -proot -e "DROP DATABASE IF EXISTS ${MYSQL_DB}; CREATE DATABASE ${MYSQL_DB} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" >/dev/null
}

seed_mysql_partial_schema() {
  container_exec "$MYSQL_CONTAINER" mysql -uroot -proot "$MYSQL_DB" -e "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BINARY(32) NOT NULL, device_id BINARY(16) NOT NULL, PRIMARY KEY (platform, token_hash)) ENGINE=InnoDB; CREATE TABLE IF NOT EXISTS private_outbox (device_id BINARY(16) NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INT NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, last_error_code VARCHAR(64) NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)) ENGINE=InnoDB; CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BINARY(16) NOT NULL, device_id BINARY(32) NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id)) ENGINE=InnoDB; CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL) ENGINE=InnoDB; INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4') ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value);" >/dev/null
}

reset_pg_db() {
  container_exec "$PG_CONTAINER" psql -U postgres -d "$PG_DB" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;" >/dev/null
}

seed_pg_partial_schema() {
  container_exec "$PG_CONTAINER" psql -U postgres -d "$PG_DB" -v ON_ERROR_STOP=1 -c "CREATE TABLE IF NOT EXISTS private_bindings (platform SMALLINT NOT NULL, token_hash BYTEA NOT NULL, device_id BYTEA NOT NULL, PRIMARY KEY (platform, token_hash)); CREATE TABLE IF NOT EXISTS private_outbox (device_id BYTEA NOT NULL, delivery_id VARCHAR(128) NOT NULL, status VARCHAR(16) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at BIGINT NOT NULL, last_error_code TEXT, updated_at BIGINT NOT NULL, PRIMARY KEY (device_id, delivery_id)); CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BYTEA NOT NULL, device_id BYTEA NOT NULL, platform VARCHAR(32) NOT NULL, channel_type VARCHAR(32) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (channel_id, device_id)); CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key VARCHAR(128) PRIMARY KEY, meta_value VARCHAR(255) NOT NULL); INSERT INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4') ON CONFLICT (meta_key) DO UPDATE SET meta_value = EXCLUDED.meta_value;" >/dev/null
}

reset_sqlite_db() {
  rm -f \
    "$SQLITE_DB_PATH" "$SQLITE_DB_PATH-shm" "$SQLITE_DB_PATH-wal" \
    "$SQLITE_DELIVERY_DB_PATH" "$SQLITE_DELIVERY_DB_PATH-shm" "$SQLITE_DELIVERY_DB_PATH-wal" \
    "$SQLITE_DISPATCH_DB_PATH" "$SQLITE_DISPATCH_DB_PATH-shm" "$SQLITE_DISPATCH_DB_PATH-wal" \
    "$SQLITE_RUNTIME_DB_PATH" "$SQLITE_RUNTIME_DB_PATH-shm" "$SQLITE_RUNTIME_DB_PATH-wal"
  sqlite3 "$SQLITE_DB_PATH" "VACUUM;" >/dev/null
}

seed_sqlite_partial_schema() {
  sqlite3 "$SQLITE_DB_PATH" "CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash)); CREATE TABLE IF NOT EXISTS private_outbox (device_id BLOB NOT NULL, delivery_id TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error_code TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (device_id, delivery_id)); CREATE TABLE IF NOT EXISTS channel_subscriptions (channel_id BLOB NOT NULL, device_id BLOB NOT NULL, platform TEXT NOT NULL, channel_type TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (channel_id, device_id)); CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL); INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4');" >/dev/null
}

dump_sqlite_summary() {
  local out="$1"
  sqlite3 "$SQLITE_DB_PATH" <<'SQL' > "$out"
SELECT 'channels.count=' || COUNT(*) FROM channels;
SELECT 'channels.aliases=' || IFNULL(GROUP_CONCAT(alias, '|'), '') FROM (SELECT alias FROM channels ORDER BY alias);
SELECT 'subscriptions.count=' || COUNT(*) FROM channel_subscriptions;
SELECT 'devices.count=' || COUNT(*) FROM devices;
SELECT 'devices.routes=' || IFNULL(GROUP_CONCAT(platform || ':' || channel_type || ':' || IFNULL(provider_token, ''), '|'), '') FROM (SELECT platform, channel_type, provider_token FROM devices ORDER BY platform, channel_type, IFNULL(provider_token, ''));
SELECT 'private_bindings.count=' || COUNT(*) FROM private_bindings;
SELECT 'private_bindings.hashes=' || IFNULL(GROUP_CONCAT(LOWER(HEX(token_hash)), '|'), '') FROM (SELECT token_hash FROM private_bindings ORDER BY LOWER(HEX(token_hash)));
SQL
  sqlite3 "$SQLITE_DISPATCH_DB_PATH" <<'SQL' >> "$out"
SELECT 'dispatch_op_dedupe.count=' || COUNT(*) FROM dispatch_op_dedupe;
SELECT 'semantic_id_registry.count=' || COUNT(*) FROM semantic_id_registry;
SELECT 'dispatch_delivery_dedupe.count=' || COUNT(*) FROM dispatch_delivery_dedupe;
SQL
}

dump_mysql_summary() {
  local out="$1"
  local sql
  sql=$(
    cat <<'SQL'
SELECT CONCAT('channels.count=', COUNT(*)) FROM channels;
SELECT CONCAT('channels.aliases=', IFNULL(GROUP_CONCAT(alias ORDER BY alias SEPARATOR '|'), '')) FROM channels;
SELECT CONCAT('subscriptions.count=', COUNT(*)) FROM channel_subscriptions;
SELECT CONCAT('devices.count=', COUNT(*)) FROM devices;
SELECT CONCAT('devices.routes=', IFNULL(GROUP_CONCAT(CONCAT(IFNULL(platform,''), ':', IFNULL(channel_type,''), ':', IFNULL(provider_token,'')) ORDER BY IFNULL(platform,''), IFNULL(channel_type,''), IFNULL(provider_token,'') SEPARATOR '|'), '')) FROM devices;
SELECT CONCAT('private_bindings.count=', COUNT(*)) FROM private_bindings;
SELECT CONCAT('private_bindings.hashes=', IFNULL(GROUP_CONCAT(LOWER(HEX(token_hash)) ORDER BY LOWER(HEX(token_hash)) SEPARATOR '|'), '')) FROM private_bindings;
SELECT CONCAT('dispatch_op_dedupe.count=', COUNT(*)) FROM dispatch_op_dedupe;
SELECT CONCAT('semantic_id_registry.count=', COUNT(*)) FROM semantic_id_registry;
SELECT CONCAT('dispatch_delivery_dedupe.count=', COUNT(*)) FROM dispatch_delivery_dedupe;
SQL
  )
  container_exec "$MYSQL_CONTAINER" mysql --batch --skip-column-names -uroot -proot "$MYSQL_DB" -e "$sql" > "$out"
}

dump_pg_summary() {
  local out="$1"
  local sql
  sql=$(
    cat <<'SQL'
SELECT 'channels.count=' || COUNT(*)::text FROM channels;
SELECT 'channels.aliases=' || COALESCE(string_agg(alias, '|' ORDER BY alias), '') FROM channels;
SELECT 'subscriptions.count=' || COUNT(*)::text FROM channel_subscriptions;
SELECT 'devices.count=' || COUNT(*)::text FROM devices;
SELECT 'devices.routes=' || COALESCE(string_agg(COALESCE(platform,'') || ':' || COALESCE(channel_type,'') || ':' || COALESCE(provider_token,''), '|' ORDER BY COALESCE(platform,''), COALESCE(channel_type,''), COALESCE(provider_token,'')), '') FROM devices;
SELECT 'private_bindings.count=' || COUNT(*)::text FROM private_bindings;
SELECT 'private_bindings.hashes=' || COALESCE(string_agg(LOWER(ENCODE(token_hash, 'hex')), '|' ORDER BY LOWER(ENCODE(token_hash, 'hex'))), '') FROM private_bindings;
SELECT 'dispatch_op_dedupe.count=' || COUNT(*)::text FROM dispatch_op_dedupe;
SELECT 'semantic_id_registry.count=' || COUNT(*)::text FROM semantic_id_registry;
SELECT 'dispatch_delivery_dedupe.count=' || COUNT(*)::text FROM dispatch_delivery_dedupe;
SQL
  )
  container_exec "$PG_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d "$PG_DB" -At -c "$sql" > "$out"
}

run_scenario() {
  local backend="$1"
  local base="$2"
  local round="$3"
  local out="$4"
  : > "$out"

  local pfx="r${round}"
  local token1="Fcm-Case-${pfx}-AbCdEf01"
  local token2="fCM-cASE-${pfx}-aBcDeF01"

  local b
  b=$(mktemp)

  local status
  status=$(post_json "$base" "/device/register" "{\"platform\":\"android\"}" "$b")
  require_status_200 "$status" "${backend}: register private" "$b"
  local device_key
  device_key=$(jq -r '.data.device_key' "$b")
  echo "register_private.issued_new_key=$(jq -r '.data.issued_new_key' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/device" "{\"device_key\":\"${device_key}\",\"platform\":\"android\",\"channel_type\":\"fcm\",\"provider_token\":\"${token1}\"}" "$b")
  require_status_200 "$status" "${backend}: register fcm token1" "$b"
  echo "register_fcm_1.issued_new_key=$(jq -r '.data.issued_new_key' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/subscribe" "{\"device_key\":\"${device_key}\",\"channel_name\":\"${pfx}-a\",\"password\":\"password-1234\"}" "$b")
  require_status_200 "$status" "${backend}: subscribe a" "$b"
  local channel_a
  channel_a=$(jq -r '.data.channel_id' "$b")
  echo "subscribe_a.created=$(jq -r '.data.created' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/subscribe" "{\"device_key\":\"${device_key}\",\"channel_name\":\"${pfx}-b\",\"password\":\"password-1234\"}" "$b")
  require_status_200 "$status" "${backend}: subscribe b" "$b"
  local channel_b
  channel_b=$(jq -r '.data.channel_id' "$b")

  status=$(post_json "$base" "/channel/subscribe" "{\"device_key\":\"${device_key}\",\"channel_name\":\"${pfx}-c\",\"password\":\"password-1234\"}" "$b")
  require_status_200 "$status" "${backend}: subscribe c" "$b"
  local channel_c
  channel_c=$(jq -r '.data.channel_id' "$b")

  status=$(post_json "$base" "/message" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"title\":\"msg-title\",\"body\":\"msg-body\",\"severity\":\"normal\"}" "$b")
  require_status_200 "$status" "${backend}: message 1" "$b"
  local msg_id_1 msg_op_id_1
  msg_id_1=$(jq -r '.data.message_id' "$b")
  msg_op_id_1=$(jq -r '.data.op_id' "$b")
  echo "message_1.has_message_id=$([[ -n "$msg_id_1" && "$msg_id_1" != "null" ]] && echo true || echo false)" >> "$out"
  echo "message_1.has_op_id=$([[ -n "$msg_op_id_1" && "$msg_op_id_1" != "null" ]] && echo true || echo false)" >> "$out"
  record_send_status "$base" "$msg_op_id_1" "message" "$msg_id_1" "message_1" "$b" "$out"

  status=$(post_json "$base" "/message" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"title\":\"msg-title\",\"body\":\"msg-body\",\"severity\":\"normal\"}" "$b")
  require_status_200 "$status" "${backend}: message 2" "$b"
  local msg_id_2 msg_op_id_2
  msg_id_2=$(jq -r '.data.message_id' "$b")
  msg_op_id_2=$(jq -r '.data.op_id' "$b")
  echo "message_2.has_message_id=$([[ -n "$msg_id_2" && "$msg_id_2" != "null" ]] && echo true || echo false)" >> "$out"
  echo "message_2.has_op_id=$([[ -n "$msg_op_id_2" && "$msg_op_id_2" != "null" ]] && echo true || echo false)" >> "$out"
  echo "message_2.distinct_message_id=$([[ "$msg_id_1" != "$msg_id_2" ]] && echo true || echo false)" >> "$out"
  echo "message_2.distinct_op_id=$([[ "$msg_op_id_1" != "$msg_op_id_2" ]] && echo true || echo false)" >> "$out"
  record_send_status "$base" "$msg_op_id_2" "message" "$msg_id_2" "message_2" "$b" "$out"

  local client_op_id="crossdb-${pfx}-client-op-0001"
  status=$(post_json "$base" "/message" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"op_id\":\"${client_op_id}\",\"title\":\"client-op-title\"}" "$b")
  require_status_200 "$status" "${backend}: client op first submit" "$b"
  local client_message_id
  client_message_id=$(jq -r '.data.message_id' "$b")
  status=$(get_json "$base" "/send_status/${client_op_id}" "$b")
  require_status_200 "$status" "${backend}: client op first status" "$b"
  local client_status_before
  client_status_before=$(jq -c '.data' "$b")

  status=$(post_json "$base" "/message" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"op_id\":\"${client_op_id}\",\"title\":\"client-op-title\"}" "$b")
  require_status_200 "$status" "${backend}: client op replay" "$b"
  [[ "$(jq -r '.data.message_id' "$b")" == "$client_message_id" ]] || {
    echo "${backend}: client op replay changed message_id" >&2
    exit 1
  }
  status=$(post_json "$base" "/message" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"op_id\":\"${client_op_id}\",\"title\":\"client-op-conflict\"}" "$b")
  [[ "$status" == "409" ]] || {
    echo "${backend}: client op conflict expected 409 got ${status}" >&2
    cat "$b" >&2
    exit 1
  }
  [[ "$(jq -r '.problem.category' "$b")" == "conflict" ]] || {
    echo "${backend}: client op conflict category mismatch" >&2
    cat "$b" >&2
    exit 1
  }
  status=$(get_json "$base" "/send_status/${client_op_id}" "$b")
  require_status_200 "$status" "${backend}: client op status after conflict" "$b"
  [[ "$(jq -c '.data' "$b")" == "$client_status_before" ]] || {
    echo "${backend}: client op conflict rewrote sender status" >&2
    exit 1
  }
  echo "client_op.replay_idempotent=true" >> "$out"
  echo "client_op.conflict_preserves_status=true" >> "$out"

  status=$(post_json "$base" "/event/create" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"event_time\":1710000000,\"title\":\"evt-title\",\"status\":\"open\",\"message\":\"evt-msg\",\"severity\":\"high\"}" "$b")
  require_status_200 "$status" "${backend}: event create 1" "$b"
  local event_id_1 event_op_id_1
  event_id_1=$(jq -r '.data.event_id' "$b")
  event_op_id_1=$(jq -r '.data.op_id' "$b")
  echo "event_1.has_event_id=$([[ -n "$event_id_1" && "$event_id_1" != "null" ]] && echo true || echo false)" >> "$out"
  echo "event_1.has_op_id=$([[ -n "$event_op_id_1" && "$event_op_id_1" != "null" ]] && echo true || echo false)" >> "$out"
  record_send_status "$base" "$event_op_id_1" "event" "$event_id_1" "event_1" "$b" "$out"

  status=$(post_json "$base" "/event/create" "{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\",\"event_time\":1710000000,\"title\":\"evt-title\",\"status\":\"open\",\"message\":\"evt-msg\",\"severity\":\"high\"}" "$b")
  require_status_200 "$status" "${backend}: event create 2" "$b"
  local event_id_2 event_op_id_2
  event_id_2=$(jq -r '.data.event_id' "$b")
  event_op_id_2=$(jq -r '.data.op_id' "$b")
  echo "event_2.has_event_id=$([[ -n "$event_id_2" && "$event_id_2" != "null" ]] && echo true || echo false)" >> "$out"
  echo "event_2.has_op_id=$([[ -n "$event_op_id_2" && "$event_op_id_2" != "null" ]] && echo true || echo false)" >> "$out"
  echo "event_2.distinct_event_id=$([[ "$event_id_1" != "$event_id_2" ]] && echo true || echo false)" >> "$out"
  echo "event_2.distinct_op_id=$([[ "$event_op_id_1" != "$event_op_id_2" ]] && echo true || echo false)" >> "$out"
  record_send_status "$base" "$event_op_id_2" "event" "$event_id_2" "event_2" "$b" "$out"

  status=$(post_json "$base" "/channel/sync" "{\"device_key\":\"${device_key}\",\"channels\":[{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\"},{\"channel_id\":\"\",\"password\":\"password-1234\"}]}" "$b")
  require_status_200 "$status" "${backend}: sync partial" "$b"
  echo "sync_partial.success=$(jq -r '.data.success' "$b")" >> "$out"
  echo "sync_partial.failed=$(jq -r '.data.failed' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/sync" "{\"device_key\":\"${device_key}\",\"channels\":[{\"channel_id\":\"${channel_a}\",\"password\":\"password-1234\"},{\"channel_id\":\"${channel_b}\",\"password\":\"password-1234\"}]}" "$b")
  require_status_200 "$status" "${backend}: sync full" "$b"
  echo "sync_full.failed=$(jq -r '.data.failed' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/unsubscribe" "{\"device_key\":\"${device_key}\",\"channel_id\":\"${channel_c}\"}" "$b")
  require_status_200 "$status" "${backend}: unsubscribe c" "$b"
  echo "unsubscribe_c.removed=$(jq -r '.data.removed' "$b")" >> "$out"

  status=$(get_json "$base" "/channel/exists?channel_id=${channel_a}" "$b")
  require_status_200 "$status" "${backend}: exists before rename" "$b"
  echo "exists_before.exists=$(jq -r '.data.exists' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/rename" "{\"channel_id\":\"${channel_a}\",\"channel_name\":\"${pfx}-a-renamed\",\"password\":\"password-1234\"}" "$b")
  require_status_200 "$status" "${backend}: rename a" "$b"
  echo "rename.channel_name=$(jq -r '.data.channel_name' "$b")" >> "$out"

  status=$(get_json "$base" "/channel/exists?channel_id=${channel_a}" "$b")
  require_status_200 "$status" "${backend}: exists after rename" "$b"
  echo "exists_after.channel_name=$(jq -r '.data.channel_name' "$b")" >> "$out"

  status=$(post_json "$base" "/channel/device" "{\"device_key\":\"${device_key}\",\"platform\":\"android\",\"channel_type\":\"fcm\",\"provider_token\":\"${token2}\"}" "$b")
  require_status_200 "$status" "${backend}: register fcm token2" "$b"
  echo "register_fcm_2.issued_new_key=$(jq -r '.data.issued_new_key' "$b")" >> "$out"
  [[ "$(jq -r '.data.provider_token' "$b")" == "$token2" ]] || {
    echo "${backend}: FCM token case was not preserved" >&2
    cat "$b" >&2
    exit 1
  }
  echo "register_fcm_2.case_preserved=true" >> "$out"

  status=$(post_json "$base" "/device/register" '{"platform":"ios"}' "$b")
  require_status_200 "$status" "${backend}: register ios" "$b"
  local ios_device_key
  ios_device_key=$(jq -r '.data.device_key' "$b")
  local apns_upper="ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
  local apns_lower="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
  status=$(post_json "$base" "/channel/device" "{\"device_key\":\"${ios_device_key}\",\"platform\":\"ios\",\"channel_type\":\"apns\",\"provider_token\":\" ${apns_upper} \"}" "$b")
  require_status_200 "$status" "${backend}: register canonical APNs token" "$b"
  [[ "$(jq -r '.data.provider_token' "$b")" == "$apns_lower" ]] || {
    echo "${backend}: APNs token was not canonicalized to lowercase hex" >&2
    cat "$b" >&2
    exit 1
  }
  echo "register_apns.canonical_lowercase=true" >> "$out"

  rm -f "$b"
}

echo "[build] cargo build" | tee -a "$SUMMARY_FILE"
(
  cd "$ROOT_DIR"
  cargo build -q
)

echo "[container] starting mysql/postgresql with ${CONTAINER_CLI}" | tee -a "$SUMMARY_FILE"
container_rm "$MYSQL_CONTAINER"
container_rm "$PG_CONTAINER"
container_run_db "$MYSQL_CONTAINER" "${MYSQL_PORT}:3306" mysql:8 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE="$MYSQL_DB"
container_run_db "$PG_CONTAINER" "${PG_PORT}:5432" postgres:16 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB="$PG_DB"

for _ in $(seq 1 120); do
  if container_exec "$MYSQL_CONTAINER" mysqladmin ping -h127.0.0.1 -uroot -proot --silent >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
for _ in $(seq 1 120); do
  if container_exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

for round in $(seq 1 "$ROUNDS"); do
  echo "[round ${round}] reset databases + seed partial schema" | tee -a "$SUMMARY_FILE"
  reset_sqlite_db
  seed_sqlite_partial_schema
  reset_mysql_db
  seed_mysql_partial_schema
  reset_pg_db
  seed_pg_partial_schema

  GW_PIDS=()
  start_gateway sqlite "$SQLITE_URL" "$SQLITE_PORT"
  start_gateway mysql "$MYSQL_URL" "$MYSQL_GATEWAY_PORT"
  start_gateway pg "$PG_URL" "$PG_GATEWAY_PORT"

  sqlite_api="$REPORT_DIR/round${round}.sqlite.api.txt"
  mysql_api="$REPORT_DIR/round${round}.mysql.api.txt"
  pg_api="$REPORT_DIR/round${round}.pg.api.txt"

  sqlite_db="$REPORT_DIR/round${round}.sqlite.db.txt"
  mysql_db="$REPORT_DIR/round${round}.mysql.db.txt"
  pg_db="$REPORT_DIR/round${round}.pg.db.txt"

  run_scenario sqlite "http://127.0.0.1:${SQLITE_PORT}" "$round" "$sqlite_api"
  run_scenario mysql "http://127.0.0.1:${MYSQL_GATEWAY_PORT}" "$round" "$mysql_api"
  run_scenario pg "http://127.0.0.1:${PG_GATEWAY_PORT}" "$round" "$pg_api"

  dump_sqlite_summary "$sqlite_db"
  dump_mysql_summary "$mysql_db"
  dump_pg_summary "$pg_db"

  if diff -u "$sqlite_api" "$mysql_api" > "$REPORT_DIR/round${round}.api.sqlite-mysql.diff"; then
    echo "round=${round} API_CROSS sqlite-mysql MATCH" | tee -a "$SUMMARY_FILE"
  else
    echo "round=${round} API_CROSS sqlite-mysql DIFF" | tee -a "$SUMMARY_FILE"
    exit 1
  fi
  if diff -u "$sqlite_api" "$pg_api" > "$REPORT_DIR/round${round}.api.sqlite-pg.diff"; then
    echo "round=${round} API_CROSS sqlite-pg MATCH" | tee -a "$SUMMARY_FILE"
  else
    echo "round=${round} API_CROSS sqlite-pg DIFF" | tee -a "$SUMMARY_FILE"
    exit 1
  fi
  if diff -u "$mysql_api" "$pg_api" > "$REPORT_DIR/round${round}.api.mysql-pg.diff"; then
    echo "round=${round} API_CROSS mysql-pg MATCH" | tee -a "$SUMMARY_FILE"
  else
    echo "round=${round} API_CROSS mysql-pg DIFF" | tee -a "$SUMMARY_FILE"
    exit 1
  fi

  if diff -u "$sqlite_db" "$mysql_db" > "$REPORT_DIR/round${round}.db.sqlite-mysql.diff"; then
    echo "round=${round} DB_CROSS sqlite-mysql MATCH" | tee -a "$SUMMARY_FILE"
  else
    echo "round=${round} DB_CROSS sqlite-mysql DIFF" | tee -a "$SUMMARY_FILE"
    exit 1
  fi
  if diff -u "$sqlite_db" "$pg_db" > "$REPORT_DIR/round${round}.db.sqlite-pg.diff"; then
    echo "round=${round} DB_CROSS sqlite-pg MATCH" | tee -a "$SUMMARY_FILE"
  else
    echo "round=${round} DB_CROSS sqlite-pg DIFF" | tee -a "$SUMMARY_FILE"
    exit 1
  fi
  if diff -u "$mysql_db" "$pg_db" > "$REPORT_DIR/round${round}.db.mysql-pg.diff"; then
    echo "round=${round} DB_CROSS mysql-pg MATCH" | tee -a "$SUMMARY_FILE"
  else
    echo "round=${round} DB_CROSS mysql-pg DIFF" | tee -a "$SUMMARY_FILE"
    exit 1
  fi

  sqlite_hash=$(hash_file "$sqlite_db")
  mysql_hash=$(hash_file "$mysql_db")
  pg_hash=$(hash_file "$pg_db")
  echo "round=${round} DB_HASH sqlite=${sqlite_hash} mysql=${mysql_hash} pg=${pg_hash}" | tee -a "$SUMMARY_FILE"

  for pid in "${GW_PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
  GW_PIDS=()
done

echo "DONE report=${REPORT_DIR}" | tee -a "$SUMMARY_FILE"
