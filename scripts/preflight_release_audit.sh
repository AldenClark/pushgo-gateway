#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GATEWAY_BIN="$ROOT_DIR/target/release/pushgo-gateway"
TOKEN="${TOKEN:-preflight-token}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd curl
need_cmd jq
need_cmd sqlite3

wait_http_ready() {
  local base_url="$1"
  local token="$2"
  for _ in $(seq 1 120); do
    if curl -fsS -H "Authorization: Bearer $token" "$base_url/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

post_json() {
  local base_url="$1"
  local token="$2"
  local path="$3"
  local data="$4"
  curl -fsS \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -X POST "$base_url$path" \
    -d "$data"
}

run_public_flow() {
  local work_dir="$1"
  local http_port="$2"
  local db_file="$work_dir/public.sqlite"
  local db_url="sqlite://$db_file?mode=rwc"
  local base_url="http://127.0.0.1:${http_port}"
  local log_file="$work_dir/public_gateway.log"

  "$GATEWAY_BIN" \
    --http-addr "127.0.0.1:${http_port}" \
    --db-url "$db_url" \
    --token "$TOKEN" \
    >"$log_file" 2>&1 &
  local pid=$!

  cleanup_public() {
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_public RETURN

  wait_http_ready "$base_url" "$TOKEN"

  local reg device_key provider_token
  reg="$(post_json "$base_url" "$TOKEN" "/device/register" '{"platform":"android"}')"
  device_key="$(printf '%s' "$reg" | jq -r '.data.device_key')"
  provider_token="audit-fcm-$(date +%s)-$RANDOM"
  post_json \
    "$base_url" \
    "$TOKEN" \
    "/channel/device" \
    "{\"device_key\":\"$device_key\",\"platform\":\"android\",\"channel_type\":\"fcm\",\"provider_token\":\"$provider_token\"}" \
    >/dev/null

  local sub1 sub2 sub3 cid1 cid2 cid3
  sub1="$(post_json "$base_url" "$TOKEN" "/channel/subscribe" "{\"device_key\":\"$device_key\",\"channel_name\":\"audit-public-a\",\"password\":\"benchmark-123\"}")"
  sub2="$(post_json "$base_url" "$TOKEN" "/channel/subscribe" "{\"device_key\":\"$device_key\",\"channel_name\":\"audit-public-b\",\"password\":\"benchmark-123\"}")"
  sub3="$(post_json "$base_url" "$TOKEN" "/channel/subscribe" "{\"device_key\":\"$device_key\",\"channel_name\":\"audit-public-c\",\"password\":\"benchmark-123\"}")"
  cid1="$(printf '%s' "$sub1" | jq -r '.data.channel_id')"
  cid2="$(printf '%s' "$sub2" | jq -r '.data.channel_id')"
  cid3="$(printf '%s' "$sub3" | jq -r '.data.channel_id')"

  local c0 c1 c2 sync_ok sync_partial
  c0="$(sqlite3 "$db_file" "SELECT COUNT(1) FROM channel_subscriptions s JOIN channels c ON c.channel_id=s.channel_id WHERE c.alias IN ('audit-public-a','audit-public-b','audit-public-c');")"
  sync_ok="$(post_json "$base_url" "$TOKEN" "/channel/sync" "{\"device_key\":\"$device_key\",\"channels\":[{\"channel_id\":\"$cid1\",\"password\":\"benchmark-123\"},{\"channel_id\":\"$cid2\",\"password\":\"benchmark-123\"}]}")"
  c1="$(sqlite3 "$db_file" "SELECT COUNT(1) FROM channel_subscriptions s JOIN channels c ON c.channel_id=s.channel_id WHERE c.alias IN ('audit-public-a','audit-public-b','audit-public-c');")"
  sync_partial="$(post_json "$base_url" "$TOKEN" "/channel/sync" "{\"device_key\":\"$device_key\",\"channels\":[{\"channel_id\":\"$cid1\",\"password\":\"benchmark-123\"},{\"channel_id\":\"$cid2\",\"password\":\"wrong-pass-123\"}]}")"
  c2="$(sqlite3 "$db_file" "SELECT COUNT(1) FROM channel_subscriptions s JOIN channels c ON c.channel_id=s.channel_id WHERE c.alias IN ('audit-public-a','audit-public-b','audit-public-c');")"

  local out="$work_dir/public_send_codes.txt"
  : > "$out"
  for _ in $(seq 1 200); do
    local payload code
    payload="$(printf '{"channel_id":"%s","password":"benchmark-123","title":"audit","body":"load","metadata":{}}' "$cid1")"
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -X POST "$base_url/message" \
      -d "$payload" || true)"
    printf '%s\n' "$code" >> "$out"
  done

  local s200 s503 s429 sother
  s200="$(grep -c '^200$' "$out" || true)"
  s503="$(grep -c '^503$' "$out" || true)"
  s429="$(grep -c '^429$' "$out" || true)"
  sother="$(awk '$1!="200" && $1!="503" && $1!="429"{c++} END{print c+0}' "$out")"

  printf 'PUBLIC_WORK_DIR=%s\nPUBLIC_DEVICE_KEY=%s\nPUBLIC_PROVIDER_TOKEN=%s\nPUBLIC_CHANNELS=%s,%s,%s\nPUBLIC_COUNT_INITIAL=%s\nPUBLIC_COUNT_AFTER_SYNC_OK=%s\nPUBLIC_COUNT_AFTER_SYNC_PARTIAL=%s\nPUBLIC_SYNC_OK=%s\nPUBLIC_SYNC_PARTIAL=%s\nPUBLIC_SEND_200=%s\nPUBLIC_SEND_503=%s\nPUBLIC_SEND_429=%s\nPUBLIC_SEND_OTHER=%s\n' \
    "$work_dir" "$device_key" "$provider_token" "$cid1" "$cid2" "$cid3" "$c0" "$c1" "$c2" \
    "$(printf '%s' "$sync_ok" | jq -c '.data|{success,failed}')" \
    "$(printf '%s' "$sync_partial" | jq -c '.data|{success,failed}')" \
    "$s200" "$s503" "$s429" "$sother"
  if [ "$sother" -ne 0 ]; then
    echo "public audit saw unexpected HTTP statuses:" >&2
    sort "$out" | uniq -c >&2
    return 1
  fi
  trap - RETURN
  cleanup_public
}

run_managed_upgrade_smoke() {
  local work_dir="$1"
  local db_file="$work_dir/managed-upgrade.sqlite"
  local db_url="sqlite://$db_file?mode=rwc"
  local log_file="$work_dir/managed_upgrade.log"

  sqlite3 "$db_file" "CREATE TABLE IF NOT EXISTS pushgo_schema_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL); INSERT OR REPLACE INTO pushgo_schema_meta (meta_key, meta_value) VALUES ('schema_version', '2026-03-18-gateway-v4'); CREATE TABLE IF NOT EXISTS private_bindings (platform INTEGER NOT NULL, token_hash BLOB NOT NULL, device_id BLOB NOT NULL, PRIMARY KEY (platform, token_hash));" >/dev/null
  "$GATEWAY_BIN" \
    --db-url "$db_url" \
    --db-upgrade run \
    >"$log_file" 2>&1

  grep -q '^\[upgrade\] completed' "$log_file" || {
    echo "managed upgrade smoke did not complete; log follows:" >&2
    cat "$log_file" >&2
    return 1
  }
  local schema_version
  schema_version="$(sqlite3 "$db_file" "SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version';")"
  if [ "$schema_version" != "2026-04-22-gateway-v9" ]; then
    echo "managed upgrade smoke schema mismatch: $schema_version" >&2
    cat "$log_file" >&2
    return 1
  fi
  local completed_runs
  completed_runs="$(sqlite3 "$db_file" "SELECT COUNT(1) FROM pushgo_upgrade_runs WHERE status='completed';")"
  if [ "$completed_runs" -lt 1 ]; then
    echo "managed upgrade smoke did not record a completed upgrade run" >&2
    cat "$log_file" >&2
    return 1
  fi
  printf 'MANAGED_UPGRADE_WORK_DIR=%s\nMANAGED_UPGRADE_SCHEMA=%s\nMANAGED_UPGRADE_COMPLETED_RUNS=%s\n' \
    "$work_dir" "$schema_version" "$completed_runs"
}

run_private_flow() {
  local work_dir="$1"
  local http_port="$2"
  local tcp_port="$3"
  local quic_port="$4"
  local db_file="$work_dir/private.sqlite"
  local db_url="sqlite://$db_file?mode=rwc"
  local base_url="http://127.0.0.1:${http_port}"
  local log_file="$work_dir/private_gateway.log"
  local cert_file="$work_dir/private-cert.pem"
  local key_file="$work_dir/private-key.pem"

  openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "$key_file" \
    -out "$cert_file" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1

  "$GATEWAY_BIN" \
    --http-addr "127.0.0.1:${http_port}" \
    --db-url "$db_url" \
    --token "$TOKEN" \
    --private-transports quic,tcp,wss \
    --private-tcp-bind "127.0.0.1:${tcp_port}" \
    --private-tcp-port "$tcp_port" \
    --private-quic-bind "127.0.0.1:${quic_port}" \
    --private-quic-port "$quic_port" \
    --private-tls-cert "$cert_file" \
    --private-tls-key "$key_file" \
    >"$log_file" 2>&1 &
  local pid=$!

  cleanup_private() {
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_private RETURN

  wait_http_ready "$base_url" "$TOKEN" || {
    echo "private gateway failed to become ready; log follows:" >&2
    cat "$log_file" >&2
    return 1
  }

  local reg device_key sub cid
  reg="$(post_json "$base_url" "$TOKEN" "/device/register" '{"platform":"ios"}')"
  device_key="$(printf '%s' "$reg" | jq -r '.data.device_key')"
  post_json "$base_url" "$TOKEN" "/channel/device" "{\"device_key\":\"$device_key\",\"platform\":\"ios\",\"channel_type\":\"private\"}" >/dev/null
  sub="$(post_json "$base_url" "$TOKEN" "/channel/subscribe" "{\"device_key\":\"$device_key\",\"channel_name\":\"audit-private-a\",\"password\":\"benchmark-123\"}")"
  cid="$(printf '%s' "$sub" | jq -r '.data.channel_id')"

  local out="$work_dir/private_send_codes.txt"
  : > "$out"
  for _ in $(seq 1 80); do
    local payload code
    payload="$(printf '{"channel_id":"%s","password":"benchmark-123","title":"private-audit","body":"payload","metadata":{}}' "$cid")"
    code="$(curl -sS -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -X POST "$base_url/message" \
      -d "$payload" || true)"
    printf '%s\n' "$code" >> "$out"
  done

  local send_200 send_other outbox_before outbox_after ttl_delta
  send_200="$(grep -c '^200$' "$out" || true)"
  send_other="$(awk '$1!="200"{c++} END{print c+0}' "$out")"
  outbox_before="$(sqlite3 "$db_file" "SELECT COUNT(1) FROM private_outbox;")"
  ttl_delta="$(sqlite3 "$db_file" "SELECT COALESCE(MAX(expires_at - sent_at),0) FROM private_payloads;")"

  outbox_after="$(sqlite3 "$db_file" "SELECT COUNT(1) FROM private_outbox;")"

  printf 'PRIVATE_WORK_DIR=%s\nPRIVATE_DEVICE_KEY=%s\nPRIVATE_CHANNEL=%s\nPRIVATE_SEND_200=%s\nPRIVATE_SEND_OTHER=%s\nPRIVATE_OUTBOX_BEFORE=%s\nPRIVATE_OUTBOX_AFTER=%s\nPRIVATE_MAX_TTL_DELTA=%s\n' \
    "$work_dir" "$device_key" "$cid" "$send_200" "$send_other" "$outbox_before" "$outbox_after" "$ttl_delta"
  if [ "$send_other" -ne 0 ]; then
    echo "private audit saw unexpected HTTP statuses:" >&2
    sort "$out" | uniq -c >&2
    return 1
  fi
  trap - RETURN
  cleanup_private
}

main() {
  local mode="${1:-all}"
  if [ "$mode" = "all" ] || [ "$mode" = "precheck" ]; then
    echo "=== PRECHECK ==="
    cargo fmt --check
    cargo check --all-targets
    cargo test -- --test-threads=1
    cargo build --release --locked --bin pushgo-gateway
    run_managed_upgrade_smoke "$(mktemp -d /tmp/pushgo-preflight-upgrade.XXXXXX)"
  fi

  if [ "$mode" = "all" ] || [ "$mode" = "public" ]; then
    echo "=== PUBLIC FLOW ==="
    run_public_flow "$(mktemp -d /tmp/pushgo-preflight-public.XXXXXX)" 17731
  fi

  if [ "$mode" = "all" ] || [ "$mode" = "private" ]; then
    echo "=== PRIVATE FLOW ==="
    run_private_flow "$(mktemp -d /tmp/pushgo-preflight-private.XXXXXX)" 17741 57741 57742
  fi
}

main "$@"
