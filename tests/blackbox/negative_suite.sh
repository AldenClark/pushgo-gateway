#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-$ROOT_DIR/target/release/pushgo-gateway}"
TOKEN="${TOKEN:-blackbox-token}"
WRONG_TOKEN="${WRONG_TOKEN:-blackbox-token-wrong}"
HTTP_PORT="${HTTP_PORT:-17880}"
DB_URL="${DB_URL:-sqlite:///tmp/pushgo-blackbox-negative.sqlite?mode=rwc}"
OUT_FILE="${OUT_FILE:-/tmp/pushgo-blackbox-negative-${HTTP_PORT}.txt}"
LOG_FILE="${LOG_FILE:-/tmp/pushgo-blackbox-negative-${HTTP_PORT}.log}"
PRIVATE_TCP_PORT="${PRIVATE_TCP_PORT:-57880}"
PRIVATE_QUIC_PORT="${PRIVATE_QUIC_PORT:-57881}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

for c in curl jq openssl; do
  need_cmd "$c"
done

wait_http_ready() {
  local base_url="$1"
  local token="$2"
  for _ in $(seq 1 200); do
    if curl -fsS -H "Authorization: Bearer $token" "$base_url/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

request() {
  local method="$1"
  local base_url="$2"
  local path="$3"
  local auth_mode="$4"
  local content_type="${5:-application/json}"
  local data="${6:-}"

  local raw
  if [ "$auth_mode" = "valid" ]; then
    raw="$(
      curl -sS -w '\n%{http_code}' \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: $content_type" \
        -X "$method" "$base_url$path" \
        -d "$data"
    )"
  elif [ "$auth_mode" = "invalid" ]; then
    raw="$(
      curl -sS -w '\n%{http_code}' \
        -H "Authorization: Bearer $WRONG_TOKEN" \
        -H "Content-Type: $content_type" \
        -X "$method" "$base_url$path" \
        -d "$data"
    )"
  else
    raw="$(
      curl -sS -w '\n%{http_code}' \
        -H "Content-Type: $content_type" \
        -X "$method" "$base_url$path" \
        -d "$data"
    )"
  fi

  REQUEST_BODY="$(echo "$raw" | sed '$d')"
  REQUEST_STATUS="$(echo "$raw" | tail -n1)"
}

write_case() {
  local name="$1"
  local status="$2"
  local code="$3"
  printf '%s|status=%s|code=%s\n' "$name" "$status" "$code" >>"$OUT_FILE"
}

require_status() {
  local expected="$1"
  local actual="$2"
  local label="$3"
  local body="$4"
  if [ "$actual" != "$expected" ]; then
    echo "case setup failed: ${label}, expected ${expected}, got ${actual}" >&2
    echo "response body: ${body}" >&2
    exit 1
  fi
}

extract_code() {
  local json="$1"
  if [ -z "$json" ]; then
    echo "none"
    return
  fi
  echo "$json" | jq -r '.code // "none"' 2>/dev/null || echo "none"
}

extract_field() {
  local json="$1"
  local jq_expr="$2"
  echo "$json" | jq -r "$jq_expr" 2>/dev/null
}

cleanup() {
  if [ -n "${GW_PID:-}" ] && kill -0 "$GW_PID" 2>/dev/null; then
    kill "$GW_PID" >/dev/null 2>&1 || true
    wait "$GW_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "${CERT_FILE:-}" ]; then
    rm -f "$CERT_FILE" >/dev/null 2>&1 || true
  fi
  if [ -n "${KEY_FILE:-}" ]; then
    rm -f "$KEY_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
  cargo build --release --locked --bin pushgo-gateway >/dev/null
fi

CERT_FILE="$(mktemp /tmp/pushgo-blackbox-cert.XXXXXX.pem)"
KEY_FILE="$(mktemp /tmp/pushgo-blackbox-key.XXXXXX.pem)"
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -subj "/CN=127.0.0.1" >/dev/null 2>&1

"$BIN" \
  --http-addr "127.0.0.1:${HTTP_PORT}" \
  --db-url "$DB_URL" \
  --token "$TOKEN" \
  --private-channel-enabled \
  --private-tcp-bind "127.0.0.1:${PRIVATE_TCP_PORT}" \
  --private-tcp-port "$PRIVATE_TCP_PORT" \
  --private-tcp-tls-offload \
  --private-quic-bind "127.0.0.1:${PRIVATE_QUIC_PORT}" \
  --private-quic-port "$PRIVATE_QUIC_PORT" \
  --private-tls-cert "$CERT_FILE" \
  --private-tls-key "$KEY_FILE" \
  --diagnostics-api-enabled \
  >"$LOG_FILE" 2>&1 &
GW_PID=$!

BASE_URL="http://127.0.0.1:${HTTP_PORT}"
wait_http_ready "$BASE_URL" "$TOKEN"

: >"$OUT_FILE"

request "GET" "$BASE_URL" "/" "none" "application/json" ""
write_case "auth.missing" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "GET" "$BASE_URL" "/" "invalid" "application/json" ""
write_case "auth.invalid" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/device/register" "valid" "application/json" "{bad json"
write_case "device_register.invalid_json" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/device/register" "valid" "application/json" '{"platform":"invalid"}'
write_case "device_register.invalid_platform" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/device/register" "valid" "application/json" '{"platform":"android"}'
write_case "device_register.private_ok" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"
require_status "200" "$REQUEST_STATUS" "device_register.private_ok" "$REQUEST_BODY"
DEVICE_KEY="$(extract_field "$REQUEST_BODY" '.data.device_key')"
if [ -z "$DEVICE_KEY" ] || [ "$DEVICE_KEY" = "null" ]; then
  echo "case setup failed: empty device_key in register response" >&2
  echo "response body: $REQUEST_BODY" >&2
  exit 1
fi

request "POST" "$BASE_URL" "/channel/subscribe" "valid" "application/json" "{\"device_key\":\"$DEVICE_KEY\",\"channel_name\":\"blackbox-negative\",\"password\":\"benchmark-123\"}"
write_case "channel_subscribe.ok" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"
require_status "200" "$REQUEST_STATUS" "channel_subscribe.ok" "$REQUEST_BODY"
CHANNEL_ID="$(extract_field "$REQUEST_BODY" '.data.channel_id')"
if [ -z "$CHANNEL_ID" ] || [ "$CHANNEL_ID" = "null" ]; then
  echo "case setup failed: empty channel_id in subscribe response" >&2
  echo "response body: $REQUEST_BODY" >&2
  exit 1
fi

request "POST" "$BASE_URL" "/message" "valid" "application/json" "{\"channel_id\":\"$CHANNEL_ID\",\"password\":\"wrong-pass\",\"title\":\"test\",\"body\":\"test\"}"
write_case "message.wrong_password" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/message" "valid" "application/json" '{"password":"benchmark-123","title":"test","body":"test"}'
write_case "message.missing_channel_id" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/event/create" "valid" "application/json" "{\"channel_id\":\"$CHANNEL_ID\",\"password\":\"benchmark-123\",\"event_id\":\"forbidden\",\"title\":\"evt\",\"message\":\"evt\"}"
write_case "event_create.forbidden_event_id" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/thing/thing-1/message" "valid" "application/json" "{\"password\":\"benchmark-123\",\"title\":\"thing-msg\",\"body\":\"thing-msg\"}"
write_case "thing_scoped_message.not_found" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

request "POST" "$BASE_URL" "/channel/subscribe" "valid" "application/json" "{\"device_key\":\"$DEVICE_KEY\",\"channel_name\":\"blackbox-negative-2\",\"password\":\"benchmark-123\"}"
require_status "200" "$REQUEST_STATUS" "channel_subscribe.second_ok" "$REQUEST_BODY"
CHANNEL_ID_2="$(extract_field "$REQUEST_BODY" '.data.channel_id')"
if [ -z "$CHANNEL_ID_2" ] || [ "$CHANNEL_ID_2" = "null" ]; then
  echo "case setup failed: empty second channel_id in subscribe response" >&2
  echo "response body: $REQUEST_BODY" >&2
  exit 1
fi

request "POST" "$BASE_URL" "/channel/sync" "valid" "application/json" "{\"device_key\":\"$DEVICE_KEY\",\"channels\":[{\"channel_id\":\"$CHANNEL_ID\",\"password\":\"benchmark-123\"},{\"channel_id\":\"$CHANNEL_ID_2\",\"password\":\"wrong-pass\"}]}"
SYNC_STATUS="$REQUEST_STATUS"
SYNC_SUCCESS="$(extract_field "$REQUEST_BODY" '.data.success')"
SYNC_FAILED="$(extract_field "$REQUEST_BODY" '.data.failed')"
write_case "channel_sync.partial" "$SYNC_STATUS" "success=${SYNC_SUCCESS},failed=${SYNC_FAILED}"

request "GET" "$BASE_URL" "/diagnostics/dispatch" "valid" "application/json" ""
write_case "diagnostics_dispatch.enabled" "$REQUEST_STATUS" "$(extract_code "$REQUEST_BODY")"

echo "OUT_FILE=$OUT_FILE"
echo "LOG_FILE=$LOG_FILE"
