# PushGo Gateway

`pushgo-gateway` is the gateway service for PushGo, with three core capability groups:

- Public API: HTTP endpoints for devices, channels, messages, and events
- Private transport: real-time delivery over QUIC / Raw TCP / WSS / MQTT 5
- MCP gateway: MCP HTTP endpoint, OAuth flow, and channel-binding pages for MCP clients

## Project Links

- Gateway (this repository): https://github.com/AldenClark/pushgo-gateway
- Apple client: https://github.com/AldenClark/pushgo
- Android client: https://github.com/AldenClark/pushgo-android

## Public Endpoints by Region

- Global region
- token-service: `https://token.pushgo.dev/`
- gateway: `https://gateway.pushgo.dev/`
- Mainland China region
- token-service: `https://token.pushgo.cn/`
- gateway: `https://gateway.pushgo.cn/`

In production, explicitly set `--token-service-url` (or `PUSHGO_TOKEN_SERVICE_URL`) based on region.

## Private Transport Model

### 1) Transport layers

- QUIC: dedicated UDP listener (`--private-quic-bind`)
- Raw TCP: dedicated TCP listener (`--private-tcp-bind`)
- WSS: upgraded from HTTP at `/private/ws` with subprotocol `pushgo-private.v1`
- MQTT 5: dedicated TCP listener (`--mqtt-bind`) using QoS 1 only

### 2) Parameter dependency map

- `--private-transports` is the master switch for private runtime. It supports `true`/`false` and explicit sets like `quic,tcp,wss,mqtt`.
- Private runtime has no implicit fallback: only transports listed in `--private-transports` are enabled.
- `--private-*-bind` always means the local listener address owned by gateway.
- `--private-*-port` always means the port advertised to app clients via `/gateway/profile` (`transport` hints).
- If `quic` is enabled, `--private-tls-cert` + `--private-tls-key` are required.
- Raw TCP is plain by default. Set `--private-tcp-tls-enabled=true` only when gateway should terminate TLS itself.
- WSS has no separate bind flag; it rides on `--http-addr` and is typically exposed by edge TLS.
- MQTT is plain by default. Set `--mqtt-tls-enabled=true` only when gateway should terminate MQTT/TLS itself.
- MQTT accepts only MQTT 5 and QoS 1. CONNECT must include MQTT 5 User Property `device_type=publish` or `device_type=subscribe`.
- `device_type=publish` creates a temporary publish-only connection and is not persisted as a device route; any CONNECT client id on publish-only connections is ignored. `device_type=subscribe` is a persistent MQTT device identity; use an existing `client_id=<device_key>` or leave `client_id` empty. If the supplied subscribe client id is missing, unknown, or replaced because it belongs to another platform, gateway issues a new device key and returns it in the MQTT 5 CONNACK Assigned Client Identifier; clients must persist that returned value as the next `client_id`.
- MQTT does not expose broker-style session persistence: CONNACK advertises `session_expiry_interval=0`, no retained messages, no topic aliases, no subscription identifiers, no wildcard/shared subscriptions. PushGo channel subscriptions are persisted by gateway and outlive the TCP connection.
- MQTT topic is the raw `{channel_id}`. Channel password is passed as MQTT 5 User Property `pushgo-password`; gateway token, when configured, is passed as MQTT username. Each SUBSCRIBE packet may contain only one topic filter.
- MQTT payload uses an envelope: publish `{"type":"message","data":{...}}`, downlink `{"schema":"pushgo.mqtt.delivery.v1","type":"message","delivery_id":"...","channel_id":"...","data":{...}}`. Topic identifies the channel; payload `type` identifies the business model. Current MQTT ingress and downlink support `message` only. MQTT publish message data may include `thing_id` to create a thing-scoped message through the shared gateway send path, but MQTT downlink delivers channel-level message payloads only; event, thing, thing-scoped message, and thing-scoped event payloads are not enqueued to MQTT devices.
- MQTT Will Message is accepted only from `device_type=subscribe` devices. Will Topic is raw `{channel_id}` and may target any channel. Will QoS must be 1, Will Retain must be false, Will Properties must include User Property `pushgo-password`, and Will payload uses the same publish envelope. Gateway validates the Will at CONNECT, publishes it on abnormal connection close or MQTT 5 `DisconnectWithWillMessage`, and suppresses it on normal DISCONNECT.

## MCP Runtime Model

- `--mcp-enabled=true` mounts `/mcp`, `/oauth/*`, and `/.well-known/*` endpoints on the same HTTP listener as the public API.
- `--public-base-url` is recommended for reverse-proxy / container deployments so OAuth issuer URLs, bind URLs, and WSS hints point to the externally reachable HTTPS origin.
- `--mcp-predefined-clients` accepts `client_id:client_secret` entries separated by semicolons or newlines.
- If `--public-base-url` is omitted, gateway will bootstrap issuer URLs from the incoming HTTPS origin when possible; fixed public deployments should still set it explicitly.

## CLI Reference

Main options support both CLI flag and environment variable forms.  
Advanced env-only runtime tunables are listed in a separate section below.

### Core

| CLI Flag                          | Env                                    | Default                    | Required          | Description                                            |
| --------------------------------- | -------------------------------------- | -------------------------- | ----------------- | ------------------------------------------------------ |
| `--http-addr`                     | `PUSHGO_HTTP_ADDR`                     | `127.0.0.1:6666`           | No                | HTTP API / WSS bind address                            |
| `--token`                         | `PUSHGO_TOKEN`                         | None                       | No                | Public API auth token (`Authorization: Bearer <token>` first; fallback `?token=<token>` only when Authorization is absent) |
| `--sandbox-mode`                  | `PUSHGO_SANDBOX_MODE`                  | `false`                    | No                | Sandbox mode (including APNS sandbox endpoint)         |
| `--token-service-url`             | `PUSHGO_TOKEN_SERVICE_URL`             | `https://token.pushgo.dev` | No                | token-service endpoint (recommended to set explicitly) |
| `--private-transports`            | `PUSHGO_PRIVATE_TRANSPORTS`            | `false`                    | No                | Private transport switch (`true/false` or `quic,tcp,wss,mqtt`) |
| `--runtime-profile`               | `PUSHGO_RUNTIME_PROFILE`               | `small`                    | No                | Resource/performance profile (`small`/`public`); never changes the database driver selected by `--db-url` |
| `--observability-profile`         | `PUSHGO_OBSERVABILITY_PROFILE`         | `prod_min`                 | No                | Observability matrix profile (`prod_min`/`ops`/`incident`/`debug`) |
| `--observability-log-level`       | `PUSHGO_OBSERVABILITY_LOG_LEVEL`       | `warn`                     | No                | Native tracing log level (`off`/`error`/`warn`/`info`/`debug`/`trace`) |
| `--db-url`                        | `PUSHGO_DB_URL`                        | None                       | Yes               | Database URL (`sqlite://`, `postgres://`, `postgresql://`, `pg://`, `mysql://`) |
| `--public-base-url`               | `PUSHGO_PUBLIC_BASE_URL`               | None                       | No                | External HTTPS base URL used for MCP/OAuth issuer URLs and advertised WSS URL |

### Private Transport Bind / Advertise

| CLI Flag                    | Env                         | Default          | Required | Description                              |
| --------------------------- | --------------------------- | ---------------- | -------- | ---------------------------------------- |
| `--private-quic-bind`       | `PUSHGO_PRIVATE_QUIC_BIND`  | `127.0.0.1:5223` | No       | Local QUIC listener bind address (UDP)   |
| `--private-quic-port`       | `PUSHGO_PRIVATE_QUIC_PORT`  | `5223`           | No       | QUIC port advertised to app clients      |
| `--private-tcp-bind`        | `PUSHGO_PRIVATE_TCP_BIND`   | `127.0.0.1:5223` | No       | Local Raw TCP listener bind address      |
| `--private-tcp-port`        | `PUSHGO_PRIVATE_TCP_PORT`   | `5223`           | No       | TCP port advertised to app clients       |
| `--mqtt-bind`               | `PUSHGO_MQTT_BIND`          | `127.0.0.1:1883` | No       | Local MQTT 5 listener bind address       |
| `--mqtt-port`               | `PUSHGO_MQTT_PORT`          | `1883`           | No       | MQTT port advertised to app clients      |
| `--mqtt-tls-enabled`        | `PUSHGO_MQTT_TLS_ENABLED`   | `false`          | No       | Terminate MQTT/TLS in gateway instead of accepting plain MQTT |
| `--mqtt-max-packet-bytes`   | `PUSHGO_MQTT_MAX_PACKET_BYTES` | `32768`       | No       | Maximum MQTT packet size accepted by gateway |

### Private TLS

| CLI Flag                    | Env                              | Default | Required          | Description                                         |
| --------------------------- | -------------------------------- | ------- | ----------------- | --------------------------------------------------- |
| `--private-tls-cert`        | `PUSHGO_PRIVATE_TLS_CERT`        | None    | Conditional       | TLS cert PEM required by `quic`, by `tcp` when `private-tcp-tls-enabled=true`, and by `mqtt` when `mqtt-tls-enabled=true` |
| `--private-tls-key`         | `PUSHGO_PRIVATE_TLS_KEY`         | None    | Conditional       | TLS key PEM required by `quic`, by `tcp` when `private-tcp-tls-enabled=true`, and by `mqtt` when `mqtt-tls-enabled=true`  |
| `--private-tcp-tls-enabled` | `PUSHGO_PRIVATE_TCP_TLS_ENABLED` | `false` | No                | Terminate Raw TCP TLS in gateway instead of accepting plain TCP |
| `--private-tcp-proxy-protocol` | `PUSHGO_PRIVATE_TCP_PROXY_PROTOCOL` | `false` | No            | Expect PROXY protocol v1 on Raw TCP ingress          |

### Runtime Profiles

Fine-grained performance/resource knobs are internal profile defaults, not public CLI/env parameters.

| Profile | Intended deployment | Key defaults |
| ------- | ------------------- | ------------ |
| `small` | Tiny/private SQLite deployment | Lower SQLite/cache/queue footprints, 10s stats flush, no idle gateway metric sampling, 5min maintenance tick, provider in-flight caps 32/32/16 |
| `public` | Large external-DB gateway, primarily PostgreSQL | Larger dispatch/stats queues, 2s stats flush, gateway metric sampling, external DB pool max 64/min 4, provider in-flight caps 128/256/128 |

Database driver selection is always based on `--db-url`; setting `--runtime-profile=public` with a SQLite URL still uses SQLite, and setting `--runtime-profile=small` with a PostgreSQL URL still uses PostgreSQL. If omitted, `small` is used.

### MCP / OAuth

| CLI Flag                                  | Env                                             | Default     | Required | Description                                                            |
| ----------------------------------------- | ----------------------------------------------- | ----------- | -------- | ---------------------------------------------------------------------- |
| `--mcp-enabled`                           | `PUSHGO_MCP_ENABLED`                            | `false`     | No       | Enable MCP HTTP endpoint (`/mcp`) and related OAuth / bind routes      |
| `--mcp-dcr-enabled`                       | `PUSHGO_MCP_DCR_ENABLED`                        | `true`      | No       | Enable OAuth Dynamic Client Registration                               |
| `--mcp-predefined-clients`                | `PUSHGO_MCP_PREDEFINED_CLIENTS`                 | None        | No       | Predefined OAuth clients as `client_id:client_secret` joined by `;` or newlines |

### Advanced Environment Variables (env-only)

| Env                                         | Default                                | Description                                                                 |
| ------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------- |
| `PUSHGO_OBSERVABILITY_LOG_LEVEL`              | `warn`                              | Optional override for native tracing log level                               |
| `RUST_LOG`                                    | None                                | Optional full EnvFilter directive override (higher priority than profile/level) |

## Channel Password Hash Strategy

- New writes use `blake3 + salt` with a PHC-like string format:
  - `$pushgo-blake3$v=1$<salt_base64url_nopad>$<digest_base64url_nopad>`
- Legacy `argon2` hashes remain readable.
- On successful legacy verification, gateway upgrades that row in-place to the new `blake3` format immediately (no offline migration required).

This keeps private deployment CPU cost low while maintaining non-plaintext storage.

### Operations Stats (DB)

`stats` is persisted for operations reporting (not only business semantics).
In addition to existing channel/device/gateway aggregates, gateway now writes operational hourly counters into `ops_stats_hourly` (`bucket_hour`, `metric_key`, `metric_value`), e.g. provider send failures, HTTP 5xx responses, and invalid-token cleanup failures.

### Trace Event Output

Gateway now uses one native `tracing` pipeline for both spans and events.
Default output level is `warn`; use `--observability-log-level` (or `PUSHGO_OBSERVABILITY_LOG_LEVEL`) to raise/lower verbosity, and use `RUST_LOG` when full EnvFilter routing is needed.
Each trace event contains fixed envelope fields (`ts_ms`, `component`, `event`) and a whitelist of typed fields.
Potentially sensitive identifiers are emitted through redacted fields.

Example:

```json
{"ts_ms":1713750000000,"component":"gateway","event":"dispatch.provider_send_failed","provider":"fcm","status_code":503,"invalid_token":false}
```

## Memory Forensics (Private Runtime)

Use compile-time symbol/stack support + external profilers + runtime diagnostics on the same timeline.

### 1) Build a profiling binary

```bash
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --profile profiling
```

`profiling` profile keeps release optimizations but preserves better debug attribution.

### 2) Run timeline sampling against a live gateway process

```bash
./scripts/private_memory_observe.sh \
  --pid <gateway_pid> \
  --base-url http://127.0.0.1:6666 \
  --auth-token <token> \
  --interval-ms 500 \
  --duration-secs 180
```

This records:
- `/proc/<pid>/smaps_rollup` (`Rss`, `Anonymous`, `Private_Dirty`, etc.)
- `/proc/<pid>/status` (`VmRSS`, `VmData`, `Threads`, etc.)
- `/diagnostics/private/memory` snapshot file per sample timestamp

Use `samples.jsonl` as the timeline index to align process memory segments and in-process object snapshots.

### 3) External allocation call-stack capture (Linux)

`heaptrack`:

```bash
heaptrack --output heaptrack.gateway.gz \
  target/profiling/pushgo-gateway <gateway args...>
```

`valgrind massif`:

```bash
valgrind --tool=massif --time-unit=ms --stacks=yes \
  --massif-out-file=massif.out.gateway \
  target/profiling/pushgo-gateway <gateway args...>
```

Then correlate profiler hotspots with the same test window in `samples.jsonl` and diagnostics snapshots.

## Nginx / LB Deployment Reference

### A) HTTP API + WSS (`/private/ws`)

```nginx
server {
    listen 443 ssl http2;
    server_name gateway.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "for=$remote_addr;proto=$scheme;host=$host";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://127.0.0.1:6666;
    }
}
```

### B) Raw TCP (`stream`)

Default plain Raw TCP:

```nginx
stream {
    upstream pushgo_private_tcp_plain {
        server 127.0.0.1:5223;
    }

    server {
        listen 5223;
        proxy_pass pushgo_private_tcp_plain;
        proxy_protocol on;
        proxy_connect_timeout 3s;
        proxy_timeout 600s;
    }
}
```

Gateway-terminated TLS (`--private-tcp-tls-enabled=true`):

```nginx
stream {
    upstream pushgo_private_tcp_tls {
        server 127.0.0.1:55223;
    }

    server {
        listen 5223;
        proxy_pass pushgo_private_tcp_tls;
        proxy_protocol on;
        proxy_connect_timeout 3s;
        proxy_timeout 600s;
    }
}
```

### C) QUIC (UDP)

```nginx
stream {
    upstream pushgo_quic_udp {
        server 127.0.0.1:5223;
    }

    server {
        listen 5223 udp;
        proxy_pass pushgo_quic_udp;
        proxy_timeout 600s;
    }
}
```

### D) MQTT 5 (`stream`)

Default plain MQTT:

```nginx
stream {
    upstream pushgo_mqtt_plain {
        server 127.0.0.1:1883;
    }

    server {
        listen 8883 ssl;
        ssl_certificate     /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        proxy_pass pushgo_mqtt_plain;
        proxy_connect_timeout 3s;
        proxy_timeout 600s;
    }
}
```

MQTT clients must use MQTT 5 and QoS 1. CONNECT must include User Property `device_type=publish` for temporary publish-only devices, or `device_type=subscribe` for persistent devices that may SUBSCRIBE and receive messages. Publish-only client ids are ignored and never persisted. Subscribe devices may pass `client_id=<device_key>` or an empty `client_id`; when the supplied client id is empty, unknown, or replaced because it belongs to another platform, gateway returns the newly assigned device key in CONNACK Assigned Client Identifier and clients must use that value as the next client id. SUBSCRIBE/PUBLISH use topic `{channel_id}` and MQTT 5 User Property `pushgo-password=<channel password>`. MQTT publish payload is `{"type":"message","data":{...}}`; `data` may include `thing_id` to create a thing-scoped message, and thing-scoped sends follow the same core validation as HTTP, including `occurred_at` when required. MQTT downlink payload is `{"schema":"pushgo.mqtt.delivery.v1","type":"message","delivery_id":"...","channel_id":"...","data":{...}}` and receives channel-level messages only; event, thing, thing-scoped message, and thing-scoped event payloads are skipped before MQTT outbox enqueue. Each SUBSCRIBE packet may contain only one topic filter. Gateway advertises no MQTT broker session persistence, retained messages, topic aliases, subscription identifiers, wildcard subscriptions, or shared subscriptions; PushGo channel subscriptions are the persisted subscription state. MQTT Will Message is available only to `device_type=subscribe`; Will Topic is `{channel_id}` and may target any channel, Will QoS must be 1, Will Retain must be false, Will Properties must include User Property `pushgo-password`, and Will payload uses the same publish envelope. Gateway publishes the Will on abnormal close or MQTT 5 `DisconnectWithWillMessage`, but not on normal DISCONNECT. If `--mqtt-tls-enabled=false`, clients connect with plain MQTT to gateway; if `true`, clients connect with MQTT/TLS directly to gateway.

### E) Critical note on `443/udp` conflicts

PushGo QUIC uses a custom ALPN (`pushgo-quic`), not HTTP/3.  
If the same Nginx instance already serves HTTP/3 on `443/udp`, private QUIC cannot share that same UDP socket.

Recommended patterns:

1. Use a dedicated UDP port for private QUIC (for example `5223/udp`) and keep HTTP/3 on `443/udp`.
2. Use a dedicated LB/public IP for private QUIC (you can still expose external `443/udp` there).

PushGo now defaults to loopback-only private listeners (`127.0.0.1:5223` for both QUIC and Raw TCP) and separates advertised app ports from local bind ports via `/gateway/profile`.

## Installation and Runtime

### Option 1: Run binary directly (download release or build from source)

Download prebuilt binary (example):

```bash
curl -fL -o pushgo-gateway \
  https://github.com/<owner>/<repo>/releases/download/<tag>/pushgo-gateway-amd64-musl
chmod +x pushgo-gateway
```

Build from source:

```bash
cargo build --release -p pushgo-gateway
./target/release/pushgo-gateway --db-url <DB_URL>
```

On Linux, systemd is recommended:

```ini
[Unit]
Description=PushGo Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pushgo
Group=pushgo
WorkingDirectory=/opt/pushgo-gateway
ExecStart=/opt/pushgo-gateway/pushgo-gateway \
  --http-addr 0.0.0.0:6666 \
  --private-transports quic,tcp,wss \
  --private-quic-bind 127.0.0.1:5223 \
  --private-quic-port 443 \
  --private-tcp-bind 127.0.0.1:5223 \
  --private-tcp-port 5223 \
  --db-url ${PUSHGO_DB_URL} \
  --token-service-url https://token.pushgo.dev

Environment=PUSHGO_DB_URL=postgres://user:pass@127.0.0.1:5432/pushgo
Environment=PUSHGO_PRIVATE_TLS_CERT=/etc/pushgo/certs/fullchain.pem
Environment=PUSHGO_PRIVATE_TLS_KEY=/etc/pushgo/certs/privkey.pem
Environment=PUSHGO_TOKEN=<gateway-bearer-token>

Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### Option 2: Run with Docker

Docker image files:

- `Dockerfile.gha`: release/GitHub Actions image assembly from prebuilt `dist/*-gnu` binaries.
- `Dockerfile.local`: local source build (multi-stage) for developer machines.

Published images (for example `ghcr.io/<owner>/pushgo-gateway:latest`) are built from `Dockerfile.gha`.

Build locally from source:

```bash
docker build -f Dockerfile.local -t pushgo-gateway:local .
```

Image ports:

- `6666/tcp`: HTTP API + WSS
- `5223/tcp`: Raw TCP
- `5223/udp`: QUIC
- `1883/tcp` or edge `8883/tcp`: MQTT 5

MCP/OAuth routes (`/mcp`, `/oauth/*`, `/.well-known/*`) also use `6666/tcp`; no extra container port is required.

Example:

```bash
docker run -d --name pushgo-gateway \
  -p 6666:6666 \
  -p 5223:5223/tcp \
  -p 5223:5223/udp \
  -e PUSHGO_HTTP_ADDR=0.0.0.0:6666 \
  -e PUSHGO_DB_URL='postgres://user:pass@db:5432/pushgo' \
  -e PUSHGO_TOKEN_SERVICE_URL='https://token.pushgo.dev' \
  -e PUSHGO_PRIVATE_TRANSPORTS=quic,tcp,wss \
  -e PUSHGO_MCP_ENABLED=true \
  -e PUSHGO_PUBLIC_BASE_URL='https://gateway.example.com' \
  -e PUSHGO_MCP_PREDEFINED_CLIENTS='chatgpt-prod:replace-me' \
  -e PUSHGO_PRIVATE_QUIC_BIND=0.0.0.0:5223 \
  -e PUSHGO_PRIVATE_QUIC_PORT=443 \
  -e PUSHGO_PRIVATE_TCP_BIND=0.0.0.0:5223 \
  -e PUSHGO_PRIVATE_TCP_PORT=5223 \
  -e PUSHGO_PRIVATE_TLS_CERT=/certs/fullchain.pem \
  -e PUSHGO_PRIVATE_TLS_KEY=/certs/privkey.pem \
  -v /etc/pushgo/certs:/certs:ro \
  ghcr.io/<owner>/pushgo-gateway:latest
```

If you rely on Dynamic Client Registration, you can omit `PUSHGO_MCP_PREDEFINED_CLIENTS`. For fixed clients, keep `PUSHGO_PUBLIC_BASE_URL` on the public HTTPS origin exposed by your reverse proxy or LB.

## Production Recommendations

1. Enable QUIC + Raw TCP together, and keep WSS as a compatibility path for restricted networks.
2. Keep local private listeners on loopback and let the edge own public exposure.
3. Plan private QUIC and HTTP/3 with separate `443/udp` ownership to avoid socket conflicts.

---

# PushGo Gateway（中文）

`pushgo-gateway` 是 PushGo 的网关服务，主要包含三类能力：

- 公共 API：设备、频道、消息、事件等 HTTP 接口
- 私有传输层：基于 QUIC / Raw TCP / WSS / MQTT 5 的实时收发
- MCP 网关：面向 MCP 客户端的 MCP HTTP 入口、OAuth 流程与频道绑定页面

## 项目链接

- 网关（本仓库）：https://github.com/AldenClark/pushgo-gateway
- Apple 客户端：https://github.com/AldenClark/pushgo
- Android 客户端：https://github.com/AldenClark/pushgo-android

## 公共服务地址（按地域）

- 全球区域
- token-service: `https://token.pushgo.dev/`
- gateway: `https://gateway.pushgo.dev/`
- 中国大陆区域
- token-service: `https://token.pushgo.cn/`
- gateway: `https://gateway.pushgo.cn/`

生产环境建议根据部署地域显式设置 `--token-service-url`（或 `PUSHGO_TOKEN_SERVICE_URL`）。

## 私有传输模型

### 1) 传输层组成

- QUIC：独立 UDP 监听（`--private-quic-bind`）
- Raw TCP：独立 TCP 监听（`--private-tcp-bind`）
- WSS：复用 HTTP 入口，通过 `/private/ws` 升级，要求 subprotocol 为 `pushgo-private.v1`
- MQTT 5：独立 TCP 监听（`--mqtt-bind`），仅支持 QoS 1

### 2) 参数依赖关系

- `--private-transports` 是私有传输总开关，支持 `true/false` 与显式集合（例如 `quic,tcp,wss,mqtt`）。
- 私有传输不做隐式回退：只有 `--private-transports` 显式列出的传输会启用。
- `--private-*-bind` 一律表示 gateway 本机监听地址。
- `--private-*-port` 一律表示通过 `/gateway/profile`（`transport` 提示）对 app 下发的对外端口。
- 启用 `quic` 时，必须配置 `--private-tls-cert` + `--private-tls-key`。
- Raw TCP 默认明文监听。只有需要 gateway 自己终止 TLS 时，才设置 `--private-tcp-tls-enabled=true`。
- WSS 没有单独 bind 参数，始终复用 `--http-addr` 对应的 HTTP 入口。
- MQTT 默认明文监听。只有需要 gateway 自己终止 MQTT/TLS 时，才设置 `--mqtt-tls-enabled=true`。
- MQTT 仅接受 MQTT 5 和 QoS 1。CONNECT 必须携带 MQTT 5 User Property `device_type=publish` 或 `device_type=subscribe`。
- `device_type=publish` 是连接级临时发送设备，不注册入库且不能订阅；publish-only 连接即使传入 client id 也会被忽略。`device_type=subscribe` 是持久 MQTT 设备，可使用已有 `client_id=<device_key>`，也可以留空 `client_id`。如果 subscribe 连接传入的 client id 为空、未知，或者因为属于其他 platform 而被替换，gateway 会分配新的 device key，并通过 MQTT 5 CONNACK Assigned Client Identifier 返回；客户端必须保存这个返回值，并在下次连接时作为 `client_id` 使用。
- MQTT 不提供 broker 风格的 session 持久化：CONNACK 会声明 `session_expiry_interval=0`，不支持 retained message、topic alias、subscription identifier、通配符订阅或 shared subscription。PushGo 频道订阅由 gateway 持久化，独立于当前 TCP 连接生命周期。
- MQTT topic 直接使用原始 `{channel_id}`。频道密码通过 MQTT 5 User Property `pushgo-password` 传递；配置了 gateway token 时，token 通过 MQTT username 传递。每个 SUBSCRIBE packet 只允许包含一个 topic filter。
- MQTT payload 使用 envelope：publish 为 `{"type":"message","data":{...}}`，下行为 `{"schema":"pushgo.mqtt.delivery.v1","type":"message","delivery_id":"...","channel_id":"...","data":{...}}`。Topic 表示频道路由，payload `type` 表示业务模型。当前 MQTT 上行和下行只支持 `message`。MQTT publish 的 message data 允许携带 `thing_id` 通过共享发送路径创建 thing-scoped message，但 MQTT 下行只投递频道级 message；event、thing、thing 下的二级 message 和 thing 下的二级 event 都不会进入 MQTT 设备 outbox。
- MQTT 遗嘱消息只允许 `device_type=subscribe` 设备设置。Will Topic 直接使用 `{channel_id}`，可发送到任意频道；Will QoS 必须为 1，Will Retain 必须为 false；Will Properties 必须携带 User Property `pushgo-password`；Will payload 使用同一套 publish envelope。Gateway 在 CONNECT 阶段校验遗嘱，在异常断开或 MQTT 5 `DisconnectWithWillMessage` 时发送，正常 DISCONNECT 不发送。

## MCP 运行模型

- `--mcp-enabled=true` 后，会在同一个 HTTP 监听器上挂载 `/mcp`、`/oauth/*` 与 `/.well-known/*`。
- 容器部署或反向代理部署时，建议显式设置 `--public-base-url`，让 OAuth issuer、绑定页面 URL、WSS 对外提示都指向真实可访问的 HTTPS 域名。
- `--mcp-predefined-clients` 使用 `client_id:client_secret` 格式，多个条目之间用分号或换行分隔。
- 如果不传 `--public-base-url`，gateway 会尽量从入站 HTTPS Origin 推导 issuer；固定公网部署仍建议显式配置。

## CLI 参数

主参数同时支持 CLI 与环境变量两种方式。  
仅环境变量可配置的高级运行时参数，见后续“高级环境变量（仅 env）”章节。

### Core

| CLI Flag                          | Env                                    | 默认值                     | 必填     | 说明                                                 |
| --------------------------------- | -------------------------------------- | -------------------------- | -------- | ---------------------------------------------------- |
| `--http-addr`                     | `PUSHGO_HTTP_ADDR`                     | `127.0.0.1:6666`           | 否       | HTTP API / WSS 监听地址                              |
| `--token`                         | `PUSHGO_TOKEN`                         | 无                         | 否       | 公共 API 鉴权 token（优先 `Authorization: Bearer <token>`；仅当 Authorization 缺失时回退 `?token=<token>`） |
| `--sandbox-mode`                  | `PUSHGO_SANDBOX_MODE`                  | `false`                    | 否       | 沙盒模式（含 APNS sandbox）                          |
| `--token-service-url`             | `PUSHGO_TOKEN_SERVICE_URL`             | `https://token.pushgo.dev` | 否       | token-service 地址（建议显式设置）                   |
| `--private-transports`            | `PUSHGO_PRIVATE_TRANSPORTS`            | `false`                    | 否       | 私有传输开关（`true/false` 或 `quic,tcp,wss,mqtt`） |
| `--runtime-profile`               | `PUSHGO_RUNTIME_PROFILE`               | `small`                    | 否       | 资源/性能档位（`small`/`public`）；不会改变 `--db-url` 选择的数据库驱动 |
| `--observability-profile`         | `PUSHGO_OBSERVABILITY_PROFILE`         | `prod_min`                 | 否       | 可观测矩阵档位（`prod_min`/`ops`/`incident`/`debug`） |
| `--observability-log-level`       | `PUSHGO_OBSERVABILITY_LOG_LEVEL`       | `warn`                     | 否       | 原生 tracing 日志级别（`off`/`error`/`warn`/`info`/`debug`/`trace`） |
| `--db-url`                        | `PUSHGO_DB_URL`                        | 无                         | 是       | 数据库 URL（`sqlite://`、`postgres://`、`postgresql://`、`pg://`、`mysql://`） |
| `--public-base-url`               | `PUSHGO_PUBLIC_BASE_URL`               | 无                         | 否       | MCP/OAuth issuer URL 与 WSS 对外提示使用的外部 HTTPS 基准地址 |

### Private 监听 / 对外宣告

| CLI Flag                    | Env                         | 默认值           | 必填 | 说明                             |
| --------------------------- | --------------------------- | ---------------- | ---- | -------------------------------- |
| `--private-quic-bind`       | `PUSHGO_PRIVATE_QUIC_BIND`  | `127.0.0.1:5223` | 否   | QUIC 本机监听地址（UDP）         |
| `--private-quic-port`       | `PUSHGO_PRIVATE_QUIC_PORT`  | `5223`           | 否   | 对 app 下发的 QUIC 端口          |
| `--private-tcp-bind`        | `PUSHGO_PRIVATE_TCP_BIND`   | `127.0.0.1:5223` | 否   | Raw TCP 本机监听地址             |
| `--private-tcp-port`        | `PUSHGO_PRIVATE_TCP_PORT`   | `5223`           | 否   | 对 app 下发的 TCP 端口           |
| `--mqtt-bind`               | `PUSHGO_MQTT_BIND`          | `127.0.0.1:1883` | 否   | MQTT 5 本机监听地址              |
| `--mqtt-port`               | `PUSHGO_MQTT_PORT`          | `1883`           | 否   | 对 app 下发的 MQTT 端口          |
| `--mqtt-tls-enabled`        | `PUSHGO_MQTT_TLS_ENABLED`   | `false`          | 否   | gateway 终止 MQTT/TLS，而不是接收明文 MQTT |
| `--mqtt-max-packet-bytes`   | `PUSHGO_MQTT_MAX_PACKET_BYTES` | `32768`       | 否   | gateway 接受的最大 MQTT packet 大小 |

### Private TLS

| CLI Flag                    | Env                              | 默认值 | 必填     | 说明                                       |
| --------------------------- | -------------------------------- | ------ | -------- | ------------------------------------------ |
| `--private-tls-cert`        | `PUSHGO_PRIVATE_TLS_CERT`        | 无     | 条件必填 | `quic` 必需；`tcp` 在 `private-tcp-tls-enabled=true` 时必需；`mqtt` 在 `mqtt-tls-enabled=true` 时必需 |
| `--private-tls-key`         | `PUSHGO_PRIVATE_TLS_KEY`         | 无     | 条件必填 | `quic` 必需；`tcp` 在 `private-tcp-tls-enabled=true` 时必需；`mqtt` 在 `mqtt-tls-enabled=true` 时必需 |
| `--private-tcp-tls-enabled` | `PUSHGO_PRIVATE_TCP_TLS_ENABLED` | `false` | 否       | gateway 终止 Raw TCP TLS，而不是接收明文 TCP |
| `--private-tcp-proxy-protocol` | `PUSHGO_PRIVATE_TCP_PROXY_PROTOCOL` | `false` | 否   | Raw TCP 入站是否要求 PROXY protocol v1    |

### Runtime Profiles

细粒度性能/资源旋钮现在是内部 profile 默认值，不再作为公共 CLI/env 参数暴露。

| Profile | 适用部署 | 关键默认值 |
| ------- | -------- | ---------- |
| `small` | 极小规模私有 SQLite 部署 | 更低 SQLite/cache/队列占用，stats 10 秒刷盘，空闲时不采样 gateway 指标，maintenance 5 分钟 tick，provider 并发 32/32/16 |
| `public` | 大规模外部 DB 网关，主要是 PostgreSQL | 更大的 dispatch/stats 队列，stats 2 秒刷盘，采样 gateway 指标，外部 DB pool max 64/min 4，provider 并发 128/256/128 |

数据库驱动始终由 `--db-url` 决定；设置 `--runtime-profile=public` 加 SQLite URL 仍然使用 SQLite，设置 `--runtime-profile=small` 加 PostgreSQL URL 仍然使用 PostgreSQL。不传时默认使用 `small`。

### MCP / OAuth

| CLI Flag                                | Env                                           | 默认值      | 必填 | 说明                                                   |
| --------------------------------------- | --------------------------------------------- | ----------- | ---- | ------------------------------------------------------ |
| `--mcp-enabled`                         | `PUSHGO_MCP_ENABLED`                          | `false`     | 否   | 开启 MCP HTTP 入口（`/mcp`）及相关 OAuth / 绑定路由   |
| `--mcp-dcr-enabled`                     | `PUSHGO_MCP_DCR_ENABLED`                      | `true`      | 否   | 是否开启 OAuth Dynamic Client Registration            |
| `--mcp-predefined-clients`              | `PUSHGO_MCP_PREDEFINED_CLIENTS`               | 无          | 否   | 预置 OAuth 客户端，格式为 `client_id:client_secret`，用 `;` 或换行分隔 |

### 高级环境变量（仅 env）

| Env                                         | 默认值                                 | 说明                                                                      |
| ------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------- |
| `PUSHGO_OBSERVABILITY_LOG_LEVEL`              | `warn`                             | 可选覆盖原生 tracing 日志级别                                             |
| `RUST_LOG`                                    | 无                                 | 可选覆盖完整 EnvFilter 指令（优先级高于 profile/level）                   |

### 运营统计（入库）

这里的 `stats` 定位为运营统计支撑（不是纯业务统计）。  
除现有 channel/device/gateway 聚合外，gateway 还会把运营向小时计数写入 `ops_stats_hourly`（`bucket_hour`、`metric_key`、`metric_value`），例如 provider 发送失败、HTTP 5xx、invalid-token 清理失败等指标。

### Trace 事件输出

gateway 已统一为一条原生 `tracing` 链路（span + event）。
默认输出级别为 `warn`；可通过 `--observability-log-level`（或 `PUSHGO_OBSERVABILITY_LOG_LEVEL`）调节，若需要完整路由规则可使用 `RUST_LOG` 覆盖。
每条事件固定包含 `ts_ms`、`component`、`event`，并附带白名单字段。
可能涉及敏感标识的字段会走脱敏输出。

示例：

```json
{"ts_ms":1713750000000,"component":"gateway","event":"dispatch.provider_send_failed","provider":"fcm","status_code":503,"invalid_token":false}
```

## Nginx / LB 部署参考

### A) HTTP API + WSS（`/private/ws`）

```nginx
server {
    listen 443 ssl http2;
    server_name gateway.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "for=$remote_addr;proto=$scheme;host=$host";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://127.0.0.1:6666;
    }
}
```

### B) Raw TCP（stream）

默认明文 Raw TCP：

```nginx
stream {
    upstream pushgo_private_tcp_plain {
        server 127.0.0.1:5223;
    }

    server {
        listen 5223;
        proxy_pass pushgo_private_tcp_plain;
        proxy_protocol on;
        proxy_connect_timeout 3s;
        proxy_timeout 600s;
    }
}
```

网关终止 TLS（`--private-tcp-tls-enabled=true`）：

```nginx
stream {
    upstream pushgo_private_tcp_tls {
        server 127.0.0.1:55223;
    }

    server {
        listen 5223;
        proxy_pass pushgo_private_tcp_tls;
        proxy_protocol on;
        proxy_connect_timeout 3s;
        proxy_timeout 600s;
    }
}
```

### C) QUIC（UDP）

```nginx
stream {
    upstream pushgo_quic_udp {
        server 127.0.0.1:5223;
    }

    server {
        listen 5223 udp;
        proxy_pass pushgo_quic_udp;
        proxy_timeout 600s;
    }
}
```

### D) MQTT 5（stream）

默认明文 MQTT：

```nginx
stream {
    upstream pushgo_mqtt_plain {
        server 127.0.0.1:1883;
    }

    server {
        listen 8883 ssl;
        ssl_certificate     /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        proxy_pass pushgo_mqtt_plain;
        proxy_connect_timeout 3s;
        proxy_timeout 600s;
    }
}
```

MQTT 客户端必须使用 MQTT 5 和 QoS 1。CONNECT 必须携带 User Property `device_type=publish` 表示临时只发送设备，或 `device_type=subscribe` 表示可订阅接收的持久设备。Publish-only 连接的 client id 会被忽略且不会持久化。Subscribe 设备可传 `client_id=<device_key>`，也可传空 `client_id`；当 client id 为空、未知，或因为属于其他 platform 而被替换时，gateway 会通过 CONNACK Assigned Client Identifier 返回新分配的 device key，客户端必须将其保存为下次连接使用的 client id。SUBSCRIBE/PUBLISH 使用 topic `{channel_id}`，并通过 MQTT 5 User Property `pushgo-password=<channel password>` 传递频道密码。MQTT publish payload 为 `{"type":"message","data":{...}}`，`data` 可携带 `thing_id` 创建 thing-scoped message，且与 HTTP 发送入口复用同一套校验，例如按需要求 `occurred_at`。MQTT 下行 payload 为 `{"schema":"pushgo.mqtt.delivery.v1","type":"message","delivery_id":"...","channel_id":"...","data":{...}}`，且只接收频道级 message；event、thing、thing 下的二级 message 和 thing 下的二级 event 会在进入 MQTT outbox 前被跳过。每个 SUBSCRIBE packet 只允许包含一个 topic filter。Gateway 不提供 MQTT broker session 持久化、retained message、topic alias、subscription identifier、通配符订阅或 shared subscription；PushGo 频道订阅才是持久订阅状态。MQTT 遗嘱消息只允许 `device_type=subscribe` 设备设置；Will Topic 为 `{channel_id}` 且可发送到任意频道，Will QoS 必须为 1，Will Retain 必须为 false，Will Properties 必须携带 User Property `pushgo-password`，Will payload 使用同一套 publish envelope。Gateway 会在异常断开或 MQTT 5 `DisconnectWithWillMessage` 时发送遗嘱，正常 DISCONNECT 不发送。`--mqtt-tls-enabled=false` 时客户端以明文 MQTT 连接 gateway；设置为 `true` 时客户端直接以 MQTT/TLS 连接 gateway。

### E) `443/udp` 冲突说明（关键）

PushGo QUIC 使用自定义 ALPN（`pushgo-quic`），不是 HTTP/3。  
如果同一 Nginx 实例已经在 `443/udp` 提供 HTTP/3，则私有 QUIC 不能复用同一个 UDP socket。

推荐方案：

1. 私有 QUIC 使用独立 UDP 端口（例如 `5223/udp`），HTTP/3 保持在 `443/udp`。
2. 为私有 QUIC 配置独立 LB/独立公网 IP（可继续对外暴露 `443/udp`）。

PushGo 现在默认把私有 QUIC / Raw TCP 都监听在本机回环地址 `127.0.0.1:5223`，并通过 `/gateway/profile` 将客户端应使用的对外端口单独下发。

## 安装与运行

### 方式一：二进制运行（Release 下载或源码编译）

下载预编译二进制（示例）：

```bash
curl -fL -o pushgo-gateway \
  https://github.com/<owner>/<repo>/releases/download/<tag>/pushgo-gateway-amd64-musl
chmod +x pushgo-gateway
```

源码编译：

```bash
cargo build --release -p pushgo-gateway
./target/release/pushgo-gateway --db-url <DB_URL>
```

Linux 建议通过 systemd 托管：

```ini
[Unit]
Description=PushGo Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pushgo
Group=pushgo
WorkingDirectory=/opt/pushgo-gateway
ExecStart=/opt/pushgo-gateway/pushgo-gateway \
  --http-addr 0.0.0.0:6666 \
  --private-transports quic,tcp,wss \
  --private-quic-bind 127.0.0.1:5223 \
  --private-quic-port 443 \
  --private-tcp-bind 127.0.0.1:5223 \
  --private-tcp-port 5223 \
  --db-url ${PUSHGO_DB_URL} \
  --token-service-url https://token.pushgo.dev

Environment=PUSHGO_DB_URL=postgres://user:pass@127.0.0.1:5432/pushgo
Environment=PUSHGO_PRIVATE_TLS_CERT=/etc/pushgo/certs/fullchain.pem
Environment=PUSHGO_PRIVATE_TLS_KEY=/etc/pushgo/certs/privkey.pem
Environment=PUSHGO_TOKEN=<gateway-bearer-token>

Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### 方式二：Docker 运行

Docker 镜像文件说明：

- `Dockerfile.gha`：用于 Release/GitHub Actions，基于预编译 `dist/*-gnu` 二进制组装镜像。
- `Dockerfile.local`：用于本地开发机，直接从源码多阶段构建镜像。

已发布镜像（例如 `ghcr.io/<owner>/pushgo-gateway:latest`）由 `Dockerfile.gha` 产出。

本地源码构建示例：

```bash
docker build -f Dockerfile.local -t pushgo-gateway:local .
```

镜像默认暴露端口：

- `6666/tcp`：HTTP API + WSS
- `5223/tcp`：Raw TCP
- `5223/udp`：QUIC
- `1883/tcp` 或边缘 `8883/tcp`：MQTT 5

MCP/OAuth 路由（`/mcp`、`/oauth/*`、`/.well-known/*`）同样复用 `6666/tcp`，不需要额外容器端口。

示例：

```bash
docker run -d --name pushgo-gateway \
  -p 6666:6666 \
  -p 5223:5223/tcp \
  -p 5223:5223/udp \
  -e PUSHGO_HTTP_ADDR=0.0.0.0:6666 \
  -e PUSHGO_DB_URL='postgres://user:pass@db:5432/pushgo' \
  -e PUSHGO_TOKEN_SERVICE_URL='https://token.pushgo.dev' \
  -e PUSHGO_PRIVATE_TRANSPORTS=quic,tcp,wss \
  -e PUSHGO_MCP_ENABLED=true \
  -e PUSHGO_PUBLIC_BASE_URL='https://gateway.example.com' \
  -e PUSHGO_MCP_PREDEFINED_CLIENTS='chatgpt-prod:replace-me' \
  -e PUSHGO_PRIVATE_QUIC_BIND=0.0.0.0:5223 \
  -e PUSHGO_PRIVATE_QUIC_PORT=443 \
  -e PUSHGO_PRIVATE_TCP_BIND=0.0.0.0:5223 \
  -e PUSHGO_PRIVATE_TCP_PORT=5223 \
  -e PUSHGO_PRIVATE_TLS_CERT=/certs/fullchain.pem \
  -e PUSHGO_PRIVATE_TLS_KEY=/certs/privkey.pem \
  -v /etc/pushgo/certs:/certs:ro \
  ghcr.io/<owner>/pushgo-gateway:latest
```

如果使用 Dynamic Client Registration，可以不传 `PUSHGO_MCP_PREDEFINED_CLIENTS`。如果是固定客户端，建议把 `PUSHGO_PUBLIC_BASE_URL` 设为反向代理或 LB 对外暴露的 HTTPS 域名。

## 生产建议

1. 建议同时启用 QUIC + Raw TCP，并保留 WSS 作为受限网络下的兼容路径。
2. 建议本机私有监听保持 loopback，仅由边缘层对外暴露。
3. 私有 QUIC 与 HTTP/3 请分离 `443/udp` 归属，避免端口冲突。
