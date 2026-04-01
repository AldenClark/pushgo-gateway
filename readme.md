# PushGo Gateway

`pushgo-gateway` is the gateway service for PushGo, with three core capability groups:

- Public API: HTTP endpoints for devices, channels, messages, and events
- Private transport: real-time delivery over QUIC / Raw TCP / WSS
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

### 2) Parameter dependency map

- `--private-channel-enabled=true` is the master switch. If disabled, private routes/runtime are unavailable.
- `--private-*-bind` always means the local listener address owned by gateway.
- `--private-*-port` always means the port advertised to app clients via `/gateway/profile` (`transport` hints).
- QUIC and gateway-terminated Raw TCP both require `--private-tls-cert` + `--private-tls-key`.
- `--private-tcp-tls-offload=true` only changes Raw TCP; QUIC still needs gateway-side TLS materials.
- WSS has no separate bind flag; it rides on `--http-addr` and is typically exposed by edge TLS.

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
| `--private-channel-enabled`       | `PUSHGO_PRIVATE_CHANNEL_ENABLED`       | `false`                    | No                | Master switch for private transport                    |
| `--diagnostics-api-enabled`       | `PUSHGO_DIAGNOSTICS_API_ENABLED`       | `false`                    | No                | Enable `/diagnostics/*` namespace and diagnostics logs |
| `--db-url`                        | `PUSHGO_DB_URL`                        | None                       | Yes               | Database URL (`sqlite://`, `postgres://`, `postgresql://`, `pg://`, `mysql://`) |
| `--public-base-url`               | `PUSHGO_PUBLIC_BASE_URL`               | None                       | No                | External HTTPS base URL used for MCP/OAuth issuer URLs and advertised WSS URL |

### Private Transport Bind / Advertise

| CLI Flag                    | Env                         | Default          | Required | Description                              |
| --------------------------- | --------------------------- | ---------------- | -------- | ---------------------------------------- |
| `--private-quic-bind`       | `PUSHGO_PRIVATE_QUIC_BIND`  | `127.0.0.1:5223` | No       | Local QUIC listener bind address (UDP)   |
| `--private-quic-port`       | `PUSHGO_PRIVATE_QUIC_PORT`  | `5223`           | No       | QUIC port advertised to app clients      |
| `--private-tcp-bind`        | `PUSHGO_PRIVATE_TCP_BIND`   | `127.0.0.1:5223` | No       | Local Raw TCP listener bind address      |
| `--private-tcp-port`        | `PUSHGO_PRIVATE_TCP_PORT`   | `5223`           | No       | TCP port advertised to app clients       |

### Private TLS / Edge Offload

| CLI Flag                    | Env                              | Default | Required          | Description                                         |
| --------------------------- | -------------------------------- | ------- | ----------------- | --------------------------------------------------- |
| `--private-tls-cert`        | `PUSHGO_PRIVATE_TLS_CERT`        | None    | Conditionally yes | Shared TLS cert PEM for QUIC and Raw TCP            |
| `--private-tls-key`         | `PUSHGO_PRIVATE_TLS_KEY`         | None    | Conditionally yes | Shared TLS key PEM for QUIC and Raw TCP             |
| `--private-tcp-tls-offload` | `PUSHGO_PRIVATE_TCP_TLS_OFFLOAD` | `false` | No                | Whether Raw TCP TLS is offloaded at the edge proxy  |
| `--private-tcp-proxy-protocol` | `PUSHGO_PRIVATE_TCP_PROXY_PROTOCOL` | `false` | No            | Expect PROXY protocol v1 on Raw TCP ingress          |

### Private Runtime Limits

| CLI Flag                          | Env                                    | Default                    | Required | Description                                       |
| --------------------------------- | -------------------------------------- | -------------------------- | -------- | ------------------------------------------------- |
| `--private-session-ttl`           | `PUSHGO_PRIVATE_SESSION_TTL`           | `3600`                     | No                | Private session TTL in seconds                         |
| `--private-grace-window`          | `PUSHGO_PRIVATE_GRACE_WINDOW`          | `60`                       | No                | Grace window for connection transition in seconds      |
| `--private-max-pending`           | `PUSHGO_PRIVATE_MAX_PENDING`           | `200`                      | No                | Max pending messages per device                        |
| `--private-pull-limit`            | `PUSHGO_PRIVATE_PULL_LIMIT`            | `200`                      | No                | Max items per pull request                             |
| `--private-ack-timeout`           | `PUSHGO_PRIVATE_ACK_TIMEOUT`           | `15`                       | No                | ACK scheduling timeout parameter                       |
| `--private-fallback-max-attempts` | `PUSHGO_PRIVATE_FALLBACK_MAX_ATTEMPTS` | `5`                        | No                | Max retry attempts for private queue scheduling        |
| `--private-fallback-max-backoff`  | `PUSHGO_PRIVATE_FALLBACK_MAX_BACKOFF`  | `300`                      | No                | Max backoff for private queue scheduling (seconds)     |
| `--private-retx-window-secs`      | `PUSHGO_PRIVATE_RETX_WINDOW_SECS`      | `10`                       | No                | Retransmission budget window (seconds)                 |
| `--private-retx-max-per-window`   | `PUSHGO_PRIVATE_RETX_MAX_PER_WINDOW`   | `128`                      | No                | Max retransmission frames per window                   |
| `--private-retx-max-per-tick`     | `PUSHGO_PRIVATE_RETX_MAX_PER_TICK`     | `16`                       | No                | Max retransmission frames per tick                     |
| `--private-retx-max-retries`      | `PUSHGO_PRIVATE_RETX_MAX_RETRIES`      | `5`                        | No                | Max retries per delivery                               |
| `--private-global-max-pending`    | `PUSHGO_PRIVATE_GLOBAL_MAX_PENDING`    | `5000000`                  | No                | Global pending cap for private queue                   |
| `--private-hot-cache-capacity`    | `PUSHGO_PRIVATE_HOT_CACHE_CAPACITY`    | `50000`                    | No                | Hot-cache capacity for private payloads                |
| `--private-default-ttl`           | `PUSHGO_PRIVATE_DEFAULT_TTL`           | `2592000`                  | No                | Default TTL for private messages (seconds)             |

### MCP / OAuth

| CLI Flag                                  | Env                                             | Default     | Required | Description                                                            |
| ----------------------------------------- | ----------------------------------------------- | ----------- | -------- | ---------------------------------------------------------------------- |
| `--mcp-enabled`                           | `PUSHGO_MCP_ENABLED`                            | `false`     | No       | Enable MCP HTTP endpoint (`/mcp`) and related OAuth / bind routes      |
| `--mcp-access-token-ttl-secs`             | `PUSHGO_MCP_ACCESS_TOKEN_TTL_SECS`              | `900`       | No       | MCP OAuth access token TTL in seconds                                  |
| `--mcp-refresh-token-absolute-ttl-secs`   | `PUSHGO_MCP_REFRESH_TOKEN_ABSOLUTE_TTL_SECS`    | `2592000`   | No       | MCP OAuth refresh token absolute TTL in seconds                        |
| `--mcp-refresh-token-idle-ttl-secs`       | `PUSHGO_MCP_REFRESH_TOKEN_IDLE_TTL_SECS`        | `604800`    | No       | MCP OAuth refresh token idle TTL in seconds                            |
| `--mcp-bind-session-ttl-secs`             | `PUSHGO_MCP_BIND_SESSION_TTL_SECS`              | `600`       | No       | MCP channel-bind page session TTL in seconds                           |
| `--mcp-dcr-enabled`                       | `PUSHGO_MCP_DCR_ENABLED`                        | `true`      | No       | Enable OAuth Dynamic Client Registration                               |
| `--mcp-predefined-clients`                | `PUSHGO_MCP_PREDEFINED_CLIENTS`                 | None        | No       | Predefined OAuth clients as `client_id:client_secret` joined by `;` or newlines |

### Advanced Environment Variables (env-only)

| Env                                         | Default                                | Description                                                                 |
| ------------------------------------------- | -------------------------------------- | --------------------------------------------------------------------------- |
| `PUSHGO_DISPATCH_WORKER_COUNT`              | Auto                                   | Dispatch worker count (clamped 2~256; auto is `cpu*2`, clamped 4~64)       |
| `PUSHGO_DISPATCH_QUEUE_CAPACITY`            | Auto                                   | Dispatch queue capacity (clamped 256~131072; auto is `workers*64`)          |
| `PUSHGO_PROVIDER_PULL_RETRY_POLL_MS`        | `1000`                                 | Provider-pull retry poll interval in milliseconds (200~5000)                |
| `PUSHGO_PROVIDER_PULL_RETRY_BATCH`          | `200`                                  | Provider-pull retry batch size (1~2000)                                     |
| `PUSHGO_PROVIDER_PULL_RETRY_TIMEOUT_SECS`   | `30`                                   | Provider-pull retry dispatch timeout in seconds (5~600)                     |
| `PUSHGO_DELIVERY_AUDIT_CHANNEL_CAPACITY`    | `16384`                                | Delivery-audit async queue capacity (512~262144)                            |
| `PUSHGO_DELIVERY_AUDIT_BATCH_SIZE`          | `256`                                  | Delivery-audit batch flush size (16~4096)                                   |
| `PUSHGO_DELIVERY_AUDIT_FLUSH_INTERVAL_MS`   | `50`                                   | Delivery-audit periodic flush interval in milliseconds (10~2000)            |
| `PUSHGO_APNS_MAX_IN_FLIGHT`                 | `100`                                  | In-process APNS max concurrent sends                                        |
| `PUSHGO_DISPATCH_TARGETS_CACHE_TTL_MS`      | `2000`                                 | Dispatch-target cache TTL in milliseconds (200~10000)                       |

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

Gateway-terminated TLS (`--private-tcp-tls-offload=false`):

```nginx
stream {
    upstream pushgo_private_tcp_tls {
        server 127.0.0.1:5223;
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

Edge-terminated TLS (`--private-tcp-tls-offload=true`):

```nginx
stream {
    upstream pushgo_private_tcp_plain {
        server 127.0.0.1:55223;
    }

    server {
        listen 5223 ssl;
        ssl_certificate     /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        proxy_pass pushgo_private_tcp_plain;
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

### D) Critical note on `443/udp` conflicts

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
  --private-channel-enabled \
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
  -e PUSHGO_PRIVATE_CHANNEL_ENABLED=true \
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
- 私有传输层：基于 QUIC / Raw TCP / WSS 的实时收发
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

### 2) 参数依赖关系

- `--private-channel-enabled=true` 是私有传输总开关；关闭时，私有路由与运行时均不可用。
- `--private-*-bind` 一律表示 gateway 本机监听地址。
- `--private-*-port` 一律表示通过 `/gateway/profile`（`transport` 提示）对 app 下发的对外端口。
- QUIC 与网关终止 TLS 的 Raw TCP 共享 `--private-tls-cert` + `--private-tls-key`。
- `--private-tcp-tls-offload=true` 只影响 Raw TCP；QUIC 仍然需要 gateway 侧 TLS 材料。
- WSS 没有单独 bind 参数，始终复用 `--http-addr` 对应的 HTTP 入口。

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
| `--private-channel-enabled`       | `PUSHGO_PRIVATE_CHANNEL_ENABLED`       | `false`                    | 否       | 私有传输总开关                                       |
| `--diagnostics-api-enabled`       | `PUSHGO_DIAGNOSTICS_API_ENABLED`       | `false`                    | 否       | 开启 `/diagnostics/*` 诊断接口与诊断日志             |
| `--db-url`                        | `PUSHGO_DB_URL`                        | 无                         | 是       | 数据库 URL（`sqlite://`、`postgres://`、`postgresql://`、`pg://`、`mysql://`） |
| `--public-base-url`               | `PUSHGO_PUBLIC_BASE_URL`               | 无                         | 否       | MCP/OAuth issuer URL 与 WSS 对外提示使用的外部 HTTPS 基准地址 |

### Private 监听 / 对外宣告

| CLI Flag                    | Env                         | 默认值           | 必填 | 说明                             |
| --------------------------- | --------------------------- | ---------------- | ---- | -------------------------------- |
| `--private-quic-bind`       | `PUSHGO_PRIVATE_QUIC_BIND`  | `127.0.0.1:5223` | 否   | QUIC 本机监听地址（UDP）         |
| `--private-quic-port`       | `PUSHGO_PRIVATE_QUIC_PORT`  | `5223`           | 否   | 对 app 下发的 QUIC 端口          |
| `--private-tcp-bind`        | `PUSHGO_PRIVATE_TCP_BIND`   | `127.0.0.1:5223` | 否   | Raw TCP 本机监听地址             |
| `--private-tcp-port`        | `PUSHGO_PRIVATE_TCP_PORT`   | `5223`           | 否   | 对 app 下发的 TCP 端口           |

### Private TLS / Offload

| CLI Flag                    | Env                              | 默认值 | 必填     | 说明                                       |
| --------------------------- | -------------------------------- | ------ | -------- | ------------------------------------------ |
| `--private-tls-cert`        | `PUSHGO_PRIVATE_TLS_CERT`        | 无     | 条件必填 | QUIC 与 Raw TCP 共享证书 PEM               |
| `--private-tls-key`         | `PUSHGO_PRIVATE_TLS_KEY`         | 无     | 条件必填 | QUIC 与 Raw TCP 共享私钥 PEM               |
| `--private-tcp-tls-offload` | `PUSHGO_PRIVATE_TCP_TLS_OFFLOAD` | `false` | 否       | Raw TCP 是否由边缘代理卸载 TLS            |
| `--private-tcp-proxy-protocol` | `PUSHGO_PRIVATE_TCP_PROXY_PROTOCOL` | `false` | 否   | Raw TCP 入站是否要求 PROXY protocol v1    |

### Private Runtime Limits

| CLI Flag                          | Env                                    | 默认值                     | 必填 | 说明                                                 |
| --------------------------------- | -------------------------------------- | -------------------------- | ---- | ---------------------------------------------------- |
| `--private-session-ttl`           | `PUSHGO_PRIVATE_SESSION_TTL`           | `3600`                     | 否       | 私有会话 TTL（秒）                                   |
| `--private-grace-window`          | `PUSHGO_PRIVATE_GRACE_WINDOW`          | `60`                       | 否       | 连接切换宽限窗口（秒）                               |
| `--private-max-pending`           | `PUSHGO_PRIVATE_MAX_PENDING`           | `200`                      | 否       | 单设备最大待处理消息数                               |
| `--private-pull-limit`            | `PUSHGO_PRIVATE_PULL_LIMIT`            | `200`                      | 否       | 单次 pull 上限                                       |
| `--private-ack-timeout`           | `PUSHGO_PRIVATE_ACK_TIMEOUT`           | `15`                       | 否       | ACK 调度超时参数                                     |
| `--private-fallback-max-attempts` | `PUSHGO_PRIVATE_FALLBACK_MAX_ATTEMPTS` | `5`                        | 否       | 私有队列调度最大重试次数                             |
| `--private-fallback-max-backoff`  | `PUSHGO_PRIVATE_FALLBACK_MAX_BACKOFF`  | `300`                      | 否       | 私有队列调度最大退避（秒）                           |
| `--private-retx-window-secs`      | `PUSHGO_PRIVATE_RETX_WINDOW_SECS`      | `10`                       | 否       | 重传预算窗口（秒）                                   |
| `--private-retx-max-per-window`   | `PUSHGO_PRIVATE_RETX_MAX_PER_WINDOW`   | `128`                      | 否       | 窗口内最大重传帧数                                   |
| `--private-retx-max-per-tick`     | `PUSHGO_PRIVATE_RETX_MAX_PER_TICK`     | `16`                       | 否       | 单 tick 最大重传帧数                                 |
| `--private-retx-max-retries`      | `PUSHGO_PRIVATE_RETX_MAX_RETRIES`      | `5`                        | 否       | 单条消息最大重传次数                                 |
| `--private-global-max-pending`    | `PUSHGO_PRIVATE_GLOBAL_MAX_PENDING`    | `5000000`                  | 否       | 全局私有队列待处理上限                               |
| `--private-hot-cache-capacity`    | `PUSHGO_PRIVATE_HOT_CACHE_CAPACITY`    | `50000`                    | 否       | 私有热缓存容量                                       |
| `--private-default-ttl`           | `PUSHGO_PRIVATE_DEFAULT_TTL`           | `2592000`                  | 否       | 私有消息默认 TTL（秒）                               |

### MCP / OAuth

| CLI Flag                                | Env                                           | 默认值      | 必填 | 说明                                                   |
| --------------------------------------- | --------------------------------------------- | ----------- | ---- | ------------------------------------------------------ |
| `--mcp-enabled`                         | `PUSHGO_MCP_ENABLED`                          | `false`     | 否   | 开启 MCP HTTP 入口（`/mcp`）及相关 OAuth / 绑定路由   |
| `--mcp-access-token-ttl-secs`           | `PUSHGO_MCP_ACCESS_TOKEN_TTL_SECS`            | `900`       | 否   | MCP OAuth access token TTL（秒）                      |
| `--mcp-refresh-token-absolute-ttl-secs` | `PUSHGO_MCP_REFRESH_TOKEN_ABSOLUTE_TTL_SECS`  | `2592000`   | 否   | MCP OAuth refresh token 绝对 TTL（秒）                |
| `--mcp-refresh-token-idle-ttl-secs`     | `PUSHGO_MCP_REFRESH_TOKEN_IDLE_TTL_SECS`      | `604800`    | 否   | MCP OAuth refresh token 空闲 TTL（秒）                |
| `--mcp-bind-session-ttl-secs`           | `PUSHGO_MCP_BIND_SESSION_TTL_SECS`            | `600`       | 否   | MCP 频道绑定页面会话 TTL（秒）                        |
| `--mcp-dcr-enabled`                     | `PUSHGO_MCP_DCR_ENABLED`                      | `true`      | 否   | 是否开启 OAuth Dynamic Client Registration            |
| `--mcp-predefined-clients`              | `PUSHGO_MCP_PREDEFINED_CLIENTS`               | 无          | 否   | 预置 OAuth 客户端，格式为 `client_id:client_secret`，用 `;` 或换行分隔 |

### 高级环境变量（仅 env）

| Env                                         | 默认值                                 | 说明                                                                      |
| ------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------- |
| `PUSHGO_DISPATCH_WORKER_COUNT`              | 自动                                   | 分发 worker 数量（2~256；自动为 `cpu*2`，并限制在 4~64）                |
| `PUSHGO_DISPATCH_QUEUE_CAPACITY`            | 自动                                   | 分发队列容量（256~131072；自动为 `workers*64`）                          |
| `PUSHGO_PROVIDER_PULL_RETRY_POLL_MS`        | `1000`                                 | provider-pull 重试轮询间隔（毫秒，200~5000）                             |
| `PUSHGO_PROVIDER_PULL_RETRY_BATCH`          | `200`                                  | provider-pull 单轮重试批量（1~2000）                                     |
| `PUSHGO_PROVIDER_PULL_RETRY_TIMEOUT_SECS`   | `30`                                   | provider-pull 重试下发超时（秒，5~600）                                  |
| `PUSHGO_DELIVERY_AUDIT_CHANNEL_CAPACITY`    | `16384`                                | delivery-audit 异步队列容量（512~262144）                                 |
| `PUSHGO_DELIVERY_AUDIT_BATCH_SIZE`          | `256`                                  | delivery-audit 批量刷写条数（16~4096）                                    |
| `PUSHGO_DELIVERY_AUDIT_FLUSH_INTERVAL_MS`   | `50`                                   | delivery-audit 定时刷写间隔（毫秒，10~2000）                              |
| `PUSHGO_APNS_MAX_IN_FLIGHT`                 | `100`                                  | 进程内 APNS 最大发送并发数                                                |
| `PUSHGO_DISPATCH_TARGETS_CACHE_TTL_MS`      | `2000`                                 | dispatch targets 缓存 TTL（毫秒，200~10000）                              |

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

网关终止 TLS（`--private-tcp-tls-offload=false`）：

```nginx
stream {
    upstream pushgo_private_tcp_tls {
        server 127.0.0.1:5223;
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

边缘代理终止 TLS（`--private-tcp-tls-offload=true`）：

```nginx
stream {
    upstream pushgo_private_tcp_plain {
        server 127.0.0.1:55223;
    }

    server {
        listen 5223 ssl;
        ssl_certificate     /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        proxy_pass pushgo_private_tcp_plain;
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

### D) `443/udp` 冲突说明（关键）

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
  --private-channel-enabled \
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
  -e PUSHGO_PRIVATE_CHANNEL_ENABLED=true \
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
