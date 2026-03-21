# PushGo Gateway

`pushgo-gateway` is the gateway service for PushGo, with two core capability groups:

- Public API: HTTP endpoints for devices, channels, messages, and events
- Private transport: real-time delivery over QUIC / Raw TCP / WSS

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

- QUIC: dedicated UDP listener (`--quic-addr`)
- Raw TCP: dedicated TCP listener (`--private-tcp-addr`)
- WSS: upgraded from HTTP at `/private/ws` with subprotocol `pushgo-private.v1`

### 2) Parameter dependency map

- `--private-channel-enabled=true`
- Master switch for private transport. If disabled, private routes/runtime are unavailable.
- QUIC requirements
- Enabling QUIC requires `--quic-addr` and also `--quic-cert` + `--quic-key`.
- Raw TCP with gateway TLS termination
- `--private-tcp-tls-offload=false` (default): TLS is terminated in gateway, so `--quic-cert` + `--quic-key` are required.
- Raw TCP with edge TLS offload
- `--private-tcp-tls-offload=true`: gateway listens in plain TCP mode and does not read cert/key; TLS is handled by Nginx/LB.
- WSS behavior
- No separate listener is required; WSS runs on `--http-addr` behind edge TLS.
- IP rate-limit switch
- `--enable-ip-rate-limit=true` enables IP-based controls for HTTP, WSS handshake, QUIC, and Raw TCP.

## Full CLI Reference

Every option supports both CLI flag and environment variable forms.

| CLI Flag                          | Env                                    | Default                      | Required          | Description                                            |
| --------------------------------- | -------------------------------------- | ---------------------------- | ----------------- | ------------------------------------------------------ |
| `--http-addr`                     | `PUSHGO_HTTP_ADDR`                     | `127.0.0.1:6666`             | No                | HTTP API / WSS bind address                            |
| `--token`                         | `PUSHGO_TOKEN`                         | None                         | No                | Bearer token for public API                            |
| `--enable-ip-rate-limit`          | `PUSHGO_ENABLE_IP_RATE_LIMIT`          | `false`                      | No                | Enable IP-based rate limiting                          |
| `--sandbox-mode`                  | `PUSHGO_SANDBOX_MODE`                  | `false`                      | No                | Sandbox mode (including APNS sandbox endpoint)         |
| `--token-service-url`             | `PUSHGO_TOKEN_SERVICE_URL`             | `https://gateway.pushgo.dev` | No                | token-service endpoint (recommended to set explicitly) |
| `--private-channel-enabled`       | `PUSHGO_PRIVATE_CHANNEL_ENABLED`       | `false`                      | No                | Master switch for private transport                    |
| `--db-url`                        | `PUSHGO_DB_URL`                        | None                         | Yes               | Database URL (`sqlite://`, `postgres://`, `mysql://`)  |
| `--quic-addr`                     | `PUSHGO_QUIC_ADDR`                     | None                         | Conditionally yes | QUIC bind address (UDP)                                |
| `--quic-cert`                     | `PUSHGO_QUIC_CERT`                     | None                         | Conditionally yes | TLS cert PEM for QUIC and Raw TCP (non-offload mode)   |
| `--quic-key`                      | `PUSHGO_QUIC_KEY`                      | None                         | Conditionally yes | TLS key PEM for QUIC and Raw TCP (non-offload mode)    |
| `--private-tcp-addr`              | `PUSHGO_PRIVATE_TCP_ADDR`              | `0.0.0.0:5223`               | No                | Raw TCP bind address                                   |
| `--private-tcp-tls-offload`       | `PUSHGO_PRIVATE_TCP_TLS_OFFLOAD`       | `false`                      | No                | Whether Raw TCP TLS is offloaded at edge proxy         |
| `--private-session-ttl`           | `PUSHGO_PRIVATE_SESSION_TTL`           | `3600`                       | No                | Private session TTL in seconds                         |
| `--private-grace-window`          | `PUSHGO_PRIVATE_GRACE_WINDOW`          | `60`                         | No                | Grace window for connection transition in seconds      |
| `--private-max-pending`           | `PUSHGO_PRIVATE_MAX_PENDING`           | `200`                        | No                | Max pending messages per device                        |
| `--private-pull-limit`            | `PUSHGO_PRIVATE_PULL_LIMIT`            | `200`                        | No                | Max items per pull request                             |
| `--private-ack-timeout`           | `PUSHGO_PRIVATE_ACK_TIMEOUT`           | `15`                         | No                | ACK scheduling timeout parameter                       |
| `--private-fallback-max-attempts` | `PUSHGO_PRIVATE_FALLBACK_MAX_ATTEMPTS` | `5`                          | No                | Max retry attempts for private queue scheduling        |
| `--private-fallback-max-backoff`  | `PUSHGO_PRIVATE_FALLBACK_MAX_BACKOFF`  | `300`                        | No                | Max backoff for private queue scheduling (seconds)     |
| `--private-retx-window-secs`      | `PUSHGO_PRIVATE_RETX_WINDOW_SECS`      | `10`                         | No                | Retransmission budget window (seconds)                 |
| `--private-retx-max-per-window`   | `PUSHGO_PRIVATE_RETX_MAX_PER_WINDOW`   | `128`                        | No                | Max retransmission frames per window                   |
| `--private-retx-max-per-tick`     | `PUSHGO_PRIVATE_RETX_MAX_PER_TICK`     | `16`                         | No                | Max retransmission frames per tick                     |
| `--private-retx-max-retries`      | `PUSHGO_PRIVATE_RETX_MAX_RETRIES`      | `5`                          | No                | Max retries per delivery                               |
| `--private-global-max-pending`    | `PUSHGO_PRIVATE_GLOBAL_MAX_PENDING`    | `5000000`                    | No                | Global pending cap for private queue                   |
| `--private-hot-cache-capacity`    | `PUSHGO_PRIVATE_HOT_CACHE_CAPACITY`    | `50000`                      | No                | Hot-cache capacity for private payloads                |
| `--private-default-ttl`           | `PUSHGO_PRIVATE_DEFAULT_TTL`           | `604800`                     | No                | Default TTL for private messages (seconds)             |

## Nginx / LB Deployment Reference

### A) HTTP API + WSS (`/private/ws`)

If `--enable-ip-rate-limit` is enabled, force-overwrite `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` at the edge.

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
  --quic-addr 0.0.0.0:5223 \
  --private-tcp-addr 0.0.0.0:5223 \
  --enable-ip-rate-limit \
  --db-url ${PUSHGO_DB_URL} \
  --token-service-url https://token.pushgo.dev

Environment=PUSHGO_DB_URL=postgres://user:pass@127.0.0.1:5432/pushgo
Environment=PUSHGO_QUIC_CERT=/etc/pushgo/certs/fullchain.pem
Environment=PUSHGO_QUIC_KEY=/etc/pushgo/certs/privkey.pem
Environment=PUSHGO_TOKEN=<gateway-bearer-token>

Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### Option 2: Run with Docker

The root `Dockerfile` exposes:

- `6666/tcp`: HTTP API + WSS
- `5223/tcp`: Raw TCP
- `5223/udp`: QUIC

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
  -e PUSHGO_ENABLE_IP_RATE_LIMIT=true \
  -e PUSHGO_QUIC_ADDR=0.0.0.0:5223 \
  -e PUSHGO_PRIVATE_TCP_ADDR=0.0.0.0:5223 \
  -e PUSHGO_QUIC_CERT=/certs/fullchain.pem \
  -e PUSHGO_QUIC_KEY=/certs/privkey.pem \
  -v /etc/pushgo/certs:/certs:ro \
  ghcr.io/<owner>/pushgo-gateway:latest
```

## Production Recommendations

1. Enable QUIC + Raw TCP together, and keep WSS as a compatibility path for restricted networks.
2. If IP rate limiting is enabled, ensure proxy headers are forcibly overwritten at the edge.
3. Plan private QUIC and HTTP/3 with separate `443/udp` ownership to avoid socket conflicts.

---

# PushGo Gateway（中文）

`pushgo-gateway` 是 PushGo 的网关服务，主要包含三类能力：

- 公共 API：设备、频道、消息、事件等 HTTP 接口
- 私有传输层：基于 QUIC / Raw TCP / WSS 的实时收发

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

- QUIC：独立 UDP 监听（`--quic-addr`）
- Raw TCP：独立 TCP 监听（`--private-tcp-addr`）
- WSS：复用 HTTP 入口，通过 `/private/ws` 升级，要求 subprotocol 为 `pushgo-private.v1`

### 2) 参数依赖关系

- `--private-channel-enabled=true`
- 私有传输总开关；关闭时，私有路由与运行时均不可用。
- QUIC 依赖
- 开启 QUIC 需要 `--quic-addr`，同时必须提供 `--quic-cert` + `--quic-key`。
- Raw TCP（网关终止 TLS）
- `--private-tcp-tls-offload=false`（默认）：TLS 在网关内终止，必须提供 `--quic-cert` + `--quic-key`。
- Raw TCP（边缘代理卸载 TLS）
- `--private-tcp-tls-offload=true`：网关侧为明文 TCP，不读取证书；证书由 Nginx/LB 处理。
- WSS 行为
- 无需单独监听端口，运行在 `--http-addr` 对应的 HTTP 入口，TLS 由边缘代理处理。
- IP 限流总开关
- `--enable-ip-rate-limit=true` 时，才会启用 HTTP、WSS 握手、QUIC、Raw TCP 的 IP 限流。

## CLI 参数（完整）

所有参数同时支持 CLI 与环境变量两种方式。

| CLI Flag                          | Env                                    | 默认值                       | 必填     | 说明                                                 |
| --------------------------------- | -------------------------------------- | ---------------------------- | -------- | ---------------------------------------------------- |
| `--http-addr`                     | `PUSHGO_HTTP_ADDR`                     | `127.0.0.1:6666`             | 否       | HTTP API / WSS 监听地址                              |
| `--token`                         | `PUSHGO_TOKEN`                         | 无                           | 否       | 公共 API Bearer Token                                |
| `--enable-ip-rate-limit`          | `PUSHGO_ENABLE_IP_RATE_LIMIT`          | `false`                      | 否       | 启用基于 IP 的限流                                   |
| `--sandbox-mode`                  | `PUSHGO_SANDBOX_MODE`                  | `false`                      | 否       | 沙盒模式（含 APNS sandbox）                          |
| `--token-service-url`             | `PUSHGO_TOKEN_SERVICE_URL`             | `https://gateway.pushgo.dev` | 否       | token-service 地址（建议显式设置）                   |
| `--private-channel-enabled`       | `PUSHGO_PRIVATE_CHANNEL_ENABLED`       | `false`                      | 否       | 私有传输总开关                                       |
| `--db-url`                        | `PUSHGO_DB_URL`                        | 无                           | 是       | 数据库 URL（`sqlite://`、`postgres://`、`mysql://`） |
| `--quic-addr`                     | `PUSHGO_QUIC_ADDR`                     | 无                           | 条件必填 | QUIC 监听地址（UDP）                                 |
| `--quic-cert`                     | `PUSHGO_QUIC_CERT`                     | 无                           | 条件必填 | QUIC 与 Raw TCP（非 offload）使用的证书 PEM          |
| `--quic-key`                      | `PUSHGO_QUIC_KEY`                      | 无                           | 条件必填 | QUIC 与 Raw TCP（非 offload）使用的私钥 PEM          |
| `--private-tcp-addr`              | `PUSHGO_PRIVATE_TCP_ADDR`              | `0.0.0.0:5223`               | 否       | Raw TCP 监听地址                                     |
| `--private-tcp-tls-offload`       | `PUSHGO_PRIVATE_TCP_TLS_OFFLOAD`       | `false`                      | 否       | Raw TCP 是否由边缘代理卸载 TLS                       |
| `--private-session-ttl`           | `PUSHGO_PRIVATE_SESSION_TTL`           | `3600`                       | 否       | 私有会话 TTL（秒）                                   |
| `--private-grace-window`          | `PUSHGO_PRIVATE_GRACE_WINDOW`          | `60`                         | 否       | 连接切换宽限窗口（秒）                               |
| `--private-max-pending`           | `PUSHGO_PRIVATE_MAX_PENDING`           | `200`                        | 否       | 单设备最大待处理消息数                               |
| `--private-pull-limit`            | `PUSHGO_PRIVATE_PULL_LIMIT`            | `200`                        | 否       | 单次 pull 上限                                       |
| `--private-ack-timeout`           | `PUSHGO_PRIVATE_ACK_TIMEOUT`           | `15`                         | 否       | ACK 调度超时参数                                     |
| `--private-fallback-max-attempts` | `PUSHGO_PRIVATE_FALLBACK_MAX_ATTEMPTS` | `5`                          | 否       | 私有队列调度最大重试次数                             |
| `--private-fallback-max-backoff`  | `PUSHGO_PRIVATE_FALLBACK_MAX_BACKOFF`  | `300`                        | 否       | 私有队列调度最大退避（秒）                           |
| `--private-retx-window-secs`      | `PUSHGO_PRIVATE_RETX_WINDOW_SECS`      | `10`                         | 否       | 重传预算窗口（秒）                                   |
| `--private-retx-max-per-window`   | `PUSHGO_PRIVATE_RETX_MAX_PER_WINDOW`   | `128`                        | 否       | 窗口内最大重传帧数                                   |
| `--private-retx-max-per-tick`     | `PUSHGO_PRIVATE_RETX_MAX_PER_TICK`     | `16`                         | 否       | 单 tick 最大重传帧数                                 |
| `--private-retx-max-retries`      | `PUSHGO_PRIVATE_RETX_MAX_RETRIES`      | `5`                          | 否       | 单条消息最大重传次数                                 |
| `--private-global-max-pending`    | `PUSHGO_PRIVATE_GLOBAL_MAX_PENDING`    | `5000000`                    | 否       | 全局私有队列待处理上限                               |
| `--private-hot-cache-capacity`    | `PUSHGO_PRIVATE_HOT_CACHE_CAPACITY`    | `50000`                      | 否       | 私有热缓存容量                                       |
| `--private-default-ttl`           | `PUSHGO_PRIVATE_DEFAULT_TTL`           | `604800`                     | 否       | 私有消息默认 TTL（秒）                               |

## Nginx / LB 部署参考

### A) HTTP API + WSS（`/private/ws`）

当启用 `--enable-ip-rate-limit` 时，建议在边缘强制覆盖 `X-Forwarded-For`、`X-Real-IP`、`Forwarded`。

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
  --quic-addr 0.0.0.0:5223 \
  --private-tcp-addr 0.0.0.0:5223 \
  --enable-ip-rate-limit \
  --db-url ${PUSHGO_DB_URL} \
  --token-service-url https://token.pushgo.dev

Environment=PUSHGO_DB_URL=postgres://user:pass@127.0.0.1:5432/pushgo
Environment=PUSHGO_QUIC_CERT=/etc/pushgo/certs/fullchain.pem
Environment=PUSHGO_QUIC_KEY=/etc/pushgo/certs/privkey.pem
Environment=PUSHGO_TOKEN=<gateway-bearer-token>

Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### 方式二：Docker 运行

根目录 `Dockerfile` 暴露端口：

- `6666/tcp`：HTTP API + WSS
- `5223/tcp`：Raw TCP
- `5223/udp`：QUIC

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
  -e PUSHGO_ENABLE_IP_RATE_LIMIT=true \
  -e PUSHGO_QUIC_ADDR=0.0.0.0:5223 \
  -e PUSHGO_PRIVATE_TCP_ADDR=0.0.0.0:5223 \
  -e PUSHGO_QUIC_CERT=/certs/fullchain.pem \
  -e PUSHGO_QUIC_KEY=/certs/privkey.pem \
  -v /etc/pushgo/certs:/certs:ro \
  ghcr.io/<owner>/pushgo-gateway:latest
```

## 生产建议

1. 建议同时启用 QUIC + Raw TCP，并保留 WSS 作为受限网络下的兼容路径。
2. 若启用 IP 限流，请确保边缘代理强制覆盖 IP 相关头部。
3. 私有 QUIC 与 HTTP/3 请分离 `443/udp` 归属，避免端口冲突。
