use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "pushgo-gateway", version, about = "PushGo 推送网关")]
pub struct Args {
    /// HTTP bind address.
    #[arg(
        env = "PUSHGO_HTTP_ADDR",
        long = "http-addr",
        default_value = "127.0.0.1:6666"
    )]
    pub http_addr: String,

    /// Optional Token for API authentication.
    #[arg(env = "PUSHGO_TOKEN", long = "token")]
    pub token: Option<String>,

    /// Run gateway in sandbox mode (APNs sandbox endpoint + verbose logging).
    #[arg(
        env = "PUSHGO_SANDBOX_MODE",
        long = "sandbox-mode",
        default_value = "false"
    )]
    pub sandbox_mode: bool,

    /// Token service URL used for APNs/FCM/WNS auth token retrieval.
    #[arg(
        env = "PUSHGO_TOKEN_SERVICE_URL",
        long = "token-service-url",
        default_value = "https://token.pushgo.dev"
    )]
    pub token_service_url: String,

    /// Enable private channel module (HTTP private routes + realtime transport).
    #[arg(
        env = "PUSHGO_PRIVATE_CHANNEL_ENABLED",
        long = "private-channel-enabled",
        default_value = "false"
    )]
    pub private_channel_enabled: bool,

    /// Enable diagnostics API namespace (`/diagnostics/*`).
    #[arg(
        env = "PUSHGO_DIAGNOSTICS_API_ENABLED",
        long = "diagnostics-api-enabled",
        default_value = "false"
    )]
    pub diagnostics_api_enabled: bool,

    /// Database URL. Supported schemes: sqlite://, postgres://, postgresql://, pg://, mysql://.
    /// This value is required.
    #[arg(env = "PUSHGO_DB_URL", long = "db-url")]
    pub db_url: Option<String>,

    /// QUIC bind address for the private transport listener.
    #[arg(
        env = "PUSHGO_PRIVATE_QUIC_BIND",
        long = "private-quic-bind",
        default_value = "127.0.0.1:5223"
    )]
    pub private_quic_bind: String,

    /// Advertised QUIC port for private channel clients.
    #[arg(
        env = "PUSHGO_PRIVATE_QUIC_PORT",
        long = "private-quic-port",
        default_value = "443"
    )]
    pub private_quic_port: u16,

    /// TLS certificate path (PEM) shared by private QUIC and private TCP listeners.
    #[arg(env = "PUSHGO_PRIVATE_TLS_CERT", long = "private-tls-cert")]
    pub private_tls_cert_path: Option<String>,

    /// TLS private key path (PEM) shared by private QUIC and private TCP listeners.
    #[arg(env = "PUSHGO_PRIVATE_TLS_KEY", long = "private-tls-key")]
    pub private_tls_key_path: Option<String>,

    /// TCP bind address for the private transport listener.
    #[arg(
        env = "PUSHGO_PRIVATE_TCP_BIND",
        long = "private-tcp-bind",
        default_value = "127.0.0.1:5223"
    )]
    pub private_tcp_bind: String,

    /// Advertised TCP port for private channel clients.
    #[arg(
        env = "PUSHGO_PRIVATE_TCP_PORT",
        long = "private-tcp-port",
        default_value = "5223"
    )]
    pub private_tcp_port: u16,

    /// If true, private TCP listener runs in plain mode for edge-terminated TLS.
    #[arg(
        env = "PUSHGO_PRIVATE_TCP_TLS_OFFLOAD",
        long = "private-tcp-tls-offload",
        default_value = "false"
    )]
    pub private_tcp_tls_offload: bool,

    /// If true, expects HAProxy PROXY protocol v1 on private TCP inbound.
    #[arg(
        env = "PUSHGO_PRIVATE_TCP_PROXY_PROTOCOL",
        long = "private-tcp-proxy-protocol",
        default_value = "false"
    )]
    pub private_tcp_proxy_protocol: bool,

    /// Private session TTL in seconds.
    #[arg(
        env = "PUSHGO_PRIVATE_SESSION_TTL",
        long = "private-session-ttl",
        default_value = "3600"
    )]
    pub private_session_ttl_secs: i64,

    /// Private grace window for connection draining in seconds.
    #[arg(
        env = "PUSHGO_PRIVATE_GRACE_WINDOW",
        long = "private-grace-window",
        default_value = "60"
    )]
    pub private_grace_window_secs: u64,

    /// Max pending private messages per device.
    #[arg(
        env = "PUSHGO_PRIVATE_MAX_PENDING",
        long = "private-max-pending",
        default_value = "200"
    )]
    pub private_max_pending_per_device: usize,

    /// Max pull batch size per request.
    #[arg(
        env = "PUSHGO_PRIVATE_PULL_LIMIT",
        long = "private-pull-limit",
        default_value = "200"
    )]
    pub private_pull_limit: usize,

    /// Ack timeout before scheduling system push fallback in seconds.
    #[arg(
        env = "PUSHGO_PRIVATE_ACK_TIMEOUT",
        long = "private-ack-timeout",
        default_value = "15"
    )]
    pub private_ack_timeout_secs: u64,

    /// Max system-push fallback attempts after private ACK timeout.
    #[arg(
        env = "PUSHGO_PRIVATE_FALLBACK_MAX_ATTEMPTS",
        long = "private-fallback-max-attempts",
        default_value = "5"
    )]
    pub private_fallback_max_attempts: u32,

    /// Max backoff in seconds for persisted fallback retries.
    #[arg(
        env = "PUSHGO_PRIVATE_FALLBACK_MAX_BACKOFF",
        long = "private-fallback-max-backoff",
        default_value = "300"
    )]
    pub private_fallback_max_backoff_secs: u64,

    /// Retransmit budget window in seconds for private in-connection retries.
    #[arg(
        env = "PUSHGO_PRIVATE_RETX_WINDOW_SECS",
        long = "private-retx-window-secs",
        default_value = "10"
    )]
    pub private_retx_window_secs: u64,

    /// Max retransmit frames allowed per device within one budget window.
    #[arg(
        env = "PUSHGO_PRIVATE_RETX_MAX_PER_WINDOW",
        long = "private-retx-max-per-window",
        default_value = "128"
    )]
    pub private_retx_max_per_window: u32,

    /// Max retransmit frames sent per tick per connection.
    #[arg(
        env = "PUSHGO_PRIVATE_RETX_MAX_PER_TICK",
        long = "private-retx-max-per-tick",
        default_value = "16"
    )]
    pub private_retx_max_per_tick: usize,

    /// Max retransmit retries per in-flight delivery before giving up in-channel retransmit.
    #[arg(
        env = "PUSHGO_PRIVATE_RETX_MAX_RETRIES",
        long = "private-retx-max-retries",
        default_value = "5"
    )]
    pub private_retx_max_retries: u8,

    /// Global max pending private outbox entries.
    #[arg(
        env = "PUSHGO_PRIVATE_GLOBAL_MAX_PENDING",
        long = "private-global-max-pending",
        default_value = "5000000"
    )]
    pub private_global_max_pending: usize,

    /// In-memory hot cache capacity for private messages.
    #[arg(
        env = "PUSHGO_PRIVATE_HOT_CACHE_CAPACITY",
        long = "private-hot-cache-capacity",
        default_value = "50000"
    )]
    pub private_hot_cache_capacity: usize,

    /// Default private message TTL in seconds.
    #[arg(
        env = "PUSHGO_PRIVATE_DEFAULT_TTL",
        long = "private-default-ttl",
        default_value = "2592000"
    )]
    pub private_default_ttl_secs: i64,
}
