use clap::Parser;
use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
};

const DEFAULT_TRACE_LOG_FILE: &str = "logs/pushgo-gateway-trace.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityProfile {
    ProdMin,
    Ops,
    Incident,
    Debug,
}

#[derive(Debug, Clone, Copy)]
pub struct ObservabilityConfig {
    pub profile: ObservabilityProfile,
    pub diagnostics_api_enabled: bool,
    pub trace_logs_enabled: bool,
    pub stats_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateTransports {
    pub quic: bool,
    pub tcp: bool,
    pub wss: bool,
}

impl PrivateTransports {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            quic: false,
            tcp: false,
            wss: false,
        }
    }

    #[must_use]
    pub const fn all() -> Self {
        Self {
            quic: true,
            tcp: true,
            wss: true,
        }
    }

    #[must_use]
    pub const fn any_enabled(self) -> bool {
        self.quic || self.tcp || self.wss
    }
}

impl ObservabilityProfile {
    #[inline]
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "prod-min" | "prod_min" | "minimal" => Some(Self::ProdMin),
            "ops" => Some(Self::Ops),
            "incident" => Some(Self::Incident),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProdMin => "prod_min",
            Self::Ops => "ops",
            Self::Incident => "incident",
            Self::Debug => "debug",
        }
    }

    fn defaults(self) -> ObservabilityConfig {
        match self {
            Self::ProdMin => ObservabilityConfig {
                profile: self,
                diagnostics_api_enabled: false,
                trace_logs_enabled: false,
                stats_enabled: true,
            },
            Self::Ops => ObservabilityConfig {
                profile: self,
                diagnostics_api_enabled: true,
                trace_logs_enabled: false,
                stats_enabled: true,
            },
            Self::Incident | Self::Debug => ObservabilityConfig {
                profile: self,
                diagnostics_api_enabled: true,
                trace_logs_enabled: true,
                stats_enabled: true,
            },
        }
    }
}

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

    /// Private transport switch. Supports:
    /// - boolean form: true/false
    /// - explicit set: none or comma-separated quic,tcp,wss
    #[arg(
        env = "PUSHGO_PRIVATE_TRANSPORTS",
        long = "private-transports",
        default_value = "false"
    )]
    pub private_transports: String,

    /// Observability profile controlling diagnostics/tracing/stats defaults.
    #[arg(
        env = "PUSHGO_OBSERVABILITY_PROFILE",
        long = "observability-profile",
        default_value = "prod_min"
    )]
    pub observability_profile: String,

    /// Override diagnostics API switch from observability profile.
    #[arg(
        env = "PUSHGO_OBSERVABILITY_DIAGNOSTICS_API_ENABLED",
        long = "observability-diagnostics-api-enabled"
    )]
    pub observability_diagnostics_api_enabled: Option<bool>,

    /// Override trace log switch from observability profile.
    #[arg(
        env = "PUSHGO_OBSERVABILITY_TRACE_LOGS_ENABLED",
        long = "observability-trace-logs-enabled"
    )]
    pub observability_trace_logs_enabled: Option<bool>,

    /// Override stats collection switch from observability profile.
    #[arg(
        env = "PUSHGO_OBSERVABILITY_STATS_ENABLED",
        long = "observability-stats-enabled"
    )]
    pub observability_stats_enabled: Option<bool>,

    /// Trace event file path (JSONL). Used when trace logs are enabled.
    #[arg(
        env = "PUSHGO_TRACE_LOG_FILE",
        long = "trace-log-file",
        default_value = DEFAULT_TRACE_LOG_FILE
    )]
    pub trace_log_file: String,

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
        default_value = "5223"
    )]
    pub private_quic_port: u16,

    /// TLS certificate path (PEM) used by private QUIC and by private TCP when TLS is gateway-terminated.
    #[arg(env = "PUSHGO_PRIVATE_TLS_CERT", long = "private-tls-cert")]
    pub private_tls_cert_path: Option<String>,

    /// TLS private key path (PEM) used by private QUIC and by private TCP when TLS is gateway-terminated.
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

    /// Enable MCP endpoint (`/mcp`) and related routes.
    #[arg(
        env = "PUSHGO_MCP_ENABLED",
        long = "mcp-enabled",
        default_value = "false"
    )]
    pub mcp_enabled: bool,

    /// Access token TTL for MCP OAuth (seconds).
    #[arg(
        env = "PUSHGO_MCP_ACCESS_TOKEN_TTL_SECS",
        long = "mcp-access-token-ttl-secs",
        default_value = "900"
    )]
    pub mcp_access_token_ttl_secs: i64,

    /// Public base URL used by externally exposed gateway URLs.
    #[arg(env = "PUSHGO_PUBLIC_BASE_URL", long = "public-base-url")]
    pub public_base_url: Option<String>,

    /// Refresh token absolute TTL (seconds).
    #[arg(
        env = "PUSHGO_MCP_REFRESH_TOKEN_ABSOLUTE_TTL_SECS",
        long = "mcp-refresh-token-absolute-ttl-secs",
        default_value = "2592000"
    )]
    pub mcp_refresh_token_absolute_ttl_secs: i64,

    /// Refresh token idle TTL (seconds).
    #[arg(
        env = "PUSHGO_MCP_REFRESH_TOKEN_IDLE_TTL_SECS",
        long = "mcp-refresh-token-idle-ttl-secs",
        default_value = "604800"
    )]
    pub mcp_refresh_token_idle_ttl_secs: i64,

    /// Bind session TTL for MCP channel bind pages (seconds).
    #[arg(
        env = "PUSHGO_MCP_BIND_SESSION_TTL_SECS",
        long = "mcp-bind-session-ttl-secs",
        default_value = "600"
    )]
    pub mcp_bind_session_ttl_secs: i64,

    /// Enable dynamic client registration for MCP OAuth.
    #[arg(
        env = "PUSHGO_MCP_DCR_ENABLED",
        long = "mcp-dcr-enabled",
        default_value = "true"
    )]
    pub mcp_dcr_enabled: bool,

    /// Predefined MCP OAuth clients formatted as `client_id:client_secret`, separated by newlines or semicolons.
    #[arg(env = "PUSHGO_MCP_PREDEFINED_CLIENTS", long = "mcp-predefined-clients")]
    pub mcp_predefined_clients: Option<String>,
}

impl Args {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.token = normalize_optional_non_empty(self.token);
        self.db_url = normalize_optional_non_empty(self.db_url);
        self.private_tls_cert_path = normalize_optional_non_empty(self.private_tls_cert_path);
        self.private_tls_key_path = normalize_optional_non_empty(self.private_tls_key_path);
        self.public_base_url = normalize_optional_non_empty(self.public_base_url);
        self.mcp_predefined_clients = normalize_optional_non_empty(self.mcp_predefined_clients);
        self.observability_profile = self.observability_profile.trim().to_string();
        if self.observability_profile.is_empty() {
            self.observability_profile = ObservabilityProfile::ProdMin.as_str().to_string();
        }
        self.trace_log_file = self.trace_log_file.trim().to_string();
        if self.trace_log_file.is_empty() {
            self.trace_log_file = DEFAULT_TRACE_LOG_FILE.to_string();
        }
        self.private_transports = self.private_transports.trim().to_string();
        if self.private_transports.is_empty() {
            self.private_transports = "false".to_string();
        }
        self
    }

    pub fn private_transports(&self) -> Result<PrivateTransports, IoError> {
        let transports = parse_private_transports(self.private_transports.as_str())?;
        self.validate_private_transport_dependencies(transports)?;
        Ok(transports)
    }

    fn validate_private_transport_dependencies(
        &self,
        transports: PrivateTransports,
    ) -> Result<(), IoError> {
        let cert_set = self.private_tls_cert_path.is_some();
        let key_set = self.private_tls_key_path.is_some();
        if cert_set ^ key_set {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "PUSHGO_PRIVATE_TLS_CERT and PUSHGO_PRIVATE_TLS_KEY must be configured together",
            ));
        }

        let tls_identity_ready = cert_set && key_set;
        if transports.quic && !tls_identity_ready {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "PUSHGO_PRIVATE_TRANSPORTS includes `quic`, but PUSHGO_PRIVATE_TLS_CERT and PUSHGO_PRIVATE_TLS_KEY are required",
            ));
        }
        if transports.tcp && !self.private_tcp_tls_offload && !tls_identity_ready {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "PUSHGO_PRIVATE_TRANSPORTS includes `tcp` with PUSHGO_PRIVATE_TCP_TLS_OFFLOAD=false, but PUSHGO_PRIVATE_TLS_CERT and PUSHGO_PRIVATE_TLS_KEY are required",
            ));
        }
        if transports.quic {
            validate_bind_addr(
                "PUSHGO_PRIVATE_QUIC_BIND",
                self.private_quic_bind.as_str(),
                "PUSHGO_PRIVATE_TRANSPORTS includes `quic`, but PUSHGO_PRIVATE_QUIC_BIND must be a valid socket address",
            )?;
            if self.private_quic_port == 0 {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "PUSHGO_PRIVATE_TRANSPORTS includes `quic`, but PUSHGO_PRIVATE_QUIC_PORT must be greater than 0",
                ));
            }
        }
        if transports.tcp {
            validate_bind_addr(
                "PUSHGO_PRIVATE_TCP_BIND",
                self.private_tcp_bind.as_str(),
                "PUSHGO_PRIVATE_TRANSPORTS includes `tcp`, but PUSHGO_PRIVATE_TCP_BIND must be a valid socket address",
            )?;
            if self.private_tcp_port == 0 {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    "PUSHGO_PRIVATE_TRANSPORTS includes `tcp`, but PUSHGO_PRIVATE_TCP_PORT must be greater than 0",
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn observability_config(&self) -> ObservabilityConfig {
        let profile = ObservabilityProfile::parse(self.observability_profile.as_str())
            .unwrap_or(ObservabilityProfile::ProdMin);
        let mut config = profile.defaults();

        if let Some(enabled) = self.observability_diagnostics_api_enabled {
            config.diagnostics_api_enabled = enabled;
        }
        if let Some(enabled) = self.observability_trace_logs_enabled {
            config.trace_logs_enabled = enabled;
        }
        if let Some(enabled) = self.observability_stats_enabled {
            config.stats_enabled = enabled;
        }

        config
    }
}

#[inline]
fn normalize_optional_non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_private_transports(raw: &str) -> Result<PrivateTransports, IoError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() || matches!(normalized.as_str(), "false" | "off" | "disabled" | "none")
    {
        return Ok(PrivateTransports::none());
    }
    if matches!(normalized.as_str(), "true" | "on" | "enabled" | "all") {
        return Ok(PrivateTransports::all());
    }

    let mut transports = PrivateTransports::none();
    let mut has_token = false;
    for token in normalized
        .split([',', ';', '|', ' '])
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        has_token = true;
        match token {
            "quic" => transports.quic = true,
            "tcp" => transports.tcp = true,
            "wss" => transports.wss = true,
            unknown => {
                return Err(IoError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "invalid private transport `{unknown}` in PUSHGO_PRIVATE_TRANSPORTS (expected true/false/none or quic,tcp,wss)"
                    ),
                ));
            }
        }
    }

    if !has_token {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "PUSHGO_PRIVATE_TRANSPORTS is empty after parsing",
        ));
    }
    Ok(transports)
}

fn validate_bind_addr(env_name: &str, raw: &str, message: &str) -> Result<SocketAddr, IoError> {
    let normalized = raw.trim();
    normalized.parse::<SocketAddr>().map_err(|err| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!("{message}: {env_name}=`{normalized}` ({err})"),
        )
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Args, ObservabilityProfile, PrivateTransports, normalize_optional_non_empty};

    #[test]
    fn normalize_optional_non_empty_treats_empty_and_whitespace_as_missing() {
        assert_eq!(normalize_optional_non_empty(None), None);
        assert_eq!(normalize_optional_non_empty(Some(String::new())), None);
        assert_eq!(normalize_optional_non_empty(Some("   ".to_string())), None);
    }

    #[test]
    fn normalize_optional_non_empty_trims_non_empty_values() {
        assert_eq!(
            normalize_optional_non_empty(Some(" sqlite:///data/pushgo.db  ".to_string())),
            Some("sqlite:///data/pushgo.db".to_string())
        );
    }

    #[test]
    fn prod_min_profile_is_default_minimal_matrix() {
        let args = Args::parse_from(["pushgo-gateway", "--db-url", "sqlite:///tmp/pushgo.db"])
            .normalized();
        let config = args.observability_config();
        assert_eq!(config.profile, ObservabilityProfile::ProdMin);
        assert!(!config.diagnostics_api_enabled);
        assert!(!config.trace_logs_enabled);
        assert!(config.stats_enabled);
    }

    #[test]
    fn profile_defaults_and_overrides_apply() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--observability-profile=ops",
            "--observability-trace-logs-enabled=true",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let config = args.observability_config();
        assert_eq!(config.profile, ObservabilityProfile::Ops);
        assert!(config.diagnostics_api_enabled);
        assert!(config.trace_logs_enabled);
        assert!(config.stats_enabled);
    }

    #[test]
    fn invalid_profile_falls_back_to_prod_min() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--observability-profile=unknown-mode",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let config = args.observability_config();
        assert_eq!(config.profile, ObservabilityProfile::ProdMin);
    }

    #[test]
    fn trace_log_file_blank_falls_back_to_default() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--trace-log-file",
            "   ",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        assert_eq!(args.trace_log_file, super::DEFAULT_TRACE_LOG_FILE);
    }

    #[test]
    fn private_transports_supports_boolean_switch() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=true",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--private-tls-cert",
            "/tmp/cert.pem",
            "--private-tls-key",
            "/tmp/key.pem",
        ])
        .normalized();
        assert_eq!(
            args.private_transports()
                .expect("private transports should parse"),
            PrivateTransports::all()
        );
    }

    #[test]
    fn private_transports_supports_explicit_list() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=tcp,wss",
            "--private-tcp-tls-offload",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        assert_eq!(
            args.private_transports()
                .expect("private transports should parse"),
            PrivateTransports {
                quic: false,
                tcp: true,
                wss: true,
            }
        );
    }

    #[test]
    fn private_transports_rejects_quic_without_tls_identity() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=quic",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let error = args
            .private_transports()
            .expect_err("quic without tls identity must fail");
        assert!(
            error
                .to_string()
                .contains("PUSHGO_PRIVATE_TRANSPORTS includes `quic`")
        );
    }

    #[test]
    fn private_transports_rejects_partial_tls_identity() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=wss",
            "--private-tls-cert",
            "/tmp/cert.pem",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let error = args
            .private_transports()
            .expect_err("partial tls identity must fail");
        assert!(error.to_string().contains(
            "PUSHGO_PRIVATE_TLS_CERT and PUSHGO_PRIVATE_TLS_KEY must be configured together"
        ));
    }

    #[test]
    fn private_transports_rejects_tcp_without_tls_identity_when_offload_disabled() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=tcp",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let error = args
            .private_transports()
            .expect_err("tcp without tls identity must fail when offload is disabled");
        assert!(error.to_string().contains(
            "PUSHGO_PRIVATE_TRANSPORTS includes `tcp` with PUSHGO_PRIVATE_TCP_TLS_OFFLOAD=false"
        ));
    }

    #[test]
    fn private_transports_rejects_invalid_bind_addr_for_enabled_transport() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=tcp",
            "--private-tcp-bind",
            "invalid-bind",
            "--private-tcp-tls-offload",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let error = args
            .private_transports()
            .expect_err("invalid tcp bind should fail");
        assert!(
            error
                .to_string()
                .contains("PUSHGO_PRIVATE_TRANSPORTS includes `tcp`, but PUSHGO_PRIVATE_TCP_BIND must be a valid socket address")
        );
    }

    #[test]
    fn private_transports_rejects_zero_port_for_enabled_transport() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=quic",
            "--private-quic-port",
            "0",
            "--private-tls-cert",
            "/tmp/cert.pem",
            "--private-tls-key",
            "/tmp/key.pem",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let error = args
            .private_transports()
            .expect_err("zero quic port should fail");
        assert!(
            error
                .to_string()
                .contains("PUSHGO_PRIVATE_TRANSPORTS includes `quic`, but PUSHGO_PRIVATE_QUIC_PORT must be greater than 0")
        );
    }

    #[test]
    fn private_transports_ignores_disabled_transport_bind_validation() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--private-transports=wss",
            "--private-quic-bind",
            "invalid-quic-bind",
            "--private-tcp-bind",
            "invalid-tcp-bind",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        assert_eq!(
            args.private_transports()
                .expect("disabled quic/tcp bind should not block wss-only config"),
            PrivateTransports {
                quic: false,
                tcp: false,
                wss: true,
            }
        );
    }
}
