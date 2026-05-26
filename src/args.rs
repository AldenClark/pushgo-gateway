use clap::Parser;
use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use reqwest::Url;

use crate::runtime_config::{GatewayRuntimeProfile, GatewayRuntimeProfileSelection, RuntimeTuning};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityProfile {
    ProdMin,
    Ops,
    Incident,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityLogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy)]
pub struct ObservabilityConfig {
    pub profile: ObservabilityProfile,
    pub log_level: ObservabilityLogLevel,
    pub diagnostics_api_enabled: bool,
    pub stats_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateTransports {
    pub quic: bool,
    pub tcp: bool,
    pub wss: bool,
}

#[derive(Debug, Clone)]
pub struct TokenServiceBaseUrl(String);

#[derive(Debug, Clone)]
pub struct PublicBaseUrl {
    canonical: String,
    parsed: Url,
}

#[derive(Debug, Clone)]
pub struct McpPredefinedClient {
    client_id: Arc<str>,
    client_secret: Arc<str>,
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

impl TokenServiceBaseUrl {
    fn parse(raw: &str) -> Result<Self, IoError> {
        let (canonical, _) = parse_http_base_url(
            raw,
            "PUSHGO_TOKEN_SERVICE_URL",
            "PUSHGO_TOKEN_SERVICE_URL must be a valid http(s) base URL",
        )?;
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PublicBaseUrl {
    fn parse(raw: &str) -> Result<Self, IoError> {
        let (canonical, parsed) = parse_http_base_url(
            raw,
            "PUSHGO_PUBLIC_BASE_URL",
            "PUSHGO_PUBLIC_BASE_URL must be a valid http(s) base URL",
        )?;
        Ok(Self { canonical, parsed })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.canonical.as_str()
    }

    #[must_use]
    pub fn advertised_port(&self) -> u16 {
        self.parsed.port_or_known_default().unwrap_or(443)
    }

    #[must_use]
    pub fn into_arc_str(self) -> Arc<str> {
        Arc::from(self.canonical.into_boxed_str())
    }
}

impl McpPredefinedClient {
    fn parse(raw: &str) -> Result<Self, IoError> {
        let Some((client_id, client_secret)) = raw.split_once(':') else {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                format!("invalid predefined MCP client entry: {raw}"),
            ));
        };
        let client_id = normalize_non_empty_str(client_id).ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidInput,
                format!("invalid predefined MCP client entry: {raw}"),
            )
        })?;
        let client_secret = normalize_non_empty_str(client_secret).ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidInput,
                format!("invalid predefined MCP client entry: {raw}"),
            )
        })?;
        Ok(Self {
            client_id: Arc::from(client_id.into_boxed_str()),
            client_secret: Arc::from(client_secret.into_boxed_str()),
        })
    }

    #[must_use]
    pub fn client_id(&self) -> Arc<str> {
        Arc::clone(&self.client_id)
    }

    #[must_use]
    pub fn client_secret(&self) -> Arc<str> {
        Arc::clone(&self.client_secret)
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
                log_level: ObservabilityLogLevel::Warn,
                diagnostics_api_enabled: false,
                stats_enabled: true,
            },
            Self::Ops => ObservabilityConfig {
                profile: self,
                log_level: ObservabilityLogLevel::Warn,
                diagnostics_api_enabled: true,
                stats_enabled: true,
            },
            Self::Incident | Self::Debug => ObservabilityConfig {
                profile: self,
                log_level: ObservabilityLogLevel::Warn,
                diagnostics_api_enabled: true,
                stats_enabled: true,
            },
        }
    }
}

impl ObservabilityLogLevel {
    #[inline]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" | "false" => Some(Self::Off),
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" | "true" | "enabled" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
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

    /// Runtime profile for resource/performance defaults.
    #[arg(
        env = "PUSHGO_RUNTIME_PROFILE",
        long = "runtime-profile",
        default_value = "small"
    )]
    pub runtime_profile: String,

    /// Observability profile controlling diagnostics/tracing/stats defaults.
    #[arg(
        env = "PUSHGO_OBSERVABILITY_PROFILE",
        long = "observability-profile",
        default_value = "prod_min"
    )]
    pub observability_profile: String,

    /// Override native tracing log level from observability profile default.
    #[arg(
        env = "PUSHGO_OBSERVABILITY_LOG_LEVEL",
        long = "observability-log-level"
    )]
    pub observability_log_level: Option<String>,

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

    /// Enable MCP endpoint (`/mcp`) and related routes.
    #[arg(
        env = "PUSHGO_MCP_ENABLED",
        long = "mcp-enabled",
        default_value = "false"
    )]
    pub mcp_enabled: bool,

    /// Public base URL used by externally exposed gateway URLs.
    #[arg(env = "PUSHGO_PUBLIC_BASE_URL", long = "public-base-url")]
    pub public_base_url: Option<String>,

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
        self.observability_log_level = normalize_optional_non_empty(self.observability_log_level);
        self.observability_profile = self.observability_profile.trim().to_string();
        if self.observability_profile.is_empty() {
            self.observability_profile = ObservabilityProfile::ProdMin.as_str().to_string();
        }
        self.runtime_profile = self.runtime_profile.trim().to_string();
        if self.runtime_profile.is_empty() {
            self.runtime_profile = GatewayRuntimeProfileSelection::Small.as_str().to_string();
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

    pub fn token_service_base_url(&self) -> Result<TokenServiceBaseUrl, IoError> {
        TokenServiceBaseUrl::parse(self.token_service_url.as_str())
    }

    pub fn public_base_url_value(&self) -> Result<Option<PublicBaseUrl>, IoError> {
        self.public_base_url
            .as_deref()
            .map(PublicBaseUrl::parse)
            .transpose()
    }

    pub fn mcp_predefined_client_values(&self) -> Result<Vec<McpPredefinedClient>, IoError> {
        let Some(raw) = self.mcp_predefined_clients.as_deref() else {
            return Ok(Vec::new());
        };
        raw.split(['\n', ';'])
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(McpPredefinedClient::parse)
            .collect()
    }

    pub fn runtime_profile_selection(&self) -> Result<GatewayRuntimeProfileSelection, IoError> {
        GatewayRuntimeProfileSelection::parse(self.runtime_profile.as_str()).ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidInput,
                format!(
                    "invalid PUSHGO_RUNTIME_PROFILE `{}` (expected small or public)",
                    self.runtime_profile
                ),
            )
        })
    }

    pub fn runtime_profile(&self) -> Result<GatewayRuntimeProfile, IoError> {
        Ok(self.runtime_profile_selection()?.resolve())
    }

    pub fn runtime_tuning(&self) -> Result<RuntimeTuning, IoError> {
        Ok(RuntimeTuning::for_profile(self.runtime_profile()?))
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

        if let Some(raw) = self.observability_log_level.as_deref()
            && let Some(log_level) = ObservabilityLogLevel::parse(raw)
        {
            config.log_level = log_level;
        }

        config
    }
}

#[inline]
fn normalize_optional_non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|raw| normalize_non_empty_str(raw.as_str()))
}

#[inline]
fn normalize_non_empty_str(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_http_base_url(raw: &str, env_name: &str, message: &str) -> Result<(String, Url), IoError> {
    let canonical = normalize_non_empty_str(raw).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!("{message}: {env_name} must not be empty"),
        )
    })?;
    let canonical = canonical.trim_end_matches('/').to_string();
    let parsed = Url::parse(canonical.as_str()).map_err(|err| {
        IoError::new(
            ErrorKind::InvalidInput,
            format!("{message}: {env_name}=`{canonical}` ({err})"),
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            format!("{message}: {env_name}=`{canonical}`"),
        ));
    }
    Ok((canonical, parsed))
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

    use crate::{runtime_config::GatewayRuntimeProfile, storage::DatabaseKind};

    use super::{
        Args, ObservabilityLogLevel, ObservabilityProfile, PrivateTransports,
        normalize_optional_non_empty,
    };

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
        assert_eq!(config.log_level, ObservabilityLogLevel::Warn);
        assert!(!config.diagnostics_api_enabled);
        assert!(config.stats_enabled);
    }

    #[test]
    fn profile_defaults_and_overrides_apply() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--observability-profile=ops",
            "--observability-log-level=debug",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let config = args.observability_config();
        assert_eq!(config.profile, ObservabilityProfile::Ops);
        assert_eq!(config.log_level, ObservabilityLogLevel::Debug);
        assert!(config.diagnostics_api_enabled);
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
    fn invalid_observability_log_level_falls_back_to_profile_default() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--observability-log-level=not-a-level",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
        ])
        .normalized();
        let config = args.observability_config();
        assert_eq!(config.log_level, ObservabilityLogLevel::Warn);
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

    #[test]
    fn token_service_base_url_rejects_non_http_values() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--token-service-url",
            " ftp://token.pushgo.dev ",
        ])
        .normalized();
        assert!(args.token_service_base_url().is_err());
    }

    #[test]
    fn public_base_url_value_trims_and_removes_trailing_slash() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--public-base-url",
            " https://pushgo.dev/ ",
        ])
        .normalized();
        let base_url = args
            .public_base_url_value()
            .expect("public base url should parse")
            .expect("public base url should exist");
        assert_eq!(base_url.as_str(), "https://pushgo.dev");
        assert_eq!(base_url.advertised_port(), 443);
    }

    #[test]
    fn mcp_predefined_client_values_reject_invalid_shape() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--mcp-predefined-clients",
            "client-only",
        ])
        .normalized();
        assert!(args.mcp_predefined_client_values().is_err());
    }

    #[test]
    fn mcp_predefined_client_values_trim_and_collect_entries() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--mcp-predefined-clients",
            " client-a : secret-a ; client-b:secret-b ",
        ])
        .normalized();
        let clients = args
            .mcp_predefined_client_values()
            .expect("clients should parse");
        assert_eq!(clients.len(), 2);
        assert_eq!(&*clients[0].client_id(), "client-a");
        assert_eq!(&*clients[0].client_secret(), "secret-a");
        assert_eq!(&*clients[1].client_id(), "client-b");
        assert_eq!(&*clients[1].client_secret(), "secret-b");
    }

    #[test]
    fn runtime_profile_defaults_to_small() {
        let args = Args::parse_from(["pushgo-gateway", "--db-url", "sqlite:///tmp/pushgo.db"])
            .normalized();
        assert_eq!(
            args.runtime_profile().unwrap(),
            GatewayRuntimeProfile::Small
        );
        let tuning = args.runtime_tuning().unwrap();
        assert_eq!(tuning.profile, GatewayRuntimeProfile::Small);
        assert_eq!(tuning.private.max_pending_per_device, 96);
        assert_eq!(tuning.sqlite.core_read_connections, 2);
    }

    #[test]
    fn runtime_profile_default_stays_small_for_postgres() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "postgres://pushgo:pushgo@localhost/pushgo",
        ])
        .normalized();
        assert_eq!(
            args.runtime_profile().unwrap(),
            GatewayRuntimeProfile::Small
        );
        let tuning = args.runtime_tuning().unwrap();
        assert_eq!(tuning.profile, GatewayRuntimeProfile::Small);
        assert_eq!(tuning.private.max_pending_per_device, 96);
        assert_eq!(tuning.external_db.max_connections, 8);
    }

    #[test]
    fn runtime_profile_public_is_explicit() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "postgres://pushgo:pushgo@localhost/pushgo",
            "--runtime-profile",
            "public",
        ])
        .normalized();
        assert_eq!(
            args.runtime_profile().unwrap(),
            GatewayRuntimeProfile::Public
        );
        let tuning = args.runtime_tuning().unwrap();
        assert_eq!(tuning.profile, GatewayRuntimeProfile::Public);
        assert_eq!(tuning.external_db.max_connections, 64);
    }

    #[test]
    fn runtime_profile_does_not_change_database_driver_selection() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--runtime-profile",
            "public",
        ])
        .normalized();
        assert_eq!(
            args.runtime_profile().unwrap(),
            GatewayRuntimeProfile::Public
        );
        assert_eq!(
            DatabaseKind::from_url(args.db_url.as_deref().unwrap()).unwrap(),
            DatabaseKind::Sqlite
        );
    }

    #[test]
    fn runtime_profile_rejects_invalid_value() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--runtime-profile",
            "huge",
        ])
        .normalized();
        let error = args
            .runtime_profile()
            .expect_err("invalid runtime profile must fail");
        assert!(error.to_string().contains("invalid PUSHGO_RUNTIME_PROFILE"));
    }

    #[test]
    fn runtime_profile_rejects_auto() {
        let args = Args::parse_from([
            "pushgo-gateway",
            "--db-url",
            "sqlite:///tmp/pushgo.db",
            "--runtime-profile",
            "auto",
        ])
        .normalized();
        assert!(args.runtime_profile().is_err());
    }
}
