use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::storage::Storage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum McpScope {
    Tools,
    ChannelsManage,
}

impl McpScope {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Tools => "mcp:tools",
            Self::ChannelsManage => "mcp:channels:manage",
        }
    }
}

impl FromStr for McpScope {
    type Err = &'static str;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim() {
            "mcp:tools" => Ok(Self::Tools),
            "mcp:channels:manage" => Ok(Self::ChannelsManage),
            _ => Err("invalid scope"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct McpScopeSet(u8);

impl McpScopeSet {
    const TOOLS_BIT: u8 = 1 << 0;
    const CHANNELS_MANAGE_BIT: u8 = 1 << 1;

    pub(super) fn tools() -> Self {
        Self(Self::TOOLS_BIT)
    }

    pub(super) fn insert(&mut self, scope: McpScope) {
        self.0 |= Self::bit(scope);
    }

    pub(super) fn contains(&self, scope: McpScope) -> bool {
        self.0 & Self::bit(scope) != 0
    }

    pub(super) fn is_subset_of(&self, other: &Self) -> bool {
        self.0 & !other.0 == 0
    }

    pub(super) fn parse(raw: &str) -> Result<Self, &'static str> {
        let mut scopes = Self::default();
        for token in raw.split_whitespace() {
            let scope = McpScope::from_str(token)?;
            scopes.insert(scope);
        }
        if scopes.0 == 0 {
            return Err("invalid scope");
        }
        Ok(scopes)
    }

    pub(super) fn as_str(&self) -> String {
        let mut values = Vec::new();
        if self.contains(McpScope::Tools) {
            values.push(McpScope::Tools.as_str());
        }
        if self.contains(McpScope::ChannelsManage) {
            values.push(McpScope::ChannelsManage.as_str());
        }
        values.join(" ")
    }

    fn bit(scope: McpScope) -> u8 {
        match scope {
            McpScope::Tools => Self::TOOLS_BIT,
            McpScope::ChannelsManage => Self::CHANNELS_MANAGE_BIT,
        }
    }
}

impl Serialize for McpScopeSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str().as_str())
    }
}

impl<'de> Deserialize<'de> for McpScopeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

impl fmt::Display for McpScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str().as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PkceMethod {
    Plain,
    S256,
}

impl PkceMethod {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }

    pub(super) fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.trim().eq_ignore_ascii_case("plain") {
            Ok(Self::Plain)
        } else if raw.trim().eq_ignore_ascii_case("s256") {
            Ok(Self::S256)
        } else {
            Err("invalid code_challenge_method")
        }
    }

    pub(super) fn verify(self, code_challenge: &str, code_verifier: &str) -> bool {
        match self {
            Self::Plain => code_challenge == code_verifier,
            Self::S256 => {
                let digest = Sha256::digest(code_verifier.as_bytes());
                let encoded = URL_SAFE_NO_PAD.encode(digest);
                code_challenge == encoded
            }
        }
    }
}

impl Serialize for PkceMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PkceMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OAuthGrantType {
    AuthorizationCode,
    RefreshToken,
}

impl OAuthGrantType {
    pub(super) fn parse(raw: &str) -> Result<Self, &'static str> {
        match raw.trim() {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "refresh_token" => Ok(Self::RefreshToken),
            _ => Err("unsupported grant_type"),
        }
    }
}

impl<'de> Deserialize<'de> for OAuthGrantType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct McpConfig {
    pub bootstrap_http_addr: Arc<str>,
    pub public_base_url: Option<Arc<str>>,
    pub access_token_ttl_secs: i64,
    pub refresh_token_absolute_ttl_secs: i64,
    pub refresh_token_idle_ttl_secs: i64,
    pub bind_session_ttl_secs: i64,
    pub dcr_enabled: bool,
    pub predefined_clients: Vec<McpPredefinedClientConfig>,
}

#[derive(Debug, Clone)]
pub(crate) struct McpState {
    pub config: McpConfig,
    pub(super) oauth_issuer: Arc<RwLock<String>>,
    pub(super) oauth_signing_key: Arc<str>,
    pub(super) store: Storage,
    pub(super) principals: Arc<RwLock<HashMap<String, Principal>>>,
    pub(super) auth_codes: Arc<RwLock<HashMap<String, AuthCode>>>,
    pub(super) refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
    pub(super) bind_sessions: Arc<RwLock<HashMap<String, BindSession>>>,
    pub(super) oauth_clients: Arc<RwLock<HashMap<String, OAuthClient>>>,
    pub shared_token: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
pub(crate) struct McpPredefinedClientConfig {
    pub client_id: Arc<str>,
    pub client_secret: Arc<str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthClient {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    #[serde(default)]
    pub allow_any_https_redirect_uri: bool,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub(super) struct Principal {
    pub principal_id: String,
    pub display_name: Option<String>,
    pub grants: HashMap<String, ChannelGrant>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ChannelGrant {
    pub channel_id: String,
    pub granted_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub(super) struct AuthCode {
    pub code: String,
    pub principal_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: McpScopeSet,
    pub code_challenge: String,
    pub code_challenge_method: PkceMethod,
    pub expires_at: i64,
    pub consumed: bool,
}

impl AuthCode {
    pub(super) fn is_active(&self, now: i64) -> bool {
        !self.consumed && self.expires_at >= now
    }

    pub(super) fn matches_exchange_request(&self, client_id: &str, redirect_uri: &str) -> bool {
        self.client_id == client_id && self.redirect_uri == redirect_uri
    }

    pub(super) fn consume(&mut self) {
        self.consumed = true;
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub(super) struct RefreshToken {
    pub token_hash: String,
    pub principal_id: String,
    pub client_id: String,
    pub scope: McpScopeSet,
    pub expires_at: i64,
    pub idle_expires_at: i64,
    pub revoked: bool,
}

impl RefreshToken {
    pub(super) fn is_active_for(&self, client_id: &str, now: i64) -> bool {
        !self.revoked
            && self.expires_at >= now
            && self.idle_expires_at >= now
            && self.client_id == client_id
    }

    pub(super) fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(super) fn rotated(
        token_hash: String,
        principal_id: String,
        client_id: String,
        scope: McpScopeSet,
        issued_at: i64,
        absolute_ttl_secs: i64,
        idle_ttl_secs: i64,
    ) -> Self {
        Self {
            token_hash,
            principal_id,
            client_id,
            scope,
            expires_at: issued_at + absolute_ttl_secs,
            idle_expires_at: issued_at + idle_ttl_secs,
            revoked: false,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub(super) struct BindSession {
    pub bind_session_id: String,
    pub principal_id: String,
    pub action: BindAction,
    pub requested_channel_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub status: BindStatus,
    pub expires_at: i64,
    pub completed_channel_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    #[serde(default)]
    pub resource_list_change_notified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum BindAction {
    Bind,
    Revoke,
}

impl BindAction {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum BindStatus {
    Pending,
    Completed,
    Expired,
}

impl BindStatus {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizationQuery {
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) state: Option<String>,
    pub(super) code_challenge: String,
    #[serde(default)]
    pub(super) code_challenge_method: Option<PkceMethod>,
    #[serde(default)]
    pub(super) scope: Option<McpScopeSet>,
    #[serde(default)]
    pub(super) lang: Option<String>,
    #[serde(default)]
    pub(super) ui_locales: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeSubmit {
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) state: Option<String>,
    pub(super) code_challenge: String,
    pub(super) code_challenge_method: Option<PkceMethod>,
    pub(super) scope: Option<McpScopeSet>,
    pub(super) channel_bindings: Option<String>,
    #[serde(default)]
    pub(super) lang: Option<String>,
    #[serde(default)]
    pub(super) ui_locales: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{McpScope, McpScopeSet, OAuthGrantType, PkceMethod};

    #[test]
    fn scope_set_parses_and_normalizes() {
        let scopes = McpScopeSet::parse("mcp:channels:manage mcp:tools mcp:tools")
            .expect("scope should parse");
        assert!(scopes.contains(McpScope::Tools));
        assert!(scopes.contains(McpScope::ChannelsManage));
        assert_eq!(scopes.to_string(), "mcp:tools mcp:channels:manage");
    }

    #[test]
    fn scope_set_rejects_unknown_scope() {
        assert!(McpScopeSet::parse("mcp:unknown").is_err());
    }

    #[test]
    fn pkce_and_grant_type_deserialize_from_strings() {
        assert_eq!(PkceMethod::parse("S256").expect("pkce should parse"), PkceMethod::S256);
        assert_eq!(
            OAuthGrantType::parse("refresh_token").expect("grant should parse"),
            OAuthGrantType::RefreshToken
        );
    }
}
