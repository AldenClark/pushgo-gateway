use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::{
    api::{ApiJson, Error, HttpResult, parse_channel_id, validate_channel_password},
    app::{AppState, AuthMode},
    storage::Storage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpAuthMode {
    Hybrid,
    OAuth2Only,
    LegacyOnly,
}

impl McpAuthMode {
    pub(crate) fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "oauth2_only" => Self::OAuth2Only,
            "legacy_only" => Self::LegacyOnly,
            _ => Self::Hybrid,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct McpConfig {
    pub oauth_enabled: bool,
    pub legacy_auth_enabled: bool,
    pub auth_mode: McpAuthMode,
    pub oauth_issuer: Arc<str>,
    pub oauth_signing_key: Option<Arc<str>>,
    pub access_token_ttl_secs: i64,
    pub refresh_token_absolute_ttl_secs: i64,
    pub refresh_token_idle_ttl_secs: i64,
    pub bind_session_ttl_secs: i64,
    pub revoke_requires_password: bool,
    pub allowed_redirect_uris: Arc<HashSet<String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct McpState {
    pub config: McpConfig,
    store: Storage,
    principals: Arc<RwLock<HashMap<String, Principal>>>,
    auth_codes: Arc<RwLock<HashMap<String, AuthCode>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
    bind_sessions: Arc<RwLock<HashMap<String, BindSession>>>,
    pub shared_token: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Principal {
    principal_id: String,
    display_name: Option<String>,
    grants: HashMap<String, ChannelGrant>,
    created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelGrant {
    channel_id: String,
    granted_at: i64,
    expires_at: Option<i64>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct AuthCode {
    code: String,
    principal_id: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: String,
    expires_at: i64,
    consumed: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct RefreshToken {
    token_hash: String,
    principal_id: String,
    client_id: String,
    scope: String,
    expires_at: i64,
    idle_expires_at: i64,
    revoked: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct BindSession {
    bind_session_id: String,
    principal_id: String,
    action: BindAction,
    requested_channel_id: Option<String>,
    redirect_uri: Option<String>,
    status: BindStatus,
    expires_at: i64,
    completed_channel_id: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum BindAction {
    Bind,
    Revoke,
}

impl BindAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum BindStatus {
    Pending,
    Completed,
    Expired,
}

impl BindStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone)]
enum McpAuthContext {
    OAuth { principal_id: String, scope: String },
    Legacy,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct McpSnapshot {
    principals: HashMap<String, Principal>,
    auth_codes: HashMap<String, AuthCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
    bind_sessions: HashMap<String, BindSession>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    scope: String,
    iat: usize,
    exp: usize,
}

impl McpState {
    pub(crate) async fn new(config: McpConfig, auth: &AuthMode, store: Storage) -> Self {
        let shared_token = match auth {
            AuthMode::Disabled => None,
            AuthMode::SharedToken(value) => Some(Arc::clone(value)),
        };
        let snapshot = load_snapshot_from_db(&store).await;
        Self {
            config,
            store,
            principals: Arc::new(RwLock::new(snapshot.principals)),
            auth_codes: Arc::new(RwLock::new(snapshot.auth_codes)),
            refresh_tokens: Arc::new(RwLock::new(snapshot.refresh_tokens)),
            bind_sessions: Arc::new(RwLock::new(snapshot.bind_sessions)),
            shared_token,
        }
    }

    fn oauth_ready(&self) -> bool {
        self.config.oauth_enabled && self.config.oauth_signing_key.is_some()
    }

    fn is_redirect_allowed(&self, redirect_uri: &str) -> bool {
        if self.config.allowed_redirect_uris.is_empty() {
            return true;
        }
        self.config.allowed_redirect_uris.contains(redirect_uri)
    }

    async fn has_grant(&self, principal_id: &str, channel_id: &str) -> bool {
        let principals = self.principals.read().await;
        principals
            .get(principal_id)
            .and_then(|p| p.grants.get(channel_id))
            .is_some()
    }

    async fn list_grants(&self, principal_id: &str) -> Vec<ChannelGrant> {
        let principals = self.principals.read().await;
        principals
            .get(principal_id)
            .map(|value| value.grants.values().cloned().collect())
            .unwrap_or_default()
    }

    async fn upsert_grant(&self, principal_id: &str, channel_id: &str, expires_at: Option<i64>) {
        let mut principals = self.principals.write().await;
        let entry = principals
            .entry(principal_id.to_string())
            .or_insert_with(|| Principal {
                principal_id: principal_id.to_string(),
                display_name: None,
                grants: HashMap::new(),
                created_at: now_ts(),
            });
        entry.grants.insert(
            channel_id.to_string(),
            ChannelGrant {
                channel_id: channel_id.to_string(),
                granted_at: now_ts(),
                expires_at,
            },
        );
        drop(principals);
        self.persist_snapshot().await;
    }

    async fn remove_grant(&self, principal_id: &str, channel_id: &str) -> bool {
        let mut principals = self.principals.write().await;
        let Some(principal) = principals.get_mut(principal_id) else {
            return false;
        };
        let removed = principal.grants.remove(channel_id).is_some();
        drop(principals);
        if removed {
            self.persist_snapshot().await;
        }
        removed
    }

    async fn persist_snapshot(&self) {
        let principals = self.principals.read().await.clone();
        let auth_codes = self.auth_codes.read().await.clone();
        let refresh_tokens = self.refresh_tokens.read().await.clone();
        let bind_sessions = self.bind_sessions.read().await.clone();
        let snapshot = McpSnapshot {
            principals,
            auth_codes,
            refresh_tokens,
            bind_sessions,
        };
        save_snapshot_to_db(&self.store, &snapshot).await;
    }
}

async fn load_snapshot_from_db(store: &Storage) -> McpSnapshot {
    let Ok(Some(content)) = store.load_mcp_state_json().await else {
        return McpSnapshot::default();
    };
    serde_json::from_str::<McpSnapshot>(&content).unwrap_or_default()
}

async fn save_snapshot_to_db(store: &Storage, snapshot: &McpSnapshot) {
    if let Ok(encoded) = serde_json::to_string(snapshot) {
        let _ = store.save_mcp_state_json(&encoded).await;
    }
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        Alphanumeric.sample_string(&mut rand::rng(), 24)
    )
}

fn token_hash(raw: &str) -> String {
    blake3::hash(raw.as_bytes()).to_hex().to_string()
}


fn verify_pkce(code_challenge: &str, method: &str, code_verifier: &str) -> bool {
    if method.eq_ignore_ascii_case("plain") {
        return code_challenge == code_verifier;
    }
    if method.eq_ignore_ascii_case("S256") {
        let digest = Sha256::digest(code_verifier.as_bytes());
        let encoded = URL_SAFE_NO_PAD.encode(digest);
        return code_challenge == encoded;
    }
    false
}

fn parse_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

async fn authenticate_mcp(headers: &HeaderMap, mcp: &McpState) -> Result<McpAuthContext, Error> {
    let token = parse_bearer(headers).ok_or(Error::Unauthorized)?;

    if matches!(
        mcp.config.auth_mode,
        McpAuthMode::Hybrid | McpAuthMode::OAuth2Only
    ) && mcp.oauth_ready()
    {
        if let Some(signing_key) = &mcp.config.oauth_signing_key {
            let mut validation = Validation::new(Algorithm::HS256);
            validation.set_audience(&["mcp"]);
            validation.set_issuer(&[mcp.config.oauth_issuer.as_ref()]);
            if let Ok(decoded) = decode::<AccessClaims>(
                &token,
                &DecodingKey::from_secret(signing_key.as_bytes()),
                &validation,
            ) {
                return Ok(McpAuthContext::OAuth {
                    principal_id: decoded.claims.sub,
                    scope: decoded.claims.scope,
                });
            }
        }
    }

    if matches!(
        mcp.config.auth_mode,
        McpAuthMode::Hybrid | McpAuthMode::LegacyOnly
    ) && mcp.config.legacy_auth_enabled
    {
        if let Some(shared) = &mcp.shared_token
            && crate::util::constant_time_eq(token.as_bytes(), shared.as_bytes())
        {
            return Ok(McpAuthContext::Legacy);
        }
    }

    Err(Error::Unauthorized)
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizationQuery {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthorizeSubmit {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    display_name: Option<String>,
    channel_bindings: Option<String>,
}
