use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use rand::distr::{Alphanumeric, SampleString};
use tokio::sync::{Mutex, RwLock};

use crate::app::AuthMode;
use crate::storage::{StoreError, StoreResult};

use super::{ChannelGrant, McpSnapshot, McpState, core_snapshot::OAuthRuntimeSnapshot};

impl McpState {
    pub(crate) async fn try_new(
        config: super::McpConfig,
        auth: &AuthMode,
        store: crate::storage::Storage,
    ) -> StoreResult<Self> {
        Self::validate_config(&config)?;
        let shared_token = match auth {
            AuthMode::Disabled => None,
            AuthMode::SharedToken(value) => Some(Arc::clone(value)),
        };
        let mut snapshot = McpSnapshot::load_from(&store).await?;
        let snapshot_pruned = snapshot.prune(Self::now_ts());
        let runtime_missing = snapshot.oauth_runtime.is_none();
        let mut oauth_clients = snapshot.oauth_clients;
        let mut redirect_policy_changed = false;
        for client in oauth_clients.values_mut() {
            if client.allow_any_https_redirect_uri {
                client.allow_any_https_redirect_uri = false;
                redirect_policy_changed = true;
            }
            let original_redirect_count = client.redirect_uris.len();
            client
                .redirect_uris
                .retain(|uri| Self::valid_redirect_uri(uri));
            client.redirect_uris.sort_unstable();
            client.redirect_uris.dedup();
            if client.redirect_uris.len() != original_redirect_count {
                redirect_policy_changed = true;
            }
        }
        let configured_issuer = Self::bootstrap_issuer(
            config.public_base_url.as_deref(),
            config.bootstrap_http_addr.as_ref(),
        )?;
        let issuer_changed = snapshot
            .oauth_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.oauth_issuer != configured_issuer);
        let oauth_issuer = Arc::from(configured_issuer.into_boxed_str());
        let oauth_signing_key = snapshot.oauth_runtime.as_ref().map_or_else(
            || Arc::from(Self::generate_signing_key().into_boxed_str()),
            |runtime| Arc::from(runtime.oauth_signing_key.clone().into_boxed_str()),
        );
        let mut predefined_clients_changed = false;
        for predefined in &config.predefined_clients {
            let redirect_uris = oauth_clients
                .get(predefined.client_id.as_ref())
                .map(|client| client.redirect_uris.clone())
                .unwrap_or_default();
            let client = super::OAuthClient {
                client_id: predefined.client_id.to_string(),
                client_secret_hash: Some(Self::token_hash(predefined.client_secret.as_ref())),
                allow_any_https_redirect_uri: false,
                redirect_uris,
                token_endpoint_auth_method: "client_secret_post".to_string(),
                created_at: Self::now_ts(),
            };
            match oauth_clients.get(predefined.client_id.as_ref()) {
                Some(existing)
                    if existing.client_secret_hash == client.client_secret_hash
                        && !existing.allow_any_https_redirect_uri
                        && existing.redirect_uris == client.redirect_uris
                        && existing.token_endpoint_auth_method == "client_secret_post" => {}
                _ => {
                    oauth_clients.insert(predefined.client_id.to_string(), client);
                    predefined_clients_changed = true;
                }
            }
        }
        let state = Self {
            config,
            oauth_issuer,
            oauth_signing_key,
            store,
            mutation: Arc::new(Mutex::new(())),
            persistence_healthy: Arc::new(AtomicBool::new(true)),
            oauth_clients: Arc::new(RwLock::new(oauth_clients)),
            principals: Arc::new(RwLock::new(snapshot.principals)),
            auth_codes: Arc::new(RwLock::new(snapshot.auth_codes)),
            refresh_tokens: Arc::new(RwLock::new(snapshot.refresh_tokens)),
            bind_sessions: Arc::new(RwLock::new(snapshot.bind_sessions)),
            shared_token,
        };
        if snapshot_pruned
            || runtime_missing
            || issuer_changed
            || redirect_policy_changed
            || predefined_clients_changed
        {
            state.persist_snapshot().await?;
        }
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) async fn new(
        config: super::McpConfig,
        auth: &AuthMode,
        store: crate::storage::Storage,
    ) -> Self {
        Self::try_new(config, auth, store)
            .await
            .expect("MCP test state should initialize")
    }

    pub(super) fn oauth_ready(&self) -> bool {
        self.persistence_healthy.load(Ordering::Acquire)
    }

    fn bootstrap_issuer(public_base_url: Option<&str>, http_addr: &str) -> StoreResult<String> {
        if let Some(base_url) = public_base_url {
            let parsed = reqwest::Url::parse(base_url).map_err(|err| {
                StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid PUSHGO_PUBLIC_BASE_URL: {err}"),
                ))
            })?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "PUSHGO_PUBLIC_BASE_URL must be an absolute HTTPS URL when MCP is enabled",
                )));
            }
            return Ok(parsed.as_str().trim_end_matches('/').to_string());
        }
        let address = http_addr.parse::<SocketAddr>().map_err(|err| {
            StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid MCP bootstrap HTTP address: {err}"),
            ))
        })?;
        if !address.ip().is_loopback() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PUSHGO_PUBLIC_BASE_URL is required when MCP listens on a non-loopback address",
            )));
        }
        Ok(format!("http://{address}"))
    }

    fn validate_config(config: &super::McpConfig) -> StoreResult<()> {
        let valid = config.access_token_ttl_secs > 0
            && config.refresh_token_absolute_ttl_secs > 0
            && config.refresh_token_idle_ttl_secs > 0
            && config.refresh_token_idle_ttl_secs <= config.refresh_token_absolute_ttl_secs
            && config.bind_session_ttl_secs > 0;
        if valid {
            Ok(())
        } else {
            Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid MCP OAuth TTL configuration",
            )))
        }
    }

    pub(super) fn valid_redirect_uri(value: &str) -> bool {
        if value.is_empty() || value.len() > 2_048 {
            return false;
        }
        let Ok(parsed) = reqwest::Url::parse(value) else {
            return false;
        };
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.fragment().is_none()
    }

    fn generate_signing_key() -> String {
        Alphanumeric.sample_string(&mut rand::rng(), 64)
    }

    pub(super) async fn oauth_issuer(&self) -> String {
        self.oauth_issuer.to_string()
    }

    pub(super) async fn oauth_signing_key(&self) -> Arc<str> {
        Arc::clone(&self.oauth_signing_key)
    }

    pub(super) async fn client_redirect_allowed(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> bool {
        let clients = self.oauth_clients.read().await;
        clients
            .get(client_id)
            .filter(|_| Self::valid_redirect_uri(redirect_uri))
            .map(|client| client.redirect_uris.iter().any(|item| item == redirect_uri))
            .unwrap_or(false)
    }

    pub(super) async fn validate_client_for_token(
        &self,
        client_id: &str,
        provided_secret: Option<&str>,
    ) -> bool {
        let clients = self.oauth_clients.read().await;
        let Some(client) = clients.get(client_id) else {
            return false;
        };
        if client.token_endpoint_auth_method == "none" {
            return true;
        }
        if client.token_endpoint_auth_method == "client_secret_post"
            && let Some(secret) = provided_secret
            && secret.len() <= 256
            && let Some(expected_hash) = &client.client_secret_hash
        {
            let provided_hash = Self::token_hash(secret);
            return crate::util::constant_time_eq(
                provided_hash.as_bytes(),
                expected_hash.as_bytes(),
            );
        }
        false
    }

    pub(super) async fn has_grant(&self, principal_id: &str, channel_id: &str) -> bool {
        let now = Self::now_ts();
        let principals = self.principals.read().await;
        principals
            .get(principal_id)
            .and_then(|p| p.grants.get(channel_id))
            .is_some_and(|grant| grant.expires_at.is_none_or(|expires_at| expires_at > now))
    }

    pub(super) async fn list_grants(&self, principal_id: &str) -> Vec<ChannelGrant> {
        let now = Self::now_ts();
        let principals = self.principals.read().await;
        principals
            .get(principal_id)
            .map(|value| {
                value
                    .grants
                    .values()
                    .filter(|grant| grant.expires_at.is_none_or(|expires_at| expires_at > now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(super) async fn prune_oauth_runtime_locked(&self, now: i64) {
        self.auth_codes
            .write()
            .await
            .retain(|_, code| code.is_active(now));
        self.refresh_tokens
            .write()
            .await
            .retain(|_, token| token.family_expires_at > now);
        self.bind_sessions
            .write()
            .await
            .retain(|_, session| session.expires_at.saturating_add(3_600) > now);

        let mut referenced_principals = self
            .auth_codes
            .read()
            .await
            .values()
            .map(|code| code.principal_id.clone())
            .collect::<HashSet<_>>();
        referenced_principals.extend(
            self.refresh_tokens
                .read()
                .await
                .values()
                .map(|token| token.principal_id.clone()),
        );
        self.principals
            .write()
            .await
            .retain(|principal_id, principal| {
                !principal.grants.is_empty() && referenced_principals.contains(principal_id)
            });
    }

    pub(super) async fn remove_grant(
        &self,
        principal_id: &str,
        channel_id: &str,
    ) -> StoreResult<bool> {
        let _mutation = self.mutation.lock().await;
        if !self.oauth_ready() {
            return Err(StoreError::Io(std::io::Error::other(
                "OAuth state is unavailable",
            )));
        }
        let mut principals = self.principals.write().await;
        let Some(principal) = principals.get_mut(principal_id) else {
            return Ok(false);
        };
        let removed = principal.grants.remove(channel_id).is_some();
        drop(principals);
        if removed {
            self.persist_snapshot_locked().await?;
        }
        Ok(removed)
    }

    pub(super) async fn persist_snapshot(&self) -> StoreResult<()> {
        let _mutation = self.mutation.lock().await;
        self.persist_snapshot_locked().await
    }

    pub(super) async fn persist_snapshot_locked(&self) -> StoreResult<()> {
        let mut snapshot = McpSnapshot {
            oauth_runtime: Some(OAuthRuntimeSnapshot {
                oauth_issuer: self.oauth_issuer.to_string(),
                oauth_signing_key: self.oauth_signing_key.to_string(),
            }),
            oauth_clients: self.oauth_clients.read().await.clone(),
            principals: self.principals.read().await.clone(),
            auth_codes: self.auth_codes.read().await.clone(),
            refresh_tokens: self.refresh_tokens.read().await.clone(),
            bind_sessions: self.bind_sessions.read().await.clone(),
        };
        snapshot.prune(Self::now_ts());
        snapshot.save_to(&self.store).await.inspect_err(|err| {
            self.persistence_healthy.store(false, Ordering::Release);
            let error_fingerprint = Self::token_hash(&err.to_string());
            ::tracing::error!(
                target: "gateway.trace_event",
                event = "mcp.state_persist_failed",
                error_kind = %"store_error",
                error_fingerprint = %(&error_fingerprint[..16])
            );
        })
    }

    #[cfg(test)]
    pub(crate) async fn refresh_token_state_for_test(
        &self,
        raw_token: &str,
    ) -> Option<(String, i64, bool)> {
        let token_hash = Self::token_hash(raw_token);
        self.refresh_tokens
            .read()
            .await
            .get(&token_hash)
            .map(|token| {
                (
                    token.family_id.clone(),
                    token.family_expires_at,
                    token.revoked,
                )
            })
    }

    #[cfg(test)]
    pub(crate) async fn refresh_family_all_revoked_for_test(&self, family_id: &str) -> bool {
        let refresh_tokens = self.refresh_tokens.read().await;
        let mut found = false;
        let all_revoked = refresh_tokens
            .values()
            .filter(|token| token.family_id == family_id)
            .all(|token| {
                found = true;
                token.revoked
            });
        found && all_revoked
    }
}

#[cfg(test)]
mod tests {
    use super::McpState;

    #[test]
    fn non_loopback_mcp_requires_public_base_url() {
        let error = McpState::bootstrap_issuer(None, "0.0.0.0:6666")
            .expect_err("public issuer must be explicit");
        assert!(error.to_string().contains("PUSHGO_PUBLIC_BASE_URL"));
    }

    #[test]
    fn loopback_mcp_uses_fixed_bootstrap_issuer() {
        assert_eq!(
            McpState::bootstrap_issuer(None, "127.0.0.1:6666").expect("loopback issuer"),
            "http://127.0.0.1:6666"
        );
    }
}
