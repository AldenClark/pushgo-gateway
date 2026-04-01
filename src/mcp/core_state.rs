use std::{collections::HashMap, sync::Arc};

use rand::distr::{Alphanumeric, SampleString};
use tokio::sync::RwLock;

use crate::app::AuthMode;

use super::{ChannelGrant, McpSnapshot, McpState, Principal, core_snapshot::OAuthRuntimeSnapshot};

impl McpState {
    pub(crate) async fn new(
        config: super::McpConfig,
        auth: &AuthMode,
        store: crate::storage::Storage,
    ) -> Self {
        let shared_token = match auth {
            AuthMode::Disabled => None,
            AuthMode::SharedToken(value) => Some(Arc::clone(value)),
        };
        let snapshot = McpSnapshot::load_from(&store).await;
        let runtime_missing = snapshot.oauth_runtime.is_none();
        let mut oauth_clients = snapshot.oauth_clients;
        let (oauth_issuer, oauth_signing_key) = match snapshot.oauth_runtime.as_ref() {
            Some(runtime) => (
                runtime.oauth_issuer.clone(),
                Arc::from(runtime.oauth_signing_key.clone().into_boxed_str()),
            ),
            None => (
                Self::bootstrap_issuer(
                    config.public_base_url.as_deref(),
                    config.bootstrap_http_addr.as_ref(),
                ),
                Arc::from(Self::generate_signing_key().into_boxed_str()),
            ),
        };
        let mut predefined_clients_changed = false;
        for predefined in &config.predefined_clients {
            let client = super::OAuthClient {
                client_id: predefined.client_id.to_string(),
                client_secret_hash: Some(Self::token_hash(predefined.client_secret.as_ref())),
                allow_any_https_redirect_uri: true,
                redirect_uris: Vec::new(),
                token_endpoint_auth_method: "client_secret_post".to_string(),
                created_at: Self::now_ts(),
            };
            match oauth_clients.get(predefined.client_id.as_ref()) {
                Some(existing)
                    if existing.client_secret_hash == client.client_secret_hash
                        && existing.allow_any_https_redirect_uri
                        && existing.token_endpoint_auth_method == "client_secret_post" => {}
                _ => {
                    oauth_clients.insert(predefined.client_id.to_string(), client);
                    predefined_clients_changed = true;
                }
            }
        }
        let state = Self {
            config,
            oauth_issuer: Arc::new(RwLock::new(oauth_issuer)),
            oauth_signing_key,
            store,
            oauth_clients: Arc::new(RwLock::new(oauth_clients)),
            principals: Arc::new(RwLock::new(snapshot.principals)),
            auth_codes: Arc::new(RwLock::new(snapshot.auth_codes)),
            refresh_tokens: Arc::new(RwLock::new(snapshot.refresh_tokens)),
            bind_sessions: Arc::new(RwLock::new(snapshot.bind_sessions)),
            shared_token,
        };
        if runtime_missing || predefined_clients_changed {
            state.persist_snapshot().await;
        }
        state
    }

    pub(super) fn oauth_ready(&self) -> bool {
        true
    }

    fn bootstrap_issuer(public_base_url: Option<&str>, http_addr: &str) -> String {
        if let Some(base_url) = public_base_url {
            return base_url.trim_end_matches('/').to_string();
        }
        let host = http_addr.split(':').next().unwrap_or("127.0.0.1");
        if host == "0.0.0.0" || host == "::" {
            "https://127.0.0.1".to_string()
        } else {
            format!("https://{host}")
        }
    }

    fn generate_signing_key() -> String {
        Alphanumeric.sample_string(&mut rand::rng(), 64)
    }

    pub(super) async fn oauth_issuer(&self) -> String {
        self.oauth_issuer.read().await.clone()
    }

    pub(super) async fn oauth_signing_key(&self) -> Arc<str> {
        Arc::clone(&self.oauth_signing_key)
    }

    pub(super) async fn maybe_update_issuer_from_origin(&self, origin: &str) {
        if self.config.public_base_url.is_some() {
            return;
        }
        if origin.is_empty() || !origin.starts_with("https://") {
            return;
        }
        let mut issuer = self.oauth_issuer.write().await;
        if issuer.as_str() == origin {
            return;
        }
        if issuer.contains("127.0.0.1")
            || issuer.contains("0.0.0.0")
            || issuer.contains("localhost")
        {
            *issuer = origin.to_string();
            drop(issuer);
            self.persist_snapshot().await;
        }
    }

    pub(super) async fn client_redirect_allowed(&self, client_id: &str, redirect_uri: &str) -> bool {
        let clients = self.oauth_clients.read().await;
        clients
            .get(client_id)
            .map(|client| {
                if client.allow_any_https_redirect_uri {
                    redirect_uri.starts_with("https://")
                } else {
                    client.redirect_uris.iter().any(|item| item == redirect_uri)
                }
            })
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
            && let Some(expected_hash) = &client.client_secret_hash
        {
            let provided_hash = Self::token_hash(secret);
            return crate::util::constant_time_eq(provided_hash.as_bytes(), expected_hash.as_bytes());
        }
        false
    }

    pub(super) async fn has_grant(&self, principal_id: &str, channel_id: &str) -> bool {
        let principals = self.principals.read().await;
        principals
            .get(principal_id)
            .and_then(|p| p.grants.get(channel_id))
            .is_some()
    }

    pub(super) async fn list_grants(&self, principal_id: &str) -> Vec<ChannelGrant> {
        let principals = self.principals.read().await;
        principals
            .get(principal_id)
            .map(|value| value.grants.values().cloned().collect())
            .unwrap_or_default()
    }

    pub(super) async fn upsert_grant(
        &self,
        principal_id: &str,
        channel_id: &str,
        expires_at: Option<i64>,
    ) {
        let mut principals = self.principals.write().await;
        let entry = principals
            .entry(principal_id.to_string())
            .or_insert_with(|| Principal {
                principal_id: principal_id.to_string(),
                display_name: None,
                grants: HashMap::new(),
                created_at: McpState::now_ts(),
            });
        entry.grants.insert(
            channel_id.to_string(),
            ChannelGrant {
                channel_id: channel_id.to_string(),
                granted_at: McpState::now_ts(),
                expires_at,
            },
        );
        drop(principals);
        self.persist_snapshot().await;
    }

    pub(super) async fn remove_grant(&self, principal_id: &str, channel_id: &str) -> bool {
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

    pub(super) async fn persist_snapshot(&self) {
        let snapshot = McpSnapshot {
            oauth_runtime: Some(OAuthRuntimeSnapshot {
                oauth_issuer: self.oauth_issuer.read().await.clone(),
                oauth_signing_key: self.oauth_signing_key.to_string(),
            }),
            oauth_clients: self.oauth_clients.read().await.clone(),
            principals: self.principals.read().await.clone(),
            auth_codes: self.auth_codes.read().await.clone(),
            refresh_tokens: self.refresh_tokens.read().await.clone(),
            bind_sessions: self.bind_sessions.read().await.clone(),
        };
        snapshot.save_to(&self.store).await;
    }
}
