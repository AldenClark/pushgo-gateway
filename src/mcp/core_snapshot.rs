use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::storage::Storage;

use super::{AuthCode, BindSession, OAuthClient, Principal, RefreshToken};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OAuthRuntimeSnapshot {
    pub oauth_issuer: String,
    pub oauth_signing_key: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct McpSnapshot {
    #[serde(default)]
    pub oauth_runtime: Option<OAuthRuntimeSnapshot>,
    #[serde(default)]
    pub oauth_clients: HashMap<String, OAuthClient>,
    pub principals: HashMap<String, Principal>,
    pub auth_codes: HashMap<String, AuthCode>,
    pub refresh_tokens: HashMap<String, RefreshToken>,
    pub bind_sessions: HashMap<String, BindSession>,
}

impl McpSnapshot {
    pub(super) async fn load_from(store: &Storage) -> Self {
        let Ok(Some(content)) = store.load_mcp_state_json().await else {
            return Self::default();
        };
        serde_json::from_str::<Self>(&content).unwrap_or_default()
    }

    pub(super) async fn save_to(&self, store: &Storage) {
        if let Ok(encoded) = serde_json::to_string(self) {
            let _ = store.save_mcp_state_json(&encoded).await;
        }
    }
}
