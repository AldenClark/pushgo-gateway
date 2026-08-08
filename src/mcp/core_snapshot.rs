use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::storage::{Storage, StoreError, StoreResult};

use super::{AuthCode, BindSession, OAuthClient, Principal, RefreshToken};

pub(super) const MAX_OAUTH_CLIENTS: usize = 1_024;
pub(super) const MAX_PRINCIPALS: usize = 4_096;
pub(super) const MAX_AUTH_CODES: usize = 4_096;
pub(super) const MAX_REFRESH_TOKENS: usize = 8_192;
pub(super) const MAX_REFRESH_TOKENS_PER_FAMILY: usize = 128;
pub(super) const MAX_BIND_SESSIONS: usize = 4_096;
pub(super) const MAX_GRANTS_PER_PRINCIPAL: usize = 128;
const EXPIRED_BIND_SESSION_RETENTION_SECS: i64 = 3_600;
const MAX_MCP_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OAuthRuntimeSnapshot {
    pub oauth_issuer: String,
    pub oauth_signing_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub(super) async fn load_from(store: &Storage) -> StoreResult<Self> {
        let Some(content) = store.load_mcp_state_json().await? else {
            return Ok(Self::default());
        };
        if content.len() > MAX_MCP_SNAPSHOT_BYTES {
            return Err(invalid_snapshot("MCP state snapshot exceeds size limit"));
        }
        let snapshot = serde_json::from_str::<Self>(&content)?;
        if snapshot
            .oauth_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.oauth_signing_key.len() < 32)
        {
            return Err(invalid_snapshot("MCP OAuth signing key is invalid"));
        }
        Ok(snapshot)
    }

    pub(super) async fn save_to(&self, store: &Storage) -> StoreResult<()> {
        let encoded = serde_json::to_string(self)?;
        if encoded.len() > MAX_MCP_SNAPSHOT_BYTES {
            return Err(invalid_snapshot("MCP state snapshot exceeds size limit"));
        }
        store.save_mcp_state_json(&encoded).await
    }

    pub(super) fn prune(&mut self, now: i64) -> bool {
        let before = snapshot_shape(self);
        // Older snapshots used the raw authorization code as the map key.
        // Keep only fixed-width BLAKE3 hashes and unexpired records.
        self.auth_codes
            .retain(|key, code| is_blake3_hex(key) && code.is_active(now));
        self.refresh_tokens.retain(|key, token| {
            if token.family_id.is_empty() {
                token.family_id = token.token_hash.clone();
            }
            is_blake3_hex(key) && token.token_hash == *key && token.family_expires_at > now
        });
        self.bind_sessions.retain(|key, session| {
            is_blake3_hex(key)
                && session
                    .expires_at
                    .saturating_add(EXPIRED_BIND_SESSION_RETENTION_SECS)
                    > now
        });
        for principal in self.principals.values_mut() {
            principal
                .grants
                .retain(|_, grant| grant.expires_at.is_none_or(|expires_at| expires_at > now));
            retain_newest(&mut principal.grants, MAX_GRANTS_PER_PRINCIPAL, |grant| {
                grant.granted_at
            });
        }
        let mut referenced_principals = self
            .auth_codes
            .values()
            .map(|code| code.principal_id.clone())
            .collect::<std::collections::HashSet<_>>();
        referenced_principals.extend(
            self.refresh_tokens
                .values()
                .map(|token| token.principal_id.clone()),
        );
        self.principals.retain(|principal_id, principal| {
            !principal.grants.is_empty() && referenced_principals.contains(principal_id)
        });

        retain_newest(&mut self.oauth_clients, MAX_OAUTH_CLIENTS, |client| {
            client.created_at
        });
        retain_newest(&mut self.principals, MAX_PRINCIPALS, |principal| {
            principal.created_at
        });
        retain_newest(&mut self.auth_codes, MAX_AUTH_CODES, |code| code.expires_at);
        retain_newest(&mut self.refresh_tokens, MAX_REFRESH_TOKENS, |token| {
            token.family_expires_at
        });
        retain_refresh_family_limits(&mut self.refresh_tokens);
        retain_newest(&mut self.bind_sessions, MAX_BIND_SESSIONS, |session| {
            session.expires_at
        });
        before != snapshot_shape(self)
    }
}

fn is_blake3_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn retain_refresh_family_limits(values: &mut HashMap<String, RefreshToken>) {
    let mut by_family = HashMap::<String, Vec<(String, i64)>>::new();
    for (key, token) in values.iter() {
        by_family
            .entry(token.family_id.clone())
            .or_default()
            .push((key.clone(), token.idle_expires_at));
    }
    let mut remove = std::collections::HashSet::new();
    let mut revoke_families = std::collections::HashSet::new();
    for family in by_family.values_mut() {
        if family.len() > MAX_REFRESH_TOKENS_PER_FAMILY {
            for (key, _) in family.iter() {
                if let Some(token) = values.get(key) {
                    revoke_families.insert(token.family_id.clone());
                    break;
                }
            }
        }
        family.sort_unstable_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
        });
        for (key, _) in family.iter().skip(MAX_REFRESH_TOKENS_PER_FAMILY) {
            remove.insert(key.clone());
        }
    }
    for token in values.values_mut() {
        if revoke_families.contains(&token.family_id) {
            token.revoke();
        }
    }
    values.retain(|key, _| !remove.contains(key));
}

fn snapshot_shape(snapshot: &McpSnapshot) -> (usize, usize, usize, usize, usize, usize, usize) {
    let empty_refresh_families = snapshot
        .refresh_tokens
        .values()
        .filter(|token| token.family_id.is_empty())
        .count();
    (
        snapshot.oauth_clients.len(),
        snapshot.principals.len(),
        snapshot
            .principals
            .values()
            .map(|principal| principal.grants.len())
            .sum(),
        snapshot.auth_codes.len(),
        snapshot.refresh_tokens.len(),
        snapshot.bind_sessions.len(),
        empty_refresh_families,
    )
}

fn invalid_snapshot(message: &'static str) -> StoreError {
    StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

fn retain_newest<T>(values: &mut HashMap<String, T>, limit: usize, timestamp: impl Fn(&T) -> i64) {
    if values.len() <= limit {
        return;
    }
    let mut ordered = values
        .iter()
        .map(|(key, value)| (key.clone(), timestamp(value)))
        .collect::<Vec<_>>();
    ordered.sort_unstable_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ordered.truncate(limit);
    let retained = ordered
        .into_iter()
        .map(|(key, _)| key)
        .collect::<std::collections::HashSet<_>>();
    values.retain(|key, _| retained.contains(key));
}
