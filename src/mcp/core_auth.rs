use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};

use crate::api::Error;

use super::{McpState, core_types::McpScopeSet};

#[derive(Debug, Clone)]
pub(super) enum McpAuthContext {
    OAuth {
        principal_id: String,
        scope: McpScopeSet,
    },
    Legacy,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub scope: McpScopeSet,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Clone)]
struct BearerToken(String);

impl BearerToken {
    fn parse(headers: &HeaderMap) -> Option<Self> {
        let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
        let mut parts = value.split_whitespace();
        let scheme = parts.next()?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = parts.next()?;
        if parts.next().is_some() || token.is_empty() {
            return None;
        }
        Some(Self(token.to_string()))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl McpState {
    pub(super) async fn authenticate(&self, headers: &HeaderMap) -> Result<McpAuthContext, Error> {
        let token = BearerToken::parse(headers).ok_or(Error::Unauthorized)?;

        if let Some(auth) = self.authenticate_oauth_token(&token).await {
            return Ok(auth);
        }
        if self.authenticate_legacy_token(&token) {
            return Ok(McpAuthContext::Legacy);
        }
        Err(Error::Unauthorized)
    }

    pub(super) fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs() as i64)
            .unwrap_or(0)
    }

    pub(super) fn random_id(prefix: &str) -> String {
        format!(
            "{prefix}_{}",
            Alphanumeric.sample_string(&mut rand::rng(), 24)
        )
    }

    pub(super) fn token_hash(raw: &str) -> String {
        blake3::hash(raw.as_bytes()).to_hex().to_string()
    }

    async fn authenticate_oauth_token(&self, token: &BearerToken) -> Option<McpAuthContext> {
        if !self.oauth_ready() {
            return None;
        }
        let signing_key = self.oauth_signing_key().await;
        let issuer = self.oauth_issuer().await;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["mcp"]);
        validation.set_issuer(&[issuer.as_str()]);
        if let Ok(decoded) = decode::<AccessClaims>(
            token.as_str(),
            &DecodingKey::from_secret(signing_key.as_bytes()),
            &validation,
        ) {
            return Some(McpAuthContext::OAuth {
                principal_id: decoded.claims.sub,
                scope: decoded.claims.scope,
            });
        }
        None
    }

    fn authenticate_legacy_token(&self, token: &BearerToken) -> bool {
        if let Some(shared) = &self.shared_token
            && crate::util::constant_time_eq(token.as_str().as_bytes(), shared.as_bytes())
        {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::BearerToken;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};

    #[test]
    fn bearer_token_parses_valid_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token-123"));
        let token = BearerToken::parse(&headers).expect("bearer token should parse");
        assert_eq!(token.as_str(), "token-123");
    }

    #[test]
    fn bearer_token_rejects_invalid_shape() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic token-123"));
        assert!(BearerToken::parse(&headers).is_none());
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer"));
        assert!(BearerToken::parse(&headers).is_none());
    }
}
