use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

use pushgo_gateway::{
    Error,
    providers::{ApnsTokenProvider as ApnsTokenProviderTrait, BoxFuture, TokenInfo},
    util::is_sandbox_mode,
};

use crate::provider_config::ApnsConfig;

const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
struct TokenState {
    token: Arc<str>,
    created_at: std::time::Instant,
}

#[derive(Debug)]
struct ApnsTokenCache {
    state: Arc<ArcSwap<TokenState>>,
    auth: Arc<ApnsAuth>,
}

impl ApnsTokenCache {
    fn init(auth: Arc<ApnsAuth>) -> Self {
        // Start empty to force a refresh on first use.
        let initial = TokenState {
            token: Arc::from(""),
            created_at: std::time::Instant::now() - TOKEN_TTL,
        };
        Self {
            state: Arc::new(ArcSwap::from_pointee(initial)),
            auth,
        }
    }

    /// Force a new APNs token and update the cache.
    fn refresh_now(&self) -> Result<Arc<str>, Error> {
        let token = generate_token(&self.auth)?;
        let token_arc: Arc<str> = Arc::from(token.into_boxed_str());
        let new_state = TokenState {
            token: Arc::clone(&token_arc),
            created_at: std::time::Instant::now(),
        };
        self.state.store(Arc::new(new_state));
        Ok(token_arc)
    }

    fn token_info(&self) -> Result<TokenInfo, Error> {
        let state = self.state.load();
        let age = state.created_at.elapsed();

        if age < TOKEN_TTL && !state.token.is_empty() {
            let expires_in = TOKEN_TTL.saturating_sub(age).as_secs();
            return Ok(TokenInfo {
                token: Arc::clone(&state.token),
                expires_in,
            });
        }

        let token = generate_token(&self.auth)?;
        let token_arc: Arc<str> = Arc::from(token.into_boxed_str());
        let new_state = TokenState {
            token: Arc::clone(&token_arc),
            created_at: std::time::Instant::now(),
        };

        let current = self.state.load();
        if Arc::ptr_eq(&current, &state) {
            self.state.store(Arc::new(new_state));
        }

        Ok(TokenInfo {
            token: token_arc,
            expires_in: TOKEN_TTL.as_secs(),
        })
    }
}

pub struct ApnsTokenProvider {
    cache: ApnsTokenCache,
    auth: Arc<ApnsAuth>,
}

impl ApnsTokenProvider {
    pub fn new(config: &ApnsConfig) -> Result<Self, Error> {
        let auth = Arc::new(build_apns_auth(config)?);
        let cache = ApnsTokenCache::init(Arc::clone(&auth));
        Ok(Self { cache, auth })
    }

    fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        let token = generate_token(&self.auth)?;
        let token: Arc<str> = Arc::from(token.into_boxed_str());
        Ok(TokenInfo {
            token,
            expires_in: TOKEN_TTL.as_secs(),
        })
    }
}

impl ApnsTokenProviderTrait for ApnsTokenProvider {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.cache.token_info() })
    }

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async move { self.token_info_fresh() })
    }

    fn refresh_now<'a>(&'a self) -> BoxFuture<'a, Result<Arc<str>, Error>> {
        Box::pin(async move { self.cache.refresh_now() })
    }
}

#[derive(Debug)]
struct ApnsAuth {
    team_id: Arc<str>,
    key_id: Arc<str>,
    encoding_key: EncodingKey,
}

fn build_apns_auth(config: &ApnsConfig) -> Result<ApnsAuth, Error> {
    let encoding_key = EncodingKey::from_ec_pem(config.key_pem.as_bytes())
        .map_err(|err| Error::Internal(format!("invalid APNs key_pem: {err}")))?;
    Ok(ApnsAuth {
        team_id: Arc::from(config.team_id.as_str()),
        key_id: Arc::from(config.key_id.as_str()),
        encoding_key,
    })
}

fn generate_token(auth: &ApnsAuth) -> Result<String, Error> {
    let header = Header {
        alg: Algorithm::ES256,
        kid: Some(auth.key_id.to_string()),
        ..Header::default()
    };
    let claims = Claims {
        iss: auth.team_id.as_ref(),
        iat: Utc::now().timestamp(),
    };
    encode(&header, &claims, &auth.encoding_key)
        .map_err(|err| Error::Internal(format!("failed to generate APNs JWT: {err}")))
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: i64,
}
