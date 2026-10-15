//! Credential ownership stays with the injected token provider. This seam has
//! no cache, token-service URL, signer, or network client of its own.
use crate::transport::BoxFuture;
use std::sync::Arc;

/// Categorical errors deliberately cannot carry credentials or service URLs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialError {
    #[error("provider credential acquisition unavailable")]
    Unavailable,
    #[error("provider credential data invalid")]
    Invalid,
}

// No Debug: accidental diagnostic formatting must not expose access tokens.
#[derive(Clone)]
pub struct FcmCredential {
    pub(crate) project_id: Arc<str>,
    pub(crate) access_token: Arc<str>,
}

impl FcmCredential {
    pub fn new(project_id: &str, access_token: &str) -> Result<Self, CredentialError> {
        // A project is one path segment, never an endpoint or query parameter.
        if project_id.is_empty()
            || project_id.len() > 128
            || matches!(project_id, "." | "..")
            || !project_id
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-_.:".contains(&v))
        {
            return Err(CredentialError::Invalid);
        }
        validate_token(access_token)?;
        Ok(Self {
            project_id: Arc::from(project_id),
            access_token: Arc::from(access_token),
        })
    }
}

#[derive(Clone)]
pub struct ApnsCredential {
    pub(crate) access_token: Arc<str>,
}

impl ApnsCredential {
    pub fn new(access_token: &str) -> Result<Self, CredentialError> {
        validate_token(access_token)?;
        Ok(Self {
            access_token: Arc::from(access_token),
        })
    }
}

fn validate_token(token: &str) -> Result<(), CredentialError> {
    if token.is_empty()
        || token.len() > 16 * 1024
        || !token.bytes().all(|v| (33..=126).contains(&v))
    {
        return Err(CredentialError::Invalid);
    }
    Ok(())
}

/// `false` maps to mainline `token_info`; `true` maps to FCM
/// `token_info_fresh` or APNs `refresh_now`. The implementation retains the
/// existing token-service cache owner and must not hold a lock across await.
/// A refresh prepares the next durable attempt; it never authorizes an inline
/// provider resend. Both methods return only the current credential snapshot.
pub trait CredentialProvider: Send + Sync {
    fn fcm<'a>(
        &'a self,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<FcmCredential, CredentialError>>;
    fn apns<'a>(
        &'a self,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<ApnsCredential, CredentialError>>;
}

/// Adapts the production Gateway credential contracts without owning another
/// cache, signer, HTTP client, or token-service protocol. The injected owners
/// retain their refresh lifecycle; this adapter only validates a wire snapshot.
pub struct ExistingTokenCredentials {
    fcm: Arc<dyn pushgo_gateway::providers::FcmTokenProvider>,
    apns: Arc<dyn pushgo_gateway::providers::ApnsTokenProvider>,
}

impl ExistingTokenCredentials {
    /// Use the Gateway's actual Remote owners and Token Service client policy.
    /// Callers select the service explicitly; this never reads configuration.
    pub fn remote(token_service_url: &str) -> Result<Self, CredentialError> {
        let client = pushgo_gateway::token_service_http_client()
            .map_err(|_| CredentialError::Unavailable)?;
        Ok(Self::new(
            pushgo_gateway::remote_fcm_token_provider(token_service_url, client.clone()),
            pushgo_gateway::remote_apns_token_provider(token_service_url, client),
        ))
    }

    /// Explicit synthetic entrypoint: credentials can only be acquired from a
    /// loopback HTTP Token Service. No environment/configuration is consulted.
    pub fn loopback_remote(token_service_url: &str) -> Result<Self, CredentialError> {
        let url = reqwest::Url::parse(token_service_url).map_err(|_| CredentialError::Invalid)?;
        let ip = url.host_str().and_then(|value| {
            value
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        });
        if url.scheme() != "http"
            || !ip.is_some_and(|ip| ip.is_loopback())
            || url.port().is_none_or(|port| port == 0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(CredentialError::Invalid);
        }
        Self::remote(token_service_url)
    }

    pub fn new(
        fcm: Arc<dyn pushgo_gateway::providers::FcmTokenProvider>,
        apns: Arc<dyn pushgo_gateway::providers::ApnsTokenProvider>,
    ) -> Self {
        Self { fcm, apns }
    }
}

impl CredentialProvider for ExistingTokenCredentials {
    fn fcm<'a>(
        &'a self,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<FcmCredential, CredentialError>> {
        Box::pin(async move {
            let access = if force_refresh {
                self.fcm.token_info_fresh().await
            } else {
                self.fcm.token_info().await
            }
            .map_err(|_| CredentialError::Unavailable)?;
            FcmCredential::new(&access.project_id, &access.token.token)
        })
    }

    fn apns<'a>(
        &'a self,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<ApnsCredential, CredentialError>> {
        Box::pin(async move {
            let token = if force_refresh {
                self.apns.refresh_now().await
            } else {
                self.apns.token_info().await.map(|info| info.token)
            }
            .map_err(|_| CredentialError::Unavailable)?;
            ApnsCredential::new(&token)
        })
    }
}

/// Synthetic credentials for the explicitly loopback-only provider transport.
pub struct FixtureCredentials;

impl CredentialProvider for FixtureCredentials {
    fn fcm<'a>(
        &'a self,
        _force_refresh: bool,
    ) -> BoxFuture<'a, Result<FcmCredential, CredentialError>> {
        Box::pin(async { FcmCredential::new("fixture-project", "fixture-local-only") })
    }
    fn apns<'a>(
        &'a self,
        _force_refresh: bool,
    ) -> BoxFuture<'a, Result<ApnsCredential, CredentialError>> {
        Box::pin(async { ApnsCredential::new("fixture-local-only") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_cannot_supply_a_url_path_query_or_invalid_header() {
        for project in [
            "",
            ".",
            "..",
            "a/b",
            "a?key=token",
            "a#fragment",
            "https://endpoint.invalid",
        ] {
            assert!(matches!(
                FcmCredential::new(project, "synthetic"),
                Err(CredentialError::Invalid)
            ));
        }
        for token in [
            "",
            "synthetic\r\ninjected: secret",
            "synthetic token",
            "合成",
        ] {
            assert!(matches!(
                ApnsCredential::new(token),
                Err(CredentialError::Invalid)
            ));
        }
        assert!(FcmCredential::new("synthetic-project", "synthetic.token-1").is_ok());
        assert!(matches!(
            ApnsCredential::new(&"x".repeat(16 * 1024 + 1)),
            Err(CredentialError::Invalid)
        ));
    }
}
