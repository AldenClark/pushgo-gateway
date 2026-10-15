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
