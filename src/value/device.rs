use crate::storage::{DeviceInfo, Platform};

use super::{ValueError, ValueResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DeviceKeyRef<'a>(&'a str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderTokenRef<'a>(&'a str);

impl<'a> DeviceKeyRef<'a> {
    pub(crate) fn parse(raw: &'a str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new("device_key is required"));
        }
        Ok(Self(trimmed))
    }

    pub(crate) fn optional(raw: Option<&'a str>) -> Option<Self> {
        raw.and_then(|value| Self::parse(value).ok())
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }

    pub(crate) fn into_owned(self) -> String {
        self.0.to_string()
    }
}

impl<'a> ProviderTokenRef<'a> {
    pub(crate) fn parse(raw: &'a str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new("provider_token is required"));
        }
        Ok(Self(trimmed))
    }

    pub(crate) fn optional(raw: Option<&'a str>) -> Option<Self> {
        raw.and_then(|value| Self::parse(value).ok())
    }

    pub(crate) fn canonicalize_for_platform(
        raw: &'a str,
        platform: Platform,
    ) -> ValueResult<String> {
        let token = Self::parse(raw)?;
        let device = DeviceInfo::from_token(platform, token.as_str())
            .map_err(|_| ValueError::new("invalid provider_token"))?;
        Ok(device.token_str().to_string())
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }

    pub(crate) fn into_owned(self) -> String {
        self.0.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderTokenRef;
    use crate::storage::Platform;

    #[test]
    fn provider_token_canonicalization_is_platform_specific() {
        let apple_upper = "A1".repeat(32);
        assert_eq!(
            ProviderTokenRef::canonicalize_for_platform(&apple_upper, Platform::IOS)
                .expect("valid APNs token"),
            "a1".repeat(32)
        );

        let mixed_case = "AbCdEfGhIjKlMnOp";
        assert_eq!(
            ProviderTokenRef::canonicalize_for_platform(mixed_case, Platform::ANDROID)
                .expect("valid FCM token"),
            mixed_case
        );
        assert_eq!(
            ProviderTokenRef::canonicalize_for_platform(mixed_case, Platform::WINDOWS)
                .expect("valid WNS token"),
            mixed_case
        );
    }
}
