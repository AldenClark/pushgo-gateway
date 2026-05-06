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

    pub(crate) fn parse_for_platform(raw: &'a str, platform: Platform) -> ValueResult<Self> {
        let token = Self::parse(raw)?;
        token.validate_for_platform(platform)
    }

    pub(crate) fn validate_for_platform(self, platform: Platform) -> ValueResult<Self> {
        DeviceInfo::from_token(platform, self.0)
            .map_err(|_| ValueError::new("invalid provider_token"))?;
        Ok(self)
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }

    pub(crate) fn into_owned(self) -> String {
        self.0.to_string()
    }
}
