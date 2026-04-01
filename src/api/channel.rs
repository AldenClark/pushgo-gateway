use crate::{
    api::Error,
    util::{decode_crockford_base32_128, encode_crockford_base32_128},
};

const MAX_CHANNEL_ALIAS_LEN: usize = 128;
const MIN_CHANNEL_PASSWORD_LEN: usize = 8;
const MAX_CHANNEL_PASSWORD_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ChannelId([u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelAlias<'a>(&'a str);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelPassword<'a>(&'a str);

impl ChannelId {
    pub(crate) fn parse(raw: &str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("channel id must not be empty"));
        }
        decode_crockford_base32_128(trimmed)
            .map(Self)
            .map_err(|_| Error::validation("invalid channel id"))
    }

    pub(crate) fn into_inner(self) -> [u8; 16] {
        self.0
    }
}

impl From<[u8; 16]> for ChannelId {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&encode_crockford_base32_128(&self.0))
    }
}

impl<'a> ChannelAlias<'a> {
    pub(crate) fn parse(raw: &'a str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("channel name must not be empty"));
        }
        let len = trimmed.chars().count();
        if len > MAX_CHANNEL_ALIAS_LEN {
            return Err(Error::validation("channel name too long (max 128)"));
        }
        if trimmed.chars().any(|ch| ch.is_control()) {
            return Err(Error::validation(
                "channel name contains invalid characters",
            ));
        }
        Ok(Self(trimmed))
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }

    pub(crate) fn into_owned(self) -> String {
        self.0.to_string()
    }
}

impl<'a> ChannelPassword<'a> {
    pub(crate) fn parse(raw: &'a str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        let len = trimmed.len();
        if !(MIN_CHANNEL_PASSWORD_LEN..=MAX_CHANNEL_PASSWORD_LEN).contains(&len) {
            return Err(Error::validation(
                "channel password length must be between 8 and 128",
            ));
        }
        Ok(Self(trimmed))
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }
}

pub(crate) fn parse_channel_id(raw: &str) -> Result<[u8; 16], Error> {
    ChannelId::parse(raw).map(ChannelId::into_inner)
}

pub(crate) fn format_channel_id(channel_id: &[u8; 16]) -> String {
    ChannelId::from(*channel_id).to_string()
}

pub(crate) fn validate_channel_password(raw: &str) -> Result<&str, Error> {
    ChannelPassword::parse(raw).map(ChannelPassword::as_str)
}

#[cfg(test)]
mod tests {
    use super::{ChannelAlias, ChannelId, ChannelPassword};

    #[test]
    fn channel_id_rejects_empty_or_invalid_input() {
        assert!(ChannelId::parse(" ").is_err());
        assert!(ChannelId::parse("not-a-channel").is_err());
    }

    #[test]
    fn channel_id_round_trips_through_display() {
        let parsed = ChannelId::parse("06J0FZG1Y8XGG14VTQ4Y3G10MR").expect("valid id");
        assert_eq!(parsed.to_string(), "06J0FZG1Y8XGG14VTQ4Y3G10MR");
    }

    #[test]
    fn channel_alias_trims_and_rejects_invalid_values() {
        let alias = ChannelAlias::parse("  production channel  ").expect("valid alias");
        assert_eq!(alias.as_str(), "production channel");
        assert!(ChannelAlias::parse(" ").is_err());
        assert!(ChannelAlias::parse("bad\nname").is_err());
    }

    #[test]
    fn channel_password_trims_and_enforces_length_bounds() {
        let password = ChannelPassword::parse("  pass-1234  ").expect("valid password");
        assert_eq!(password.as_str(), "pass-1234");
        assert!(ChannelPassword::parse("short").is_err());
        assert!(ChannelPassword::parse(&"x".repeat(129)).is_err());
    }
}
