use crate::api::Error;

pub(crate) use crate::value::{ChannelAlias, ChannelId, ChannelPassword};

pub(crate) fn parse_channel_id(raw: &str) -> Result<[u8; 16], Error> {
    Ok(ChannelId::parse(raw).map(ChannelId::into_inner)?)
}

pub(crate) fn format_channel_id(channel_id: &[u8; 16]) -> String {
    ChannelId::from(*channel_id).to_string()
}

pub(crate) fn validate_channel_password(raw: &str) -> Result<&str, Error> {
    Ok(ChannelPassword::parse(raw).map(ChannelPassword::as_str)?)
}
