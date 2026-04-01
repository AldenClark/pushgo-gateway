use crate::{
    api::{ChannelId, ChannelPassword, Error},
    app::AppState,
    storage::StoreError,
};

#[derive(Debug, Clone)]
pub(crate) struct AuthorizedChannel {
    pub channel_id: [u8; 16],
    pub channel_scope: String,
}

pub(crate) async fn authorize_channel_by_password(
    state: &AppState,
    channel_id_raw: &str,
    password_raw: &str,
) -> Result<AuthorizedChannel, Error> {
    let channel_id = ChannelId::parse(channel_id_raw)?;
    let password = ChannelPassword::parse(password_raw)?;
    state
        .store
        .channel_info_with_password(channel_id.into_inner(), password.as_str())
        .await?
        .ok_or(StoreError::ChannelNotFound)?;
    Ok(AuthorizedChannel {
        channel_id: channel_id.into_inner(),
        channel_scope: channel_id.to_string(),
    })
}

pub(crate) async fn authorize_channel_exists(
    state: &AppState,
    channel_id_raw: &str,
) -> Result<AuthorizedChannel, Error> {
    let channel_id = ChannelId::parse(channel_id_raw)?;
    state
        .store
        .channel_info(channel_id.into_inner())
        .await?
        .ok_or(StoreError::ChannelNotFound)?;
    Ok(AuthorizedChannel {
        channel_id: channel_id.into_inner(),
        channel_scope: channel_id.to_string(),
    })
}
