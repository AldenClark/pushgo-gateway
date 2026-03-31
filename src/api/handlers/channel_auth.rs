use crate::{
    api::{Error, format_channel_id, parse_channel_id, validate_channel_password},
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
    let channel_id = parse_channel_id(channel_id_raw)?;
    let password = validate_channel_password(password_raw)?;
    state
        .store
        .channel_info_with_password(channel_id, password)
        .await?
        .ok_or(StoreError::ChannelNotFound)?;
    Ok(AuthorizedChannel {
        channel_id,
        channel_scope: format_channel_id(&channel_id),
    })
}

pub(crate) async fn authorize_channel_exists(
    state: &AppState,
    channel_id_raw: &str,
) -> Result<AuthorizedChannel, Error> {
    let channel_id = parse_channel_id(channel_id_raw)?;
    state
        .store
        .channel_info(channel_id)
        .await?
        .ok_or(StoreError::ChannelNotFound)?;
    Ok(AuthorizedChannel {
        channel_id,
        channel_scope: format_channel_id(&channel_id),
    })
}
