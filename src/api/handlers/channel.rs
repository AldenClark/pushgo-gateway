use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        ApiJson, Error, HttpResult, format_channel_id, normalize_channel_alias, parse_channel_id,
        validate_channel_password,
    },
    app::AppState,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelExistsQuery {
    channel_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelExistsResponse {
    channel_id: String,
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_name: Option<String>,
}

pub(crate) async fn channel_exists(
    State(state): State<AppState>,
    Query(query): Query<ChannelExistsQuery>,
) -> HttpResult {
    if !state
        .api_rate_limiter
        .allow_channel(query.channel_id.as_str())
    {
        return Err(Error::TooBusy);
    }
    let channel_id = parse_channel_id(&query.channel_id)?;
    let info = state.store.channel_info_async(channel_id).await?;
    Ok(crate::api::ok(ChannelExistsResponse {
        channel_id: format_channel_id(&channel_id),
        exists: info.is_some(),
        channel_name: info.map(|meta| meta.alias),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelRenameData {
    channel_id: String,
    channel_name: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub(super) struct ChannelRenameResponse {
    channel_id: String,
    channel_name: String,
}

pub(crate) async fn channel_rename(
    State(state): State<AppState>,
    ApiJson(payload): ApiJson<ChannelRenameData>,
) -> HttpResult {
    if !state
        .api_rate_limiter
        .allow_channel(payload.channel_id.as_str())
    {
        return Err(Error::TooBusy);
    }
    let channel_id = parse_channel_id(&payload.channel_id)?;
    let channel_name = normalize_channel_alias(&payload.channel_name)?;
    let password = validate_channel_password(&payload.password)?;

    state
        .store
        .rename_channel_async(channel_id, password, &channel_name)
        .await?;

    Ok(crate::api::ok(ChannelRenameResponse {
        channel_id: format_channel_id(&channel_id),
        channel_name,
    }))
}
