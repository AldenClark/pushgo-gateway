use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiJson, ChannelAlias, ChannelId, ChannelPassword, HttpResult},
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
    let span = tracing::info_span!("gateway.channel.exists");
    let fut = async move {
        let channel_id = ChannelId::parse(&query.channel_id)?;
        let info = state.store.channel_info(channel_id.into_inner()).await?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "channel.exists_completed",
            channel_id = %(crate::util::redact_text(channel_id.to_string())),
            exists = (info.is_some())
        );
        Ok(crate::api::ok(ChannelExistsResponse {
            channel_id: channel_id.to_string(),
            exists: info.is_some(),
            channel_name: info.map(|meta| meta.alias),
        }))
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &crate::api::Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.exists_failed",
                error = %(err.to_string())
            );
        })
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
    let span = tracing::info_span!("gateway.channel.rename");
    let fut = async move {
        let channel_id = ChannelId::parse(&payload.channel_id)?;
        let channel_name = ChannelAlias::parse(&payload.channel_name)?;
        let password = ChannelPassword::parse(&payload.password)?;

        state
            .store
            .rename_channel(
                channel_id.into_inner(),
                password.as_str(),
                channel_name.as_str(),
            )
            .await?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "channel.rename_completed",
            channel_id = %(crate::util::redact_text(channel_id.to_string())),
            channel_name = %(channel_name.as_str())
        );

        Ok(crate::api::ok(ChannelRenameResponse {
            channel_id: channel_id.to_string(),
            channel_name: channel_name.into_owned(),
        }))
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &crate::api::Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.rename_failed",
                error = %(err.to_string())
            );
        })
}
