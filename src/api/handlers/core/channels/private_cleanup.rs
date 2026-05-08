use std::collections::HashSet;

use crate::{
    api::{Error, format_channel_id},
    app::AppState,
    private::{PrivateState, protocol::PrivatePayloadEnvelope as ProviderPullEnvelope},
};

pub(super) async fn clear_private_pending_for_channel(
    state: &AppState,
    private_state: &PrivateState,
    device_id: [u8; 16],
    channel_id: [u8; 16],
) -> Result<usize, Error> {
    let mut singleton = HashSet::with_capacity(1);
    singleton.insert(channel_id);
    clear_private_pending_for_channels(state, private_state, device_id, &singleton).await
}

pub(super) async fn clear_private_pending_for_channels(
    state: &AppState,
    private_state: &PrivateState,
    device_id: [u8; 16],
    channel_ids: &HashSet<[u8; 16]>,
) -> Result<usize, Error> {
    let span = tracing::info_span!(
        "gateway.channel.private_pending_cleanup",
        channels = channel_ids.len()
    );
    let fut = async move {
        if channel_ids.is_empty() {
            return Ok(0);
        }
        const MAX_PENDING_SCAN_PER_UNSUBSCRIBE: usize = 200_000;
        let expected_channel_ids: HashSet<String> =
            channel_ids.iter().map(format_channel_id).collect();
        let entries = state
            .store
            .list_private_outbox(device_id, MAX_PENDING_SCAN_PER_UNSUBSCRIBE)
            .await?;
        let mut cleared = 0usize;
        let mut skipped_decode = 0usize;
        let mut skipped_version = 0usize;
        for entry in entries {
            let Some(message) = state
                .store
                .load_private_message(entry.delivery_id.as_str())
                .await?
            else {
                continue;
            };
            let envelope = match ProviderPullEnvelope::decode_postcard(&message.payload) {
                Some(value) => value,
                None => {
                    skipped_decode = skipped_decode.saturating_add(1);
                    continue;
                }
            };
            if !envelope.is_supported_version() {
                skipped_version = skipped_version.saturating_add(1);
                continue;
            }
            let payload_channel_id = envelope
                .data
                .get("channel_id")
                .map(String::as_str)
                .map(str::trim)
                .unwrap_or_default();
            if !expected_channel_ids.contains(payload_channel_id) {
                continue;
            }
            let _ = private_state
                .complete_terminal_delivery(device_id, entry.delivery_id.as_str(), None)
                .await?;
            cleared = cleared.saturating_add(1);
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "channel.private_pending_cleanup_completed",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            channels = (channel_ids.len() as u64),
            cleared = (cleared as u64),
            skipped_decode = (skipped_decode as u64),
            skipped_version = (skipped_version as u64)
        );
        Ok(cleared)
    };
    tracing::Instrument::instrument(fut, span)
        .await
        .inspect_err(|err: &Error| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "channel.private_pending_cleanup_failed",
                error = %(err.to_string())
            );
        })
}
