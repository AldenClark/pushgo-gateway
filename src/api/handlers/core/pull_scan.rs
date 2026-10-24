//! Bounded read traversal of the two existing authorities. A position never
//! acknowledges, defers, deletes, or transfers a delivery responsibility.
use super::{PullItem, V2_PULL_LIMIT, V2PullResponse, is_retained_model};
use crate::{
    api::Error,
    app::AppState,
    private::protocol::PrivatePayloadEnvelope,
    routing::derive_private_device_id,
    storage::{ProviderPullCandidate, ProviderPullPosition},
    value::DeviceKeyRef,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

const MAX_PAGE_TOKEN_BYTES: usize = 2_048;
const MAX_DELIVERY_KEY_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    Ordinary,
    Retained,
}
impl Source {
    fn other(self) -> Self {
        match self {
            Self::Ordinary => Self::Retained,
            Self::Retained => Self::Ordinary,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    after: Option<ProviderPullPosition>,
    ceiling: Option<ProviderPullPosition>,
}
impl Window {
    fn complete(&self) -> bool {
        self.ceiling
            .as_ref()
            .is_none_or(|ceiling| self.after.as_ref().is_some_and(|after| after == ceiling))
    }
    fn valid(&self) -> bool {
        let key_valid = |key: &ProviderPullPosition| {
            !key.delivery_id.is_empty() && key.delivery_id.len() <= MAX_DELIVERY_KEY_BYTES
        };
        self.after.as_ref().is_none_or(key_valid)
            && self.ceiling.as_ref().is_none_or(key_valid)
            && match (&self.after, &self.ceiling) {
                // ID tie ordering belongs to the native database collation.
                // Equality/exhaustion, not Rust byte order, closes the window.
                (Some(after), Some(ceiling)) => after.at <= ceiling.at,
                (Some(_), None) => false,
                _ => true,
            }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageToken {
    version: u8,
    scope: String,
    ordinary: Window,
    retained: Window,
    next_source: Source,
}
impl PageToken {
    fn complete(&self) -> bool {
        self.ordinary.complete() && self.retained.complete()
    }
    fn decode(raw: &str, scope: &str) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_PAGE_TOKEN_BYTES {
            return Err(invalid_token());
        }
        let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid_token())?;
        let token: Self = serde_json::from_slice(&bytes).map_err(|_| invalid_token())?;
        if token.version != 1
            || token.scope.len() != 64
            || !token.scope.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !token.ordinary.valid()
            || !token.retained.valid()
        {
            return Err(invalid_token());
        }
        if token.scope != scope {
            return Err(changed_scope());
        }
        Ok(token)
    }
    fn encode(&self) -> Result<String, Error> {
        let value = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(self).map_err(|error| Error::Internal(error.to_string()))?);
        if value.len() > MAX_PAGE_TOKEN_BYTES {
            return Err(Error::Internal(
                "provider page token exceeded its bound".into(),
            ));
        }
        Ok(value)
    }
}

fn invalid_token() -> Error {
    Error::validation_code("page_token is invalid", "page_token_invalid")
}
fn changed_scope() -> Error {
    Error::Conflict {
        message: "page_token belongs to a different device or route epoch".into(),
        code: "page_token_scope_changed".into(),
    }
}
fn scope(device: &str, epoch: Option<i64>) -> String {
    // This is an ownership-consistency digest, not an authorization MAC.
    // Every query still binds the request's normal authorized device identity.
    let mut hash = blake3::Hasher::new();
    hash.update(b"pushgo-provider-page-v1\0");
    hash.update(device.as_bytes());
    hash.update(&[u8::from(epoch.is_some())]);
    hash.update(&epoch.unwrap_or(0).to_le_bytes());
    hash.finalize().to_hex().to_string()
}

// A soft aggregate target, not a new acceptance or single-item size limit.
const SOFT_RESPONSE_BYTES: usize = 1024 * 1024;
const RESPONSE_OVERHEAD_RESERVE: usize = MAX_PAGE_TOKEN_BYTES + 256;
const SCAN_READ_BATCH: usize = 32;

#[derive(Default)]
struct EncodedPage {
    items: Vec<PullItem>,
    encoded_items_bytes: usize,
    full: bool,
}
impl EncodedPage {
    fn push(&mut self, item: PullItem) -> Result<bool, Error> {
        let encoded =
            serde_json::to_vec(&item).map_err(|error| Error::Internal(error.to_string()))?;
        let additional = encoded.len() + usize::from(!self.items.is_empty());
        if !self.items.is_empty()
            && self.encoded_items_bytes.saturating_add(additional)
                > SOFT_RESPONSE_BYTES - RESPONSE_OVERHEAD_RESERVE
        {
            self.full = true;
            return Ok(false);
        }
        // A legal single item always makes progress, even above the soft target.
        self.encoded_items_bytes = self.encoded_items_bytes.saturating_add(additional);
        self.items.push(item);
        self.full = self.encoded_items_bytes > SOFT_RESPONSE_BYTES - RESPONSE_OVERHEAD_RESERVE;
        Ok(true)
    }
}

pub(super) async fn pull_page(
    state: &AppState,
    raw_device: &str,
    raw_token: Option<&str>,
) -> Result<V2PullResponse, Error> {
    let started = std::time::Instant::now();
    let mut read_count = 1usize; // initial route epoch
    let device = DeviceKeyRef::parse(raw_device)?;
    let device = device.as_str();
    let ordinary = state
        .store
        .ordinary_handle()
        .ok_or_else(|| Error::Internal("ordinary authority is not initialized".into()))?;
    let epoch = ordinary.pull_route_epoch(device).await?;
    let expected_scope = scope(device, epoch);
    let first = raw_token.is_none();
    let mut token = if let Some(raw) = raw_token {
        PageToken::decode(raw, &expected_scope)?
    } else {
        read_count += 2; // one ceiling per existing authority
        PageToken {
            version: 1,
            scope: expected_scope,
            ordinary: Window {
                after: None,
                ceiling: ordinary.pull_scan_ceiling(device).await?,
            },
            retained: Window {
                after: None,
                ceiling: state
                    .store
                    .peek_provider_scan_ceiling(
                        derive_private_device_id(device),
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?,
            },
            next_source: Source::Ordinary,
        }
    };
    let primary = token.next_source;
    let mut output = EncodedPage::default();
    // First-page ordinary priority is preserved. Continuations reserve half a
    // scan page for each source, then fill unused capacity. Filtered candidates
    // consume scan capacity, too; neither filter nor byte filling is unbounded.
    let first_budget = if first {
        V2_PULL_LIMIT
    } else {
        V2_PULL_LIMIT / 2
    };
    let used_first = scan_source(
        state,
        device,
        primary,
        &mut token,
        first_budget,
        &mut output,
        &mut read_count,
    )
    .await?;
    let remaining = V2_PULL_LIMIT - used_first;
    let used_second = scan_source(
        state,
        device,
        primary.other(),
        &mut token,
        remaining,
        &mut output,
        &mut read_count,
    )
    .await?;
    let remaining = remaining - used_second;
    let used_fill = if remaining > 0 {
        scan_source(
            state,
            device,
            primary,
            &mut token,
            remaining,
            &mut output,
            &mut read_count,
        )
        .await?
    } else {
        0
    };
    token.next_source = primary.other();
    read_count += 1; // final route epoch fence
    if ordinary.pull_route_epoch(device).await? != epoch {
        return Err(changed_scope());
    }
    let retained_scanned = match primary {
        Source::Ordinary => used_second,
        Source::Retained => used_first + used_fill,
    };
    if retained_scanned != 0 {
        // Preserve activity ownership at page granularity, not once per32-row read.
        state
            .store
            .record_device_activity_best_effort(
                derive_private_device_id(device),
                chrono::Utc::now().timestamp_millis(),
                "provider_pull_v2",
            )
            .await;
    }
    let complete = token.complete();
    ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::DEBUG,
        event = "provider.pull_scan_page", scan_read_queries = read_count as u64,
        activity_touch = (retained_scanned != 0),
        scanned = (used_first + used_second + used_fill) as u64,
        returned = output.items.len() as u64, encoded_items_bytes = output.encoded_items_bytes as u64,
        elapsed_us = started.elapsed().as_micros() as u64, complete);
    Ok(V2PullResponse {
        items: output.items,
        has_more: !complete,
        next_page_token: if complete {
            None
        } else {
            Some(token.encode()?)
        },
        scan_complete: complete,
    })
}

async fn scan_source(
    state: &AppState,
    device: &str,
    source: Source,
    token: &mut PageToken,
    budget: usize,
    output: &mut EncodedPage,
    read_count: &mut usize,
) -> Result<usize, Error> {
    let window = match source {
        Source::Ordinary => &mut token.ordinary,
        Source::Retained => &mut token.retained,
    };
    if budget == 0 || window.complete() || output.full {
        return Ok(0);
    }
    let ceiling = window
        .ceiling
        .as_ref()
        .expect("incomplete source has ceiling")
        .clone();
    let mut scanned = 0;
    let mut filtered = 0usize;
    while scanned < budget && !window.complete() && !output.full {
        let batch = SCAN_READ_BATCH.min(budget - scanned);
        *read_count += 1;
        let rows = match source {
            Source::Ordinary => {
                state
                    .store
                    .ordinary_handle()
                    .ok_or_else(|| Error::Internal("ordinary authority is not initialized".into()))?
                    .pull_scan_page(device, window.after.as_ref(), &ceiling, batch + 1)
                    .await?
            }
            Source::Retained => {
                state
                    .store
                    .peek_provider_scan_page(
                        derive_private_device_id(device),
                        chrono::Utc::now().timestamp_millis(),
                        window.after.as_ref(),
                        &ceiling,
                        batch + 1,
                    )
                    .await?
            }
        };
        let more = rows.len() > batch;
        let available = rows.len().min(batch);
        let mut adopted = 0;
        for row in rows.into_iter().take(batch) {
            if window
                .after
                .as_ref()
                .is_some_and(|after| row.position == *after || row.position.at < after.at)
                || row.position.at > ceiling.at
            {
                return Err(Error::Internal(
                    "provider scan failed to advance inside its captured window".into(),
                ));
            }
            let position = row.position;
            let delivery_id = position.delivery_id.clone();
            let item = match source {
                Source::Ordinary => {
                    match serde_json::from_slice::<hashbrown::HashMap<String, String>>(&row.payload)
                    {
                        Ok(mut payload)
                            if payload
                                .get("delivery_id")
                                .is_none_or(|inner| inner == &delivery_id) =>
                        {
                            payload.remove("delivery_id");
                            Some(PullItem {
                                delivery_id,
                                payload,
                            })
                        }
                        _ => None,
                    }
                }
                Source::Retained => {
                    let candidate = ProviderPullCandidate {
                        delivery_id,
                        payload: row.payload,
                    };
                    PrivatePayloadEnvelope::decode_postcard(&candidate.payload).and_then(
                        |envelope| {
                            if !envelope.is_supported_version()
                                || !is_retained_model(&envelope.data)
                                || envelope.data.get("delivery_id").map(String::as_str)
                                    != Some(candidate.delivery_id.as_str())
                            {
                                return None;
                            }
                            let mut payload = envelope.data;
                            payload.remove("delivery_id");
                            Some(PullItem {
                                delivery_id: candidate.delivery_id,
                                payload,
                            })
                        },
                    )
                }
            };
            if let Some(item) = item {
                if !output.push(item)? {
                    break;
                }
            } else {
                filtered += 1;
            }
            // A filtered row still exists durably. An item that did not fit is
            // not adopted and cannot move this seek past its own position.
            window.after = Some(position);
            adopted += 1;
            scanned += 1;
            if output.full {
                break;
            }
        }
        if !more && adopted == available {
            window.after = window.ceiling.clone();
        }
    }
    if filtered != 0 {
        ::tracing::event!(target: "gateway.trace_event", ::tracing::Level::WARN,
            event = "provider.pull_scan_filtered", count = filtered as u64);
    }
    Ok(scanned)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(at: i64, id: &str) -> ProviderPullPosition {
        ProviderPullPosition {
            at,
            delivery_id: id.into(),
        }
    }
    fn token() -> PageToken {
        PageToken {
            version: 1,
            scope: scope("synthetic-device", Some(7)),
            ordinary: Window {
                after: Some(key(1, "a")),
                ceiling: Some(key(2, "z")),
            },
            retained: Window {
                after: None,
                ceiling: Some(key(3, "c")),
            },
            next_source: Source::Retained,
        }
    }
    #[test]
    fn page_token_is_bounded_and_rejects_wrong_scope_and_malformed_positions() {
        let value = token();
        let encoded = value.encode().unwrap();
        assert!(encoded.len() <= MAX_PAGE_TOKEN_BYTES);
        assert!(
            !PageToken::decode(&encoded, &value.scope)
                .unwrap()
                .complete()
        );
        assert!(
            matches!(PageToken::decode(&encoded, &scope("other-device", Some(7))), Err(Error::Conflict { code, .. }) if code == "page_token_scope_changed")
        );
        assert!(
            matches!(PageToken::decode(&encoded, &scope("synthetic-device", Some(8))), Err(Error::Conflict { code, .. }) if code == "page_token_scope_changed")
        );
        assert_ne!(
            scope("synthetic-device", None),
            scope("synthetic-device", Some(0))
        );
        for raw in [
            String::new(),
            "?".into(),
            "x".repeat(MAX_PAGE_TOKEN_BYTES + 1),
        ] {
            assert!(PageToken::decode(&raw, &value.scope).is_err());
        }
        let mut invalid = token();
        invalid.version = 2;
        assert!(PageToken::decode(&invalid.encode().unwrap(), &value.scope).is_err());
        invalid = token();
        invalid.ordinary.after = Some(key(3, "zz"));
        assert!(PageToken::decode(&invalid.encode().unwrap(), &value.scope).is_err());
    }
    #[test]
    fn soft_byte_budget_preserves_a_single_oversized_item_without_accepting_the_next() {
        let item = |body: String| PullItem {
            delivery_id: "synthetic-delivery".into(),
            payload: hashbrown::HashMap::from_iter([("body".into(), body)]),
        };
        let mut page = EncodedPage::default();
        assert!(
            page.push(item("a".repeat(SOFT_RESPONSE_BYTES + 1)))
                .unwrap()
        );
        assert_eq!(page.items.len(), 1);
        assert!(page.full);
        assert!(!page.push(item("next".into())).unwrap());
        assert_eq!(page.items.len(), 1);
    }
}
