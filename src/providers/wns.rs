use std::{collections::BTreeMap, sync::Arc};

use hashbrown::HashMap;
use parking_lot::Mutex;
use serde::Serialize;
use thiserror::Error;

use crate::{util::SharedStringMap, value::NotificationSeverity};

pub const WNS_ENVELOPE_VERSION: u8 = 2;

const CLIENT_LOCAL_ROUTING_FIELDS: &[&str] = &[
    "ack_contract",
    "base_url",
    "delivery_id",
    "gateway_url",
    "provider_device_key",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WnsEnvelopeKind {
    Notification,
    ProviderWakeup,
}

#[derive(Debug, Error)]
pub enum WnsPayloadEncodeError {
    #[error("WNS payload is missing an authoritative delivery_id")]
    MissingDeliveryId,
    #[error("failed to encode WNS JSON envelope: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct WnsWireEnvelope<'a> {
    version: u8,
    kind: WnsEnvelopeKind,
    delivery_id: &'a str,
    payload: BTreeMap<&'a str, &'a str>,
}

#[derive(Debug)]
pub struct WnsPayload {
    data: SharedStringMap,
    delivery_id: Arc<str>,
    kind: WnsEnvelopeKind,
    priority: Option<u8>,
    ttl_seconds: Option<u32>,
    encoded_body_cache: Mutex<Option<Arc<[u8]>>>,
}

impl WnsPayload {
    pub fn new(
        data: impl Into<SharedStringMap>,
        delivery_id: &str,
        kind: WnsEnvelopeKind,
        level: &str,
        ttl_seconds: Option<u32>,
    ) -> Self {
        let priority = Self::priority_for_level(level);
        Self {
            data: data.into(),
            delivery_id: Arc::from(delivery_id.trim()),
            kind,
            priority,
            ttl_seconds,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn data(&self) -> &HashMap<String, String> {
        self.data.as_map()
    }

    pub fn priority(&self) -> Option<u8> {
        self.priority
    }

    pub fn ttl_seconds(&self) -> Option<u32> {
        self.ttl_seconds
    }

    pub fn priority_for_level(level: &str) -> Option<u8> {
        Some(
            NotificationSeverity::parse_known(level)
                .unwrap_or(NotificationSeverity::Normal)
                .wns_priority(),
        )
    }

    pub(crate) fn with_data(&self, data: impl Into<SharedStringMap>) -> Self {
        Self {
            data: data.into(),
            delivery_id: Arc::clone(&self.delivery_id),
            kind: self.kind,
            priority: self.priority,
            ttl_seconds: self.ttl_seconds,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn encoded_body(&self) -> Result<Arc<[u8]>, WnsPayloadEncodeError> {
        if let Some(body) = self.encoded_body_cache.lock().as_ref() {
            return Ok(Arc::clone(body));
        }
        let delivery_id = self.delivery_id.trim();
        if delivery_id.is_empty() {
            return Err(WnsPayloadEncodeError::MissingDeliveryId);
        }
        let payload = self
            .data()
            .iter()
            .filter(|(key, _)| !CLIENT_LOCAL_ROUTING_FIELDS.contains(&key.as_str()))
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let envelope = WnsWireEnvelope {
            version: WNS_ENVELOPE_VERSION,
            kind: self.kind,
            delivery_id,
            payload,
        };
        let encoded: Arc<[u8]> = serde_json::to_vec(&envelope)?.into();
        let mut cache = self.encoded_body_cache.lock();
        let body = cache.get_or_insert_with(|| Arc::clone(&encoded));
        Ok(Arc::clone(body))
    }

    pub fn encoded_len(&self) -> Result<usize, WnsPayloadEncodeError> {
        self.encoded_body().map(|body| body.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_wakeup_body_matches_shared_v2_fixture() {
        let data = HashMap::from([
            ("_skip_persist".to_string(), "1".to_string()),
            ("ack_contract".to_string(), "v2_batch".to_string()),
            (
                "base_url".to_string(),
                "https://untrusted.invalid".to_string(),
            ),
            (
                "body".to_string(),
                "Open PushGo to retrieve the queued delivery".to_string(),
            ),
            (
                "delivery_id".to_string(),
                "untrusted-inner-delivery".to_string(),
            ),
            (
                "gateway_url".to_string(),
                "https://alternate-attacker.invalid".to_string(),
            ),
            (
                "provider_device_key".to_string(),
                "remote-device-key".to_string(),
            ),
            ("provider_mode".to_string(), "wakeup".to_string()),
            ("provider_wakeup".to_string(), "1".to_string()),
            ("title".to_string(), "New PushGo delivery".to_string()),
        ]);
        let payload = WnsPayload::new(
            SharedStringMap::from(data),
            "delivery-fixture-001",
            WnsEnvelopeKind::ProviderWakeup,
            "high",
            None,
        );

        let body = payload.encoded_body().expect("WNS payload should encode");
        let actual = std::str::from_utf8(body.as_ref()).expect("WNS v2 must be UTF-8 JSON");
        let expected = include_str!("../../tests/fixtures/provider_contract/wns_v2_wakeup.json");

        assert_eq!(actual, expected.trim_end());
    }

    #[test]
    fn notification_body_matches_shared_v2_fixture_and_keeps_outer_id_authoritative() {
        let data = HashMap::from([
            ("delivery_id".to_string(), "conflicting-inner".to_string()),
            ("body".to_string(), "Fixture notification body".to_string()),
            ("title".to_string(), "Fixture notification".to_string()),
        ]);
        let payload = WnsPayload::new(
            SharedStringMap::from(data),
            "delivery-fixture-002",
            WnsEnvelopeKind::Notification,
            "normal",
            None,
        );

        let body = payload.encoded_body().expect("WNS payload should encode");
        let value: serde_json::Value =
            serde_json::from_slice(body.as_ref()).expect("WNS payload should be JSON");
        let expected =
            include_str!("../../tests/fixtures/provider_contract/wns_v2_notification.json");

        assert_eq!(
            std::str::from_utf8(body.as_ref()).expect("WNS v2 must be UTF-8 JSON"),
            expected.trim_end()
        );
        assert_eq!(value["version"], WNS_ENVELOPE_VERSION);
        assert_eq!(value["kind"], "notification");
        assert_eq!(value["delivery_id"], "delivery-fixture-002");
        assert!(value["payload"].get("delivery_id").is_none());
    }

    #[test]
    fn encoded_body_rejects_missing_authoritative_delivery_id() {
        let payload = WnsPayload::new(
            SharedStringMap::from(HashMap::from([(
                "title".to_string(),
                "No identity".to_string(),
            )])),
            "",
            WnsEnvelopeKind::Notification,
            "normal",
            None,
        );

        assert!(matches!(
            payload.encoded_body(),
            Err(WnsPayloadEncodeError::MissingDeliveryId)
        ));
    }
}
