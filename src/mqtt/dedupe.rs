use std::sync::Arc;

use dashmap::DashMap;

const MQTT_QOS1_FALLBACK_DEDUPE_TTL_MILLIS: i64 = 2 * 60 * 1000;

#[derive(Debug, Default)]
pub(crate) struct MqttPublishDedupe {
    entries: DashMap<String, i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MqttPublishDedupeDecision {
    Proceed,
    Duplicate,
}

impl MqttPublishDedupe {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn reserve(
        &self,
        key: MqttPublishDedupeKey<'_>,
        now_millis: i64,
    ) -> MqttPublishDedupeDecision {
        let expires_at = now_millis + MQTT_QOS1_FALLBACK_DEDUPE_TTL_MILLIS;
        self.prune_expired(now_millis);
        let key = key.to_key();
        if let Some(existing) = self.entries.get(key.as_str())
            && *existing > now_millis
        {
            return MqttPublishDedupeDecision::Duplicate;
        }
        self.entries.insert(key, expires_at);
        MqttPublishDedupeDecision::Proceed
    }

    pub(crate) fn clear(&self, key: MqttPublishDedupeKey<'_>) {
        let key = key.to_key();
        self.entries.remove(key.as_str());
    }

    fn prune_expired(&self, now_millis: i64) {
        self.entries
            .retain(|_, expires_at| *expires_at > now_millis);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MqttPublishDedupeKey<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) packet_id: u16,
    pub(crate) topic: &'a str,
    pub(crate) payload: &'a [u8],
}

impl MqttPublishDedupeKey<'_> {
    fn to_key(self) -> String {
        let payload_hash = blake3::hash(self.payload).to_hex().to_string();
        format!(
            "mqtt-qos1:{}:{}:{}:{}",
            self.client_id.trim(),
            self.packet_id,
            self.topic.trim(),
            payload_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_dedupe_is_short_window_and_payload_sensitive() {
        let dedupe = MqttPublishDedupe::default();
        let key = MqttPublishDedupeKey {
            client_id: "client-1",
            packet_id: 7,
            topic: "pushgo/messages/channel",
            payload: b"same",
        };

        assert_eq!(
            dedupe.reserve(key, 1_000),
            MqttPublishDedupeDecision::Proceed
        );
        assert_eq!(
            dedupe.reserve(key, 1_001),
            MqttPublishDedupeDecision::Duplicate
        );
        dedupe.clear(key);
        assert_eq!(
            dedupe.reserve(key, 1_001),
            MqttPublishDedupeDecision::Proceed
        );
        assert_eq!(
            dedupe.reserve(
                MqttPublishDedupeKey {
                    payload: b"different",
                    ..key
                },
                1_002
            ),
            MqttPublishDedupeDecision::Proceed
        );
        assert_eq!(
            dedupe.reserve(key, 1_000 + MQTT_QOS1_FALLBACK_DEDUPE_TTL_MILLIS + 1),
            MqttPublishDedupeDecision::Proceed
        );
    }
}
