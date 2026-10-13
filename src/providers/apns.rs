use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::util::SharedStringMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApnsExpirationEpochSeconds(i64);

impl ApnsExpirationEpochSeconds {
    pub fn from_epoch_millis(epoch_millis: i64) -> Self {
        Self(epoch_millis.div_euclid(1000))
    }

    pub fn into_inner(self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for ApnsExpirationEpochSeconds {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApnsPushType {
    Alert,
    Background,
    LiveActivity,
    Widgets,
}

/// Core APS payload fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Aps {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<Alert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_available: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutable_content: Option<u8>,
    #[serde(rename = "content-changed", skip_serializing_if = "Option::is_none")]
    pub content_changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interruption_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(rename = "content-state", skip_serializing_if = "Option::is_none")]
    pub content_state: Option<JsonMap<String, JsonValue>>,
    #[serde(rename = "stale-date", skip_serializing_if = "Option::is_none")]
    pub stale_date: Option<i64>,
    #[serde(rename = "dismissal-date", skip_serializing_if = "Option::is_none")]
    pub dismissal_date: Option<i64>,
}

/// Alert content shown to the user.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Alert {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Full APNs payload with flattened client data.
#[derive(Debug, Serialize)]
pub struct ApnsPayload {
    pub aps: Aps,
    #[serde(flatten)]
    data: SharedStringMap,
    #[serde(skip)]
    pub expiration: Option<ApnsExpirationEpochSeconds>,
    #[serde(skip)]
    push_type: ApnsPushType,
    #[serde(skip)]
    topic_override: Option<String>,
    #[serde(skip)]
    priority: u8,
    #[serde(skip)]
    encoded_body_cache: Mutex<Option<Arc<[u8]>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ApnsPayloadSnapshot {
    aps: Aps,
    data: hashbrown::HashMap<String, String>,
    expiration: Option<ApnsExpirationEpochSeconds>,
    push_type: ApnsPushType,
    topic_override: Option<String>,
    priority: u8,
}

pub(crate) const WATCH_ALERT_DEADLINE_KEY: &str = "watch_alert_deadline_at";

/// Freeze Watch reminder age independently of sender TTL and pull retention.
pub(crate) fn watch_alert_deadline(accepted_at: i64, minutes: i64) -> Option<i64> {
    if accepted_at <= 0 || !matches!(minutes, 5 | 15 | 30 | 60) {
        return None;
    }
    accepted_at.checked_add(minutes.checked_mul(60_000)?)
}

impl ApnsPayload {
    pub(crate) fn with_watch_alert_deadline(&self, deadline: i64) -> Self {
        let mut data = self.data.as_map().clone();
        data.insert(WATCH_ALERT_DEADLINE_KEY.to_string(), deadline.to_string());
        let mut payload = self.with_data(data);
        let bound = ApnsExpirationEpochSeconds::from_epoch_millis(deadline);
        payload.expiration = Some(match self.expiration {
            Some(original) if original.into_inner() == 0 => original,
            Some(original)
                if original.into_inner() > 0 && original.into_inner() < bound.into_inner() =>
            {
                original
            }
            _ => bound,
        });
        payload
    }

    /// Old durable jobs use their original outbox acceptance and default window.
    /// Never derive a fresh deadline from retry time or current device settings.
    pub(crate) fn watch_alert_for_attempt(&self, accepted_at: i64, now: i64) -> Option<Self> {
        if accepted_at <= 0 || accepted_at > now {
            return None;
        }
        let deadline = match self.data.as_map().get(WATCH_ALERT_DEADLINE_KEY) {
            Some(raw) => {
                let deadline = raw.parse::<i64>().ok()?;
                let age = deadline.checked_sub(accepted_at)?;
                if !matches!(age, 300_000 | 900_000 | 1_800_000 | 3_600_000) {
                    return None;
                }
                deadline
            }
            None => watch_alert_deadline(accepted_at, 30)?,
        };
        if now >= deadline
            || self.expiration.is_some_and(|expiration| {
                let seconds = expiration.into_inner();
                seconds < 0 || (seconds > 0 && now.div_euclid(1000) >= seconds)
            })
        {
            return None;
        }
        let mut payload = self.with_watch_alert_deadline(deadline);
        let mut data = payload.data.as_map().clone();
        data.insert("sent_at".to_string(), accepted_at.to_string());
        payload.data = data.into();
        Some(payload)
    }

    pub(crate) fn watch_alert_is_current(&self, now: i64) -> bool {
        self.data
            .as_map()
            .get("sent_at")
            .and_then(|raw| raw.parse::<i64>().ok())
            .and_then(|accepted_at| self.watch_alert_for_attempt(accepted_at, now))
            .is_some()
    }

    pub(crate) fn snapshot(&self) -> ApnsPayloadSnapshot {
        ApnsPayloadSnapshot {
            aps: self.aps.clone(),
            data: self.data.as_map().clone(),
            expiration: self.expiration,
            push_type: self.push_type,
            topic_override: self.topic_override.clone(),
            priority: self.priority,
        }
    }

    pub(crate) fn from_snapshot(snapshot: ApnsPayloadSnapshot) -> Self {
        Self {
            aps: snapshot.aps,
            data: snapshot.data.into(),
            expiration: snapshot.expiration,
            push_type: snapshot.push_type,
            topic_override: snapshot.topic_override,
            priority: snapshot.priority,
            encoded_body_cache: Mutex::new(None),
        }
    }
    pub fn new(
        title: Option<String>,
        body: Option<String>,
        fallback_body: Option<String>,
        thread_id: Option<String>,
        level: String,
        expiration: Option<ApnsExpirationEpochSeconds>,
        data: impl Into<SharedStringMap>,
    ) -> Self {
        let normalized_title = title
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let normalized_body = body
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        // APNs rejects an alert payload when both title and body are missing.
        let resolved_body = if normalized_title.is_none() && normalized_body.is_none() {
            fallback_body
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        } else {
            normalized_body
        };
        let interruption_level = interruption_level_for(&level).to_string();
        Self {
            aps: Aps {
                alert: Some(Alert {
                    title: normalized_title,
                    body: resolved_body,
                }),
                content_available: None,
                mutable_content: Some(1),
                content_changed: None,
                thread_id,
                interruption_level: Some(interruption_level),
                timestamp: None,
                event: None,
                content_state: None,
                stale_date: None,
                dismissal_date: None,
            },
            data: data.into(),
            expiration,
            push_type: ApnsPushType::Alert,
            topic_override: None,
            priority: 10,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn wakeup(
        fallback_title: Option<String>,
        fallback_body: Option<String>,
        thread_id: Option<String>,
        expiration: Option<ApnsExpirationEpochSeconds>,
        data: impl Into<SharedStringMap>,
    ) -> Self {
        let title = fallback_title
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let body = fallback_body
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self {
            aps: Aps {
                alert: Some(Alert { title, body }),
                content_available: None,
                mutable_content: Some(1),
                content_changed: None,
                thread_id,
                interruption_level: None,
                timestamp: None,
                event: None,
                content_state: None,
                stale_date: None,
                dismissal_date: None,
            },
            data: data.into(),
            expiration,
            push_type: ApnsPushType::Alert,
            topic_override: None,
            priority: 10,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn live_activity(
        title: String,
        state: Option<String>,
        severity: Option<String>,
        updated_at_millis: i64,
        event: impl Into<String>,
        topic: impl Into<String>,
    ) -> Self {
        let mut content_state = JsonMap::new();
        content_state.insert("title".to_string(), JsonValue::String(title));
        if let Some(state) = state.filter(|value| !value.trim().is_empty()) {
            content_state.insert("state".to_string(), JsonValue::String(state));
        }
        if let Some(severity) = severity.filter(|value| !value.trim().is_empty()) {
            content_state.insert("severity".to_string(), JsonValue::String(severity));
        }
        content_state.insert(
            "updatedAt".to_string(),
            JsonValue::String(activitykit_iso8601(updated_at_millis)),
        );
        Self {
            aps: Aps {
                alert: None,
                content_available: None,
                mutable_content: None,
                content_changed: None,
                thread_id: None,
                interruption_level: None,
                timestamp: Some(updated_at_millis / 1000),
                event: Some(event.into()),
                content_state: Some(content_state),
                stale_date: None,
                dismissal_date: None,
            },
            data: SharedStringMap::default(),
            expiration: None,
            push_type: ApnsPushType::LiveActivity,
            topic_override: Some(topic.into()),
            priority: 10,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn live_activity_end(
        title: String,
        state: Option<String>,
        severity: Option<String>,
        updated_at_millis: i64,
        topic: impl Into<String>,
        dismissal_date: Option<i64>,
    ) -> Self {
        let mut payload =
            Self::live_activity(title, state, severity, updated_at_millis, "end", topic);
        payload.aps.dismissal_date = dismissal_date;
        payload
    }

    pub fn widgets() -> Self {
        Self {
            aps: Aps {
                alert: None,
                content_available: None,
                mutable_content: None,
                content_changed: Some(true),
                thread_id: None,
                interruption_level: None,
                timestamp: None,
                event: None,
                content_state: None,
                stale_date: None,
                dismissal_date: None,
            },
            data: SharedStringMap::default(),
            expiration: None,
            push_type: ApnsPushType::Widgets,
            topic_override: None,
            priority: 5,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn push_type(&self) -> ApnsPushType {
        self.push_type
    }

    pub fn push_type_header(&self) -> &'static str {
        match self.push_type {
            ApnsPushType::Alert => "alert",
            ApnsPushType::Background => "background",
            ApnsPushType::LiveActivity => "liveactivity",
            ApnsPushType::Widgets => "widgets",
        }
    }

    pub fn topic_override(&self) -> Option<&str> {
        self.topic_override.as_deref()
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub(crate) fn with_data(&self, data: impl Into<SharedStringMap>) -> Self {
        Self {
            aps: self.aps.clone(),
            data: data.into(),
            expiration: self.expiration,
            push_type: self.push_type,
            topic_override: self.topic_override.clone(),
            priority: self.priority,
            encoded_body_cache: Mutex::new(None),
        }
    }

    pub fn encoded_body(&self) -> Result<Arc<[u8]>, serde_json::Error> {
        if let Some(body) = self.encoded_body_cache.lock().as_ref() {
            return Ok(Arc::clone(body));
        }
        let encoded: Arc<[u8]> = serde_json::to_vec(self)?.into();
        let mut cache = self.encoded_body_cache.lock();
        let body = cache.get_or_insert_with(|| Arc::clone(&encoded));
        Ok(Arc::clone(body))
    }

    pub fn encoded_len(&self) -> Result<usize, serde_json::Error> {
        self.encoded_body().map(|body| body.len())
    }
}

fn activitykit_iso8601(epoch_millis: i64) -> String {
    let secs = epoch_millis.div_euclid(1000);
    let nanos = (epoch_millis.rem_euclid(1000) as u32) * 1_000_000;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn interruption_level_for(level: &str) -> &'static str {
    match level {
        "critical" => "critical",
        "high" => "time-sensitive",
        "low" => "passive",
        _ => "active",
    }
}

#[cfg(test)]
mod tests {
    use super::{ApnsExpirationEpochSeconds, ApnsPayload};
    use crate::util::SharedStringMap;

    #[test]
    fn wakeup_payload_is_alert_with_mutable_content() {
        let payload = ApnsPayload::wakeup(
            Some("Wakeup title".to_string()),
            Some("Wakeup body".to_string()),
            None,
            None,
            SharedStringMap::default(),
        );
        assert_eq!(payload.push_type_header(), "alert");
        assert_eq!(payload.aps.mutable_content, Some(1));
        assert_eq!(payload.priority(), 10);
        assert_eq!(
            payload
                .aps
                .alert
                .as_ref()
                .and_then(|alert| alert.title.as_deref()),
            Some("Wakeup title")
        );
        assert_eq!(
            payload
                .aps
                .alert
                .as_ref()
                .and_then(|alert| alert.body.as_deref()),
            Some("Wakeup body")
        );
    }

    #[test]
    fn alert_payload_leaves_sound_selection_to_clients() {
        let payload = ApnsPayload::new(
            Some("Title".to_string()),
            Some("Body".to_string()),
            None,
            None,
            "critical".to_string(),
            None,
            SharedStringMap::default(),
        );
        let json = serde_json::to_value(&payload).expect("serialize APNs payload");
        assert!(json["aps"].get("sound").is_none());
    }

    #[test]
    fn expiration_converts_epoch_millis_to_apns_epoch_seconds() {
        let expiration = ApnsExpirationEpochSeconds::from_epoch_millis(1_700_000_123_456);
        assert_eq!(expiration.into_inner(), 1_700_000_123);
        assert_eq!(expiration.to_string(), "1700000123");
    }

    #[test]
    fn live_activity_payload_uses_activitykit_headers_and_content_state() {
        let payload = ApnsPayload::live_activity(
            "Database latency".to_string(),
            Some("open".to_string()),
            Some("critical".to_string()),
            1_700_000_000_123,
            "update",
            "io.ethan.pushgo.push-type.liveactivity",
        );
        assert_eq!(payload.push_type_header(), "liveactivity");
        assert_eq!(
            payload.topic_override(),
            Some("io.ethan.pushgo.push-type.liveactivity")
        );
        let json = serde_json::to_value(&payload).expect("serialize live activity payload");
        assert_eq!(json["aps"]["event"], "update");
        assert_eq!(json["aps"]["timestamp"], 1_700_000_000);
        assert_eq!(json["aps"]["content-state"]["title"], "Database latency");
        assert_eq!(json["aps"]["content-state"]["state"], "open");
        assert_eq!(json["aps"]["content-state"]["severity"], "critical");
        assert_eq!(
            json["aps"]["content-state"]["updatedAt"],
            "2023-11-14T22:13:20.123Z"
        );
    }
}

#[cfg(test)]
mod watch_alert_tests {
    use super::*;
    const ACCEPTED: i64 = 1_700_000_000_000;
    fn payload(expiration: Option<i64>) -> ApnsPayload {
        ApnsPayload::wakeup(
            None,
            None,
            None,
            expiration.map(ApnsExpirationEpochSeconds::from_epoch_millis),
            hashbrown::HashMap::<String, String>::new(),
        )
    }
    #[test]
    fn watch_alert_cutoff_uses_original_acceptance_and_survives_snapshot() {
        let deadline = watch_alert_deadline(ACCEPTED, 5).unwrap();
        let original = payload(None);
        let frozen = original.with_watch_alert_deadline(deadline);
        let restored = ApnsPayload::from_snapshot(frozen.snapshot());
        assert!(
            restored
                .watch_alert_for_attempt(ACCEPTED, deadline - 1)
                .is_some()
        );
        assert!(
            restored
                .watch_alert_for_attempt(ACCEPTED, deadline)
                .is_none()
        );
        assert_eq!(restored.expiration.unwrap().into_inner(), deadline / 1000);
        assert!(original.expiration.is_none());
        assert!(
            !serde_json::to_value(original)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key(WATCH_ALERT_DEADLINE_KEY)
        );
    }
    #[test]
    fn watch_alert_preserves_no_store_and_earlier_sender_expiration() {
        let deadline = watch_alert_deadline(ACCEPTED, 30).unwrap();
        let no_store = payload(Some(0)).with_watch_alert_deadline(deadline);
        assert_eq!(no_store.expiration.unwrap().into_inner(), 0);
        assert!(
            no_store
                .watch_alert_for_attempt(ACCEPTED, ACCEPTED + 1)
                .is_some()
        );
        let earlier = payload(Some(ACCEPTED + 60_000)).with_watch_alert_deadline(deadline);
        assert_eq!(
            earlier.expiration.unwrap().into_inner(),
            (ACCEPTED + 60_000) / 1000
        );
        assert!(
            earlier
                .watch_alert_for_attempt(ACCEPTED, ACCEPTED + 60_000)
                .is_none()
        );
    }
    #[test]
    fn watch_alert_legacy_and_invalid_time_never_refresh_from_now() {
        let legacy = payload(None);
        assert!(
            legacy
                .watch_alert_for_attempt(ACCEPTED, ACCEPTED + 1_799_999)
                .is_some()
        );
        assert!(
            legacy
                .watch_alert_for_attempt(ACCEPTED, ACCEPTED + 1_800_000)
                .is_none()
        );
        for accepted in [0, -1, i64::MAX, ACCEPTED + 1] {
            assert!(legacy.watch_alert_for_attempt(accepted, ACCEPTED).is_none());
        }
        assert!(watch_alert_deadline(i64::MAX, 30).is_none());
        for raw in ["bad", "0", "-1", "1700000000000", "9223372036854775807"] {
            let forged = legacy.with_data(hashbrown::HashMap::from([(
                WATCH_ALERT_DEADLINE_KEY.to_string(),
                raw.to_string(),
            )]));
            assert!(forged.watch_alert_for_attempt(ACCEPTED, ACCEPTED).is_none());
        }
    }
}

#[cfg(test)]
mod watch_alert_network_boundary_tests {
    use super::*;
    #[test]
    fn watch_alert_network_rechecks_clock_after_credential_wait() {
        let accepted = 1_700_000_000_000;
        let deadline = accepted + 300_000;
        let legacy = ApnsPayload::wakeup(
            None,
            None,
            None,
            None,
            hashbrown::HashMap::<String, String>::new(),
        );
        let frozen = legacy
            .with_watch_alert_deadline(deadline)
            .watch_alert_for_attempt(accepted, deadline - 1)
            .unwrap();
        assert!(frozen.watch_alert_is_current(deadline - 1));
        assert!(!frozen.watch_alert_is_current(deadline));
        assert!(!frozen.watch_alert_is_current(accepted - 1));
    }
}
