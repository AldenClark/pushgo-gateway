use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::util::SharedStringMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsPushType {
    Alert,
    Background,
    LiveActivity,
    Widgets,
}

/// Core APS payload fields.
#[derive(Debug, Serialize, Clone)]
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
#[derive(Debug, Serialize, Clone)]
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
    pub expiration: Option<i64>,
    #[serde(skip)]
    push_type: ApnsPushType,
    #[serde(skip)]
    topic_override: Option<String>,
    #[serde(skip)]
    priority: u8,
    #[serde(skip)]
    encoded_body_cache: Mutex<Option<Arc<[u8]>>>,
}

impl ApnsPayload {
    pub fn new(
        title: Option<String>,
        body: Option<String>,
        fallback_body: Option<String>,
        thread_id: Option<String>,
        level: String,
        expiration: Option<i64>,
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
        expiration: Option<i64>,
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
    use super::ApnsPayload;
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
