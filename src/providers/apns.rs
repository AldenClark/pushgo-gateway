use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::util::SharedStringMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsPushType {
    Alert,
    Background,
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
    pub sound: Option<Sound>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutable_content: Option<u8>,
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

/// Sound configuration (name or detailed settings).
#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum Sound {
    Name(String),
    Detailed {
        name: String,
        critical: u8,
        volume: f32,
    },
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
        let sound = build_sound_for_level(&level);
        Self {
            aps: Aps {
                alert: Some(Alert {
                    title: normalized_title,
                    body: resolved_body,
                }),
                content_available: None,
                sound,
                mutable_content: Some(1),
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
                sound: None,
                mutable_content: Some(1),
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

    pub fn push_type(&self) -> ApnsPushType {
        self.push_type
    }

    pub fn push_type_header(&self) -> &'static str {
        match self.push_type {
            ApnsPushType::Alert => "alert",
            ApnsPushType::Background => "background",
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

fn interruption_level_for(level: &str) -> &'static str {
    match level {
        "critical" => "critical",
        "high" => "time-sensitive",
        "low" => "passive",
        _ => "active",
    }
}

fn build_sound_for_level(level: &str) -> Option<Sound> {
    let name = match level {
        "critical" => "alert.caf",
        "high" => "level-up.caf",
        "low" => return None,
        _ => "bubble-pop.caf",
    }
    .to_string();
    if level == "critical" {
        return Some(Sound::Detailed {
            name,
            critical: 1,
            volume: 1.0,
        });
    }
    Some(Sound::Name(name))
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
}
