use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue};

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
#[derive(Debug, Serialize, Clone)]
pub struct ApnsPayload {
    pub aps: Aps,
    #[serde(flatten)]
    data: HashMap<String, String>,
    #[serde(skip)]
    pub expiration: Option<i64>,
    #[serde(skip)]
    push_type: ApnsPushType,
    #[serde(skip)]
    topic_override: Option<String>,
    #[serde(skip)]
    priority: u8,
}

impl ApnsPayload {
    pub fn new(
        title: Option<String>,
        body: Option<String>,
        fallback_body: Option<String>,
        thread_id: Option<String>,
        level: String,
        expiration: Option<i64>,
        data: HashMap<String, String>,
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
                .or_else(|| Some("You received a new message.".to_string()))
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
            data,
            expiration,
            push_type: ApnsPushType::Alert,
            topic_override: None,
            priority: 10,
        }
    }

    pub fn wakeup(
        _thread_id: Option<String>,
        expiration: Option<i64>,
        data: HashMap<String, String>,
    ) -> Self {
        Self {
            aps: Aps {
                alert: None,
                content_available: Some(1),
                sound: None,
                mutable_content: None,
                thread_id: None,
                interruption_level: None,
                timestamp: None,
                event: None,
                content_state: None,
                stale_date: None,
                dismissal_date: None,
            },
            data,
            expiration,
            push_type: ApnsPushType::Background,
            topic_override: None,
            priority: 5,
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

    pub fn encoded_body(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
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
