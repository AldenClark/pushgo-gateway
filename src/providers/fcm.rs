use std::sync::Arc;

use hashbrown::HashMap;
use serde::Serialize;

use crate::util::SharedStringMap;

#[derive(Debug, Serialize)]
pub struct FcmPayload {
    data: SharedStringMap,
    priority: &'static str,
    ttl_seconds: Option<u32>,
}

impl FcmPayload {
    pub fn new(
        data: impl Into<SharedStringMap>,
        priority: &'static str,
        ttl_seconds: Option<u32>,
    ) -> Self {
        Self {
            data: data.into(),
            priority,
            ttl_seconds,
        }
    }

    pub fn priority_for_level(level: &str) -> &'static str {
        match level.trim().to_ascii_lowercase().as_str() {
            "critical" | "high" => "HIGH",
            _ => "NORMAL",
        }
    }

    pub fn data(&self) -> &HashMap<String, String> {
        self.data.as_map()
    }

    pub fn priority(&self) -> &'static str {
        self.priority
    }

    pub fn ttl_seconds(&self) -> Option<u32> {
        self.ttl_seconds
    }

    pub fn encoded_body(&self, device_token: &str) -> Result<Arc<[u8]>, serde_json::Error> {
        let encoded = serde_json::to_vec(&FcmRequest {
            message: FcmMessage {
                token: device_token,
                data: self.data(),
                android: FcmAndroidConfig {
                    priority: self.priority(),
                    ttl: self.ttl_seconds().map(|value| format!("{value}s")),
                },
            },
        })?;
        Ok(encoded.into())
    }

    pub fn encoded_len(&self, device_token: &str) -> Result<usize, serde_json::Error> {
        self.encoded_body(device_token).map(|body| body.len())
    }
}

#[derive(Serialize)]
struct FcmRequest<'a> {
    message: FcmMessage<'a>,
}

#[derive(Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    data: &'a HashMap<String, String>,
    android: FcmAndroidConfig,
}

#[derive(Serialize)]
struct FcmAndroidConfig {
    priority: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<String>,
}
