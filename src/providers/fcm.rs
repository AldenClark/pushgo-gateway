use std::collections::HashMap;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FcmPayload {
    data: HashMap<String, String>,
    priority: &'static str,
    ttl_seconds: Option<u32>,
}

impl FcmPayload {
    pub fn new(
        data: HashMap<String, String>,
        priority: &'static str,
        ttl_seconds: Option<u32>,
    ) -> Self {
        Self {
            data,
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
        &self.data
    }

    pub fn priority(&self) -> &'static str {
        self.priority
    }

    pub fn ttl_seconds(&self) -> Option<u32> {
        self.ttl_seconds
    }

    pub fn encoded_body(&self, device_token: &str) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&FcmRequest {
            message: FcmMessage {
                token: device_token,
                data: self.data(),
                android: FcmAndroidConfig {
                    priority: self.priority(),
                    ttl: self.ttl_seconds().map(|value| format!("{value}s")),
                },
            },
        })
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
