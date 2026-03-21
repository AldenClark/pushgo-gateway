use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WnsPayload {
    data: HashMap<String, String>,
    priority: Option<u8>,
    ttl_seconds: Option<u32>,
}

impl WnsPayload {
    pub fn new(data: HashMap<String, String>, level: &str, ttl_seconds: Option<u32>) -> Self {
        let priority = Self::priority_for_level(level);
        Self {
            data,
            priority,
            ttl_seconds,
        }
    }

    pub fn data(&self) -> &HashMap<String, String> {
        &self.data
    }

    pub fn priority(&self) -> Option<u8> {
        self.priority
    }

    pub fn ttl_seconds(&self) -> Option<u32> {
        self.ttl_seconds
    }

    pub fn priority_for_level(level: &str) -> Option<u8> {
        match level.trim().to_ascii_lowercase().as_str() {
            "critical" | "high" => Some(1),
            "low" => Some(3),
            _ => Some(2),
        }
    }

    pub fn encoded_body(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self.data())
    }

    pub fn encoded_len(&self) -> Result<usize, postcard::Error> {
        self.encoded_body().map(|body| body.len())
    }
}
