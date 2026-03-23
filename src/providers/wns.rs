use std::sync::Arc;

use hashbrown::HashMap;
use parking_lot::Mutex;

use crate::util::SharedStringMap;

#[derive(Debug)]
pub struct WnsPayload {
    data: SharedStringMap,
    priority: Option<u8>,
    ttl_seconds: Option<u32>,
    encoded_body_cache: Mutex<Option<Arc<[u8]>>>,
}

impl WnsPayload {
    pub fn new(data: impl Into<SharedStringMap>, level: &str, ttl_seconds: Option<u32>) -> Self {
        let priority = Self::priority_for_level(level);
        Self {
            data: data.into(),
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
        match level.trim().to_ascii_lowercase().as_str() {
            "critical" | "high" => Some(1),
            "low" => Some(3),
            _ => Some(2),
        }
    }

    pub fn encoded_body(&self) -> Result<Arc<[u8]>, postcard::Error> {
        if let Some(body) = self.encoded_body_cache.lock().as_ref() {
            return Ok(Arc::clone(body));
        }
        let encoded: Arc<[u8]> = postcard::to_allocvec(self.data())?.into();
        let mut cache = self.encoded_body_cache.lock();
        let body = cache.get_or_insert_with(|| Arc::clone(&encoded));
        Ok(Arc::clone(body))
    }

    pub fn encoded_len(&self) -> Result<usize, postcard::Error> {
        self.encoded_body().map(|body| body.len())
    }
}
