use std::sync::Arc;

use hashbrown::HashMap;

#[derive(Debug, Clone)]
pub(crate) struct BasePayloadBundle {
    pub(crate) canonical_fields: Arc<HashMap<String, String>>,
    pub(crate) ttl: Option<i64>,
    pub(crate) estimated_inline_bytes: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum TargetPayload {
    Private(Vec<u8>),
    ProviderInline(Arc<HashMap<String, String>>),
    ProviderWakeup(Arc<HashMap<String, String>>),
    Mqtt(Arc<HashMap<String, String>>),
}
