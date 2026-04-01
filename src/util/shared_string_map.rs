use std::sync::Arc;

use hashbrown::HashMap;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct SharedStringMap(Arc<HashMap<String, String>>);

impl SharedStringMap {
    pub fn as_map(&self) -> &HashMap<String, String> {
        self.0.as_ref()
    }
}

impl From<HashMap<String, String>> for SharedStringMap {
    fn from(value: HashMap<String, String>) -> Self {
        Self(Arc::new(value))
    }
}

impl From<Arc<HashMap<String, String>>> for SharedStringMap {
    fn from(value: Arc<HashMap<String, String>>) -> Self {
        Self(value)
    }
}

impl Serialize for SharedStringMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}
