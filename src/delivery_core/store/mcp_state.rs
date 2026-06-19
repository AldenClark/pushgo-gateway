use async_trait::async_trait;

use crate::storage::{Storage, StoreResult};

#[async_trait]
pub(crate) trait McpStateStore {
    async fn load_mcp_state_json(&self) -> StoreResult<Option<String>>;
    async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()>;
}

#[async_trait]
impl McpStateStore for Storage {
    async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        self.load_mcp_state_json().await
    }

    async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        self.save_mcp_state_json(state_json).await
    }
}
