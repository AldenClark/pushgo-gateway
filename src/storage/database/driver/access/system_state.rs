use super::*;
use async_trait::async_trait;

#[async_trait]
impl SystemStateDatabaseAccess for DatabaseDriver {
    async fn automation_reset(&self) -> StoreResult<()> {
        delegate_db_async!(self, automation_reset())
    }

    async fn automation_counts(&self) -> StoreResult<AutomationCounts> {
        delegate_db_async!(self, automation_counts())
    }

    async fn load_mcp_state_json(&self) -> StoreResult<Option<String>> {
        delegate_db_async!(self, load_mcp_state_json())
    }

    async fn save_mcp_state_json(&self, state_json: &str) -> StoreResult<()> {
        delegate_db_async!(self, save_mcp_state_json(state_json))
    }
}
