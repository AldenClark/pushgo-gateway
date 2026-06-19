use std::sync::Arc;

use hashbrown::HashMap;

pub(crate) struct ProviderWakeupProjection;

pub(crate) struct ProviderWakeupData(pub(crate) Arc<HashMap<String, String>>);

impl ProviderWakeupProjection {
    pub(crate) fn project(data: &HashMap<String, String>) -> HashMap<String, String> {
        crate::util::build_provider_wakeup_data(data)
    }

    pub(crate) fn project_shared(data: &HashMap<String, String>) -> ProviderWakeupData {
        ProviderWakeupData(Arc::new(Self::project(data)))
    }
}

impl ProviderWakeupData {
    pub(crate) fn into_inner(self) -> Arc<HashMap<String, String>> {
        self.0
    }
}
