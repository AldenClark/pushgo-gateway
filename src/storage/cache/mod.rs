use crate::storage::types::{ChannelInfo, DeviceInfo, DispatchTarget, DispatchTargetsCacheEntry};

mod memory;

pub use memory::InMemoryCache;

#[derive(Debug, Clone)]
pub enum CacheStore {
    InMemory(InMemoryCache),
}
impl CacheStore {
    pub fn new() -> Self {
        CacheStore::InMemory(InMemoryCache::new())
    }
}

impl Default for CacheStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheAccess for CacheStore {
    fn get_device(&self, device_id: &[u8; 32]) -> Option<DeviceInfo> {
        match self {
            CacheStore::InMemory(inner) => inner.get_device(device_id),
        }
    }

    fn put_device(&self, device_id: [u8; 32], device: &DeviceInfo) {
        match self {
            CacheStore::InMemory(inner) => inner.put_device(device_id, device),
        }
    }

    fn remove_device(&self, device_id: &[u8; 32]) -> Option<DeviceInfo> {
        match self {
            CacheStore::InMemory(inner) => inner.remove_device(device_id),
        }
    }

    fn clear_devices(&self) {
        match self {
            CacheStore::InMemory(inner) => inner.clear_devices(),
        }
    }

    fn invalidate_channel_devices(&self, channel_id: [u8; 16]) {
        match self {
            CacheStore::InMemory(inner) => inner.invalidate_channel_devices(channel_id),
        }
    }

    fn invalidate_all_channel_devices(&self) {
        match self {
            CacheStore::InMemory(inner) => inner.invalidate_all_channel_devices(),
        }
    }

    fn put_channel_info(&self, channel_id: [u8; 16], info: &ChannelInfo) {
        match self {
            CacheStore::InMemory(inner) => inner.put_channel_info(channel_id, info),
        }
    }

    fn get_channel_info(&self, channel_id: [u8; 16]) -> Option<ChannelInfo> {
        match self {
            CacheStore::InMemory(inner) => inner.get_channel_info(channel_id),
        }
    }

    fn invalidate_channel_info(&self, channel_id: [u8; 16]) {
        match self {
            CacheStore::InMemory(inner) => inner.invalidate_channel_info(channel_id),
        }
    }

    fn put_channel_devices(&self, channel_id: [u8; 16], devices: &[DeviceInfo]) {
        match self {
            CacheStore::InMemory(inner) => inner.put_channel_devices(channel_id, devices),
        }
    }

    fn get_channel_devices(&self, channel_id: [u8; 16]) -> Option<Vec<DeviceInfo>> {
        match self {
            CacheStore::InMemory(inner) => inner.get_channel_devices(channel_id),
        }
    }

    fn put_channel_dispatch_targets(&self, channel_id: [u8; 16], targets: &[DispatchTarget]) {
        match self {
            CacheStore::InMemory(inner) => inner.put_channel_dispatch_targets(channel_id, targets),
        }
    }

    fn get_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
    ) -> Option<DispatchTargetsCacheEntry> {
        match self {
            CacheStore::InMemory(inner) => inner.get_channel_dispatch_targets(channel_id),
        }
    }

    fn dispatch_targets_cache_ttl_ms(&self) -> i64 {
        match self {
            CacheStore::InMemory(inner) => inner.dispatch_targets_cache_ttl_ms(),
        }
    }
}

pub trait CacheAccess: Send + Sync {
    fn get_device(&self, device_id: &[u8; 32]) -> Option<DeviceInfo>;
    fn put_device(&self, device_id: [u8; 32], device: &DeviceInfo);
    fn remove_device(&self, device_id: &[u8; 32]) -> Option<DeviceInfo>;
    fn clear_devices(&self);

    fn invalidate_channel_devices(&self, channel_id: [u8; 16]);
    fn invalidate_all_channel_devices(&self);

    fn put_channel_info(&self, channel_id: [u8; 16], info: &ChannelInfo);
    fn get_channel_info(&self, channel_id: [u8; 16]) -> Option<ChannelInfo>;
    fn invalidate_channel_info(&self, channel_id: [u8; 16]);

    fn put_channel_devices(&self, channel_id: [u8; 16], devices: &[DeviceInfo]);
    fn get_channel_devices(&self, channel_id: [u8; 16]) -> Option<Vec<DeviceInfo>>;

    fn put_channel_dispatch_targets(&self, channel_id: [u8; 16], targets: &[DispatchTarget]);
    fn get_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
    ) -> Option<DispatchTargetsCacheEntry>;

    fn dispatch_targets_cache_ttl_ms(&self) -> i64;
}
