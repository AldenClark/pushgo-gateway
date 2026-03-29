use std::sync::Arc;

use chrono::Utc;
use scc::HashCache;

use crate::storage::{ChannelInfo, DeviceInfo, DispatchTarget};

use super::{CacheAccess, DispatchTargetsCacheEntry};

const CHANNEL_INFO_CACHE_MIN_CAPACITY: usize = 1024;
const CHANNEL_INFO_CACHE_MAX_CAPACITY: usize = 16384;
const CHANNEL_DEVICES_CACHE_MIN_CAPACITY: usize = 2048;
const CHANNEL_DEVICES_CACHE_MAX_CAPACITY: usize = 32768;
const DISPATCH_TARGETS_CACHE_MIN_CAPACITY: usize = 2048;
const DISPATCH_TARGETS_CACHE_MAX_CAPACITY: usize = 32768;
const DEVICE_CACHE_MIN_CAPACITY: usize = 2048;
const DEVICE_CACHE_MAX_CAPACITY: usize = 32768;
const DISPATCH_TARGETS_CACHE_TTL_MS_DEFAULT: i64 = 2000;
const DISPATCH_TARGETS_CACHE_TTL_MS_MIN: i64 = 200;
const DISPATCH_TARGETS_CACHE_TTL_MS_MAX: i64 = 10_000;

#[derive(Debug, Clone)]
pub struct InMemoryCache {
    device_cache: Arc<HashCache<[u8; 32], DeviceInfo>>,
    channel_info_cache: Arc<HashCache<[u8; 16], ChannelInfo>>,
    channel_devices_cache: Arc<HashCache<[u8; 16], Vec<DeviceInfo>>>,
    channel_dispatch_targets_cache: Arc<HashCache<[u8; 16], DispatchTargetsCacheEntry>>,
    dispatch_targets_cache_ttl_ms: i64,
}

impl InMemoryCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            device_cache: Arc::new(HashCache::with_capacity(
                DEVICE_CACHE_MIN_CAPACITY,
                DEVICE_CACHE_MAX_CAPACITY,
            )),
            channel_info_cache: Arc::new(HashCache::with_capacity(
                CHANNEL_INFO_CACHE_MIN_CAPACITY,
                CHANNEL_INFO_CACHE_MAX_CAPACITY,
            )),
            channel_devices_cache: Arc::new(HashCache::with_capacity(
                CHANNEL_DEVICES_CACHE_MIN_CAPACITY,
                CHANNEL_DEVICES_CACHE_MAX_CAPACITY,
            )),
            channel_dispatch_targets_cache: Arc::new(HashCache::with_capacity(
                DISPATCH_TARGETS_CACHE_MIN_CAPACITY,
                DISPATCH_TARGETS_CACHE_MAX_CAPACITY,
            )),
            dispatch_targets_cache_ttl_ms: Self::read_dispatch_targets_cache_ttl_ms(),
        }
    }

    fn read_dispatch_targets_cache_ttl_ms() -> i64 {
        std::env::var("PUSHGO_DISPATCH_TARGETS_CACHE_TTL_MS")
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .map(|value| {
                value.clamp(
                    DISPATCH_TARGETS_CACHE_TTL_MS_MIN,
                    DISPATCH_TARGETS_CACHE_TTL_MS_MAX,
                )
            })
            .unwrap_or(DISPATCH_TARGETS_CACHE_TTL_MS_DEFAULT)
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheAccess for InMemoryCache {
    fn get_device(&self, device_id: &[u8; 32]) -> Option<DeviceInfo> {
        self.device_cache
            .read_sync(device_id, |_, value| value.clone())
    }

    fn put_device(&self, device_id: [u8; 32], device: &DeviceInfo) {
        if let Some(mut cached) = self.device_cache.get_sync(&device_id) {
            *cached = device.clone();
            return;
        }
        let _ = self.device_cache.put_sync(device_id, device.clone());
    }

    fn remove_device(&self, device_id: &[u8; 32]) -> Option<DeviceInfo> {
        self.device_cache
            .remove_sync(device_id)
            .map(|(_, value)| value)
    }

    fn clear_devices(&self) {
        self.device_cache.clear_sync();
    }

    fn invalidate_channel_devices(&self, channel_id: [u8; 16]) {
        let _ = self.channel_devices_cache.remove_sync(&channel_id);
        let _ = self.channel_dispatch_targets_cache.remove_sync(&channel_id);
    }

    fn invalidate_all_channel_devices(&self) {
        self.channel_devices_cache.clear_sync();
        self.channel_dispatch_targets_cache.clear_sync();
    }

    fn put_channel_info(&self, channel_id: [u8; 16], info: &ChannelInfo) {
        if let Some(mut cached) = self.channel_info_cache.get_sync(&channel_id) {
            *cached = info.clone();
            return;
        }
        let _ = self.channel_info_cache.put_sync(channel_id, info.clone());
    }

    fn get_channel_info(&self, channel_id: [u8; 16]) -> Option<ChannelInfo> {
        self.channel_info_cache
            .read_sync(&channel_id, |_, value| value.clone())
    }

    fn invalidate_channel_info(&self, channel_id: [u8; 16]) {
        let _ = self.channel_info_cache.remove_sync(&channel_id);
    }

    fn put_channel_devices(&self, channel_id: [u8; 16], devices: &[DeviceInfo]) {
        let copied = devices.to_vec();
        if let Some(mut cached) = self.channel_devices_cache.get_sync(&channel_id) {
            *cached = copied;
            return;
        }
        let _ = self.channel_devices_cache.put_sync(channel_id, copied);
    }

    fn get_channel_devices(&self, channel_id: [u8; 16]) -> Option<Vec<DeviceInfo>> {
        self.channel_devices_cache
            .read_sync(&channel_id, |_, value| value.clone())
    }

    fn put_channel_dispatch_targets(&self, channel_id: [u8; 16], targets: &[DispatchTarget]) {
        let entry = DispatchTargetsCacheEntry {
            cached_at_ms: Utc::now().timestamp_millis(),
            targets: targets.to_vec(),
        };

        if let Some(mut cached) = self.channel_dispatch_targets_cache.get_sync(&channel_id) {
            *cached = entry;
            return;
        }

        let _ = self
            .channel_dispatch_targets_cache
            .put_sync(channel_id, entry);
    }

    fn get_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
    ) -> Option<DispatchTargetsCacheEntry> {
        self.channel_dispatch_targets_cache
            .read_sync(&channel_id, |_, value| value.clone())
    }

    fn dispatch_targets_cache_ttl_ms(&self) -> i64 {
        self.dispatch_targets_cache_ttl_ms
    }
}
