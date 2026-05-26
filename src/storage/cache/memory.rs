use std::sync::Arc;

use chrono::Utc;
use scc::HashCache;

use crate::{
    runtime_config::{GatewayRuntimeProfile, RuntimeTuning},
    storage::{ChannelInfo, DeviceInfo, DispatchTarget},
};

use super::{CacheAccess, CacheMemorySnapshot, DispatchTargetsCacheEntry};

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
        Self::with_profile(GatewayRuntimeProfile::Small)
    }

    #[must_use]
    pub fn with_profile(profile: GatewayRuntimeProfile) -> Self {
        let caps = RuntimeTuning::for_profile(profile).cache;
        Self {
            device_cache: Arc::new(HashCache::with_capacity(caps.device_min, caps.device_max)),
            channel_info_cache: Arc::new(HashCache::with_capacity(
                caps.channel_info_min,
                caps.channel_info_max,
            )),
            channel_devices_cache: Arc::new(HashCache::with_capacity(
                caps.channel_devices_min,
                caps.channel_devices_max,
            )),
            channel_dispatch_targets_cache: Arc::new(HashCache::with_capacity(
                caps.dispatch_targets_min,
                caps.dispatch_targets_max,
            )),
            dispatch_targets_cache_ttl_ms: caps.dispatch_targets_ttl_ms,
        }
    }

    pub fn memory_snapshot(&self) -> CacheMemorySnapshot {
        let mut device_cache_token_bytes = 0usize;
        self.device_cache.iter_sync(|_, value| {
            device_cache_token_bytes =
                device_cache_token_bytes.saturating_add(value.token_raw.len());
            true
        });

        let mut channel_info_alias_bytes = 0usize;
        self.channel_info_cache.iter_sync(|_, value| {
            channel_info_alias_bytes = channel_info_alias_bytes.saturating_add(value.alias.len());
            true
        });

        let mut channel_devices_device_entries = 0usize;
        let mut channel_devices_token_bytes = 0usize;
        self.channel_devices_cache.iter_sync(|_, value| {
            channel_devices_device_entries =
                channel_devices_device_entries.saturating_add(value.len());
            for device in value {
                channel_devices_token_bytes =
                    channel_devices_token_bytes.saturating_add(device.token_raw.len());
            }
            true
        });

        let mut dispatch_targets_target_entries = 0usize;
        let mut dispatch_targets_heap_bytes = 0usize;
        self.channel_dispatch_targets_cache.iter_sync(|_, value| {
            dispatch_targets_target_entries =
                dispatch_targets_target_entries.saturating_add(value.targets.len());
            dispatch_targets_heap_bytes = dispatch_targets_heap_bytes.saturating_add(
                value
                    .targets
                    .iter()
                    .map(dispatch_target_heap_bytes)
                    .sum::<usize>(),
            );
            true
        });

        CacheMemorySnapshot {
            device_cache_entries: self.device_cache.len(),
            device_cache_token_bytes,
            channel_info_cache_entries: self.channel_info_cache.len(),
            channel_info_alias_bytes,
            channel_devices_cache_entries: self.channel_devices_cache.len(),
            channel_devices_device_entries,
            channel_devices_token_bytes,
            dispatch_targets_cache_entries: self.channel_dispatch_targets_cache.len(),
            dispatch_targets_target_entries,
            dispatch_targets_heap_bytes,
        }
    }
}

fn dispatch_target_heap_bytes(target: &DispatchTarget) -> usize {
    match target {
        DispatchTarget::Provider {
            provider_token,
            device_key,
            ..
        } => provider_token.len().saturating_add(device_key.len()),
        DispatchTarget::Private { device_key, .. } => {
            16usize.saturating_add(device_key.as_ref().map_or(0, String::len))
        }
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
