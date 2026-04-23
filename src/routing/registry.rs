use std::hash::{Hash, Hasher};

use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::storage::Platform;
use crate::util::generate_hex_id_128;

use super::types::{default_route_for_platform, normalize_provider_token};
use super::{DeviceChannelType, DeviceRegistryStats, DeviceRouteRecord};

const REPLACED_DEVICE_KEY_TTL_SECS: i64 = 10 * 60;

#[derive(Debug, Clone)]
pub struct RetiredProviderRoute {
    pub device_key: String,
    pub previous: DeviceRouteRecord,
    pub updated: DeviceRouteRecord,
}

pub struct DeviceRegistry {
    state: RwLock<DeviceRegistryState>,
}

#[derive(Default)]
struct DeviceRegistryState {
    by_device: HashMap<String, DeviceRouteRecord>,
    // Provider ingress still needs a token-indexed lookup path to map incoming
    // provider callbacks back onto the canonical device_key identity.
    provider_ingress_index: HashMap<ProviderIngressKey, String>,
    replaced_device_keys: HashMap<String, ReplacedDeviceKey>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        DeviceRegistry {
            state: RwLock::new(DeviceRegistryState::default()),
        }
    }

    pub fn register_device(
        &self,
        platform: Platform,
        device_key: Option<&str>,
    ) -> Result<String, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut state = self.state.write();
        if let Some(key) = device_key.map(str::trim).filter(|value| !value.is_empty())
            && state.by_device.contains_key(key)
        {
            return Ok(key.to_string());
        }

        let key = loop {
            let candidate = generate_hex_id_128();
            if !state.by_device.contains_key(candidate.as_str()) {
                break candidate;
            }
        };

        state
            .by_device
            .insert(key.clone(), default_route_for_platform(platform, now));
        Ok(key)
    }

    pub fn allocate_device_key(&self) -> String {
        let state = self.state.read();
        loop {
            let candidate = generate_hex_id_128();
            if !state.by_device.contains_key(candidate.as_str()) {
                return candidate;
            }
        }
    }

    pub fn restore_route(&self, device_key: &str, route: DeviceRouteRecord) -> Result<(), String> {
        let key = device_key.trim();
        if key.is_empty() {
            return Err("device_key is required".to_string());
        }
        let route = route.normalized();

        let mut state = self.state.write();
        if let Some(previous) = state.by_device.get(key)
            && let Some(old_key) = ProviderIngressKey::from_route(previous)
        {
            state.provider_ingress_index.remove(&old_key);
        }
        if let Some(new_key) = ProviderIngressKey::from_route(&route) {
            state
                .provider_ingress_index
                .insert(new_key, key.to_string());
        }
        state.by_device.insert(key.to_string(), route);
        Ok(())
    }

    pub fn update_channel(
        &self,
        device_key: &str,
        channel_type: DeviceChannelType,
        provider_token: Option<String>,
    ) -> Result<DeviceRouteRecord, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut state = self.state.write();
        let old_key = state
            .by_device
            .get(device_key)
            .ok_or_else(|| "device_key not found".to_string())?;
        let old_key = ProviderIngressKey::from_route(old_key);

        if let Some(old_key) = old_key {
            state.provider_ingress_index.remove(&old_key);
        }

        let (result, new_key) = {
            let rec = state
                .by_device
                .get_mut(device_key)
                .ok_or_else(|| "device_key not found".to_string())?;

            rec.channel_type = channel_type;
            rec.provider_token = normalize_provider_token(provider_token);
            rec.updated_at = now;

            (rec.clone(), ProviderIngressKey::from_route(rec))
        };

        if let Some(new_key) = new_key {
            state
                .provider_ingress_index
                .insert(new_key, device_key.to_string());
        }

        Ok(result)
    }

    pub fn clear_channel(
        &self,
        device_key: &str,
        channel_type: DeviceChannelType,
    ) -> Result<DeviceRouteRecord, String> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut state = self.state.write();
        let old_key = {
            let rec = state
                .by_device
                .get(device_key)
                .ok_or_else(|| "device_key not found".to_string())?;
            if rec.channel_type != channel_type {
                return Err("channel_type mismatch".to_string());
            }
            ProviderIngressKey::from_route(rec)
        };
        if let Some(old_key) = old_key {
            state.provider_ingress_index.remove(&old_key);
        }
        let rec = state
            .by_device
            .get_mut(device_key)
            .ok_or_else(|| "device_key not found".to_string())?;
        rec.provider_token = None;
        rec.updated_at = now;
        Ok(rec.clone())
    }

    pub fn remove_device(&self, device_key: &str) -> Option<DeviceRouteRecord> {
        let key = device_key.trim();
        if key.is_empty() {
            return None;
        }
        let mut state = self.state.write();
        let previous = state.by_device.remove(key)?;
        if let Some(provider_key) = ProviderIngressKey::from_route(&previous) {
            state.provider_ingress_index.remove(&provider_key);
        }
        Some(previous)
    }

    pub fn remember_replaced_device_key(
        &self,
        previous_device_key: &str,
        replacement_device_key: &str,
        platform: Platform,
    ) {
        let previous_device_key = previous_device_key.trim();
        let replacement_device_key = replacement_device_key.trim();
        if previous_device_key.is_empty()
            || replacement_device_key.is_empty()
            || previous_device_key == replacement_device_key
        {
            return;
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut state = self.state.write();
        state.purge_expired_replaced_device_keys(now);
        state.replaced_device_keys.insert(
            previous_device_key.to_string(),
            ReplacedDeviceKey {
                device_key: replacement_device_key.to_string(),
                platform,
                recorded_at: now,
            },
        );
    }

    pub fn resolve_replaced_device_key(
        &self,
        previous_device_key: &str,
        platform: Platform,
    ) -> Option<String> {
        let key = previous_device_key.trim();
        if key.is_empty() {
            return None;
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut state = self.state.write();
        state.purge_expired_replaced_device_keys(now);
        let replaced = state.replaced_device_keys.get(key)?;
        let route = state.by_device.get(replaced.device_key.as_str())?;
        if replaced.platform != platform || route.platform != platform {
            return None;
        }
        Some(replaced.device_key.clone())
    }

    pub fn retire_provider_token(
        &self,
        platform: Platform,
        provider_token: &str,
    ) -> Option<RetiredProviderRoute> {
        let provider_key = ProviderIngressKey::new(platform, provider_token)?;
        let now = chrono::Utc::now().timestamp_millis();
        let mut state = self.state.write();
        let device_key = state.provider_ingress_index.remove(&provider_key)?;
        let previous = state.by_device.get(device_key.as_str())?.clone();
        if previous.platform != platform
            || ProviderIngressKey::from_route(&previous).as_ref() != Some(&provider_key)
        {
            return None;
        }
        let updated = {
            let route = state.by_device.get_mut(device_key.as_str())?;
            route.channel_type = DeviceChannelType::Private;
            route.provider_token = None;
            route.updated_at = now;
            route.clone()
        };
        Some(RetiredProviderRoute {
            device_key,
            previous,
            updated,
        })
    }

    pub fn get(&self, device_key: &str) -> Option<DeviceRouteRecord> {
        let state = self.state.read();
        state.by_device.get(device_key).cloned()
    }

    pub fn resolve_provider_ingress_route(
        &self,
        platform: Platform,
        provider_token: &str,
    ) -> Option<String> {
        let key = ProviderIngressKey::new(platform, provider_token)?;
        let state = self.state.read();
        state.provider_ingress_index.get(&key).cloned()
    }

    pub fn stats(&self) -> DeviceRegistryStats {
        let state = self.state.read();
        let mut stats = DeviceRegistryStats {
            total_devices: state.by_device.len(),
            provider_routes: state.provider_ingress_index.len(),
            ..DeviceRegistryStats::default()
        };

        for route in state.by_device.values() {
            match route.platform {
                Platform::IOS => stats.ios_devices += 1,
                Platform::MACOS => stats.macos_devices += 1,
                Platform::WATCHOS => stats.watchos_devices += 1,
                Platform::ANDROID => stats.android_devices += 1,
                Platform::WINDOWS => stats.windows_devices += 1,
            }
        }

        stats
    }

    pub fn clear_all(&self) {
        let mut state = self.state.write();
        state.by_device.clear();
        state.provider_ingress_index.clear();
        state.replaced_device_keys.clear();
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Eq)]
struct ProviderIngressKey {
    platform: Platform,
    token: String,
}

#[derive(Debug, Clone)]
struct ReplacedDeviceKey {
    device_key: String,
    platform: Platform,
    recorded_at: i64,
}

impl DeviceRegistryState {
    fn purge_expired_replaced_device_keys(&mut self, now: i64) {
        self.replaced_device_keys
            .retain(|_, replaced| now - replaced.recorded_at <= REPLACED_DEVICE_KEY_TTL_SECS);
    }
}

impl ProviderIngressKey {
    fn new(platform: Platform, token: &str) -> Option<Self> {
        let normalized_token = token.trim();
        if normalized_token.is_empty() {
            return None;
        }
        Some(Self {
            platform,
            token: normalized_token.to_string(),
        })
    }

    fn from_route(route: &DeviceRouteRecord) -> Option<Self> {
        let token = route.provider_token.as_deref()?;
        Self::new(route.platform, token)
    }
}

impl PartialEq for ProviderIngressKey {
    fn eq(&self, other: &Self) -> bool {
        self.platform == other.platform && self.token == other.token
    }
}

impl Hash for ProviderIngressKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.platform.hash(state);
        self.token.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::registry::REPLACED_DEVICE_KEY_TTL_SECS;
    use crate::routing::{DeviceChannelType, DeviceRegistry};
    use crate::storage::Platform;

    #[test]
    fn register_device_defaults_to_private_route() {
        let registry = DeviceRegistry::new();
        for platform in [
            Platform::IOS,
            Platform::MACOS,
            Platform::ANDROID,
            Platform::WINDOWS,
        ] {
            let device_key = registry
                .register_device(platform, None)
                .expect("register device should succeed");
            let route = registry
                .get(device_key.as_str())
                .expect("registered route should exist");
            assert_eq!(route.channel_type, DeviceChannelType::Private);
            assert!(
                route.provider_token.is_none(),
                "newly issued route should not carry provider token"
            );
        }
    }

    #[test]
    fn clear_channel_rejects_mismatch_and_preserves_provider_index() {
        let registry = DeviceRegistry::new();
        let device_key = registry
            .register_device(Platform::IOS, None)
            .expect("register device should succeed");
        registry
            .update_channel(
                device_key.as_str(),
                DeviceChannelType::Apns,
                Some("token-1".to_string()),
            )
            .expect("update channel should succeed");
        let err = registry
            .clear_channel(device_key.as_str(), DeviceChannelType::Fcm)
            .expect_err("clear with mismatched channel type should fail");
        assert_eq!(err, "channel_type mismatch");
        let mapped = registry.resolve_provider_ingress_route(Platform::IOS, "token-1");
        assert_eq!(mapped.as_deref(), Some(device_key.as_str()));
    }

    #[test]
    fn replaced_device_key_resolution_expires_stale_mapping() {
        let registry = DeviceRegistry::new();
        let replacement = registry
            .register_device(Platform::ANDROID, None)
            .expect("replacement route should exist");
        registry.remember_replaced_device_key(
            "old-device",
            replacement.as_str(),
            Platform::ANDROID,
        );

        {
            let mut state = registry.state.write();
            let replaced = state
                .replaced_device_keys
                .get_mut("old-device")
                .expect("mapping should exist");
            replaced.recorded_at -= REPLACED_DEVICE_KEY_TTL_SECS + 1;
        }

        assert_eq!(
            registry.resolve_replaced_device_key("old-device", Platform::ANDROID),
            None,
            "expired replacement mapping should not survive beyond the coalescing window"
        );
    }
}
