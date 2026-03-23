use std::hash::{Hash, Hasher};

use hashbrown::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::util::generate_hex_id_128;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceChannelType {
    Apns,
    Fcm,
    Wns,
    Private,
}

impl DeviceChannelType {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceChannelType::Apns => "apns",
            DeviceChannelType::Fcm => "fcm",
            DeviceChannelType::Wns => "wns",
            DeviceChannelType::Private => "private",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("apns") {
            Some(DeviceChannelType::Apns)
        } else if trimmed.eq_ignore_ascii_case("fcm") {
            Some(DeviceChannelType::Fcm)
        } else if trimmed.eq_ignore_ascii_case("wns") {
            Some(DeviceChannelType::Wns)
        } else if trimmed.eq_ignore_ascii_case("private") {
            Some(DeviceChannelType::Private)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRouteRecord {
    pub platform: String,
    pub channel_type: DeviceChannelType,
    pub provider_token: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegistryStats {
    pub total_devices: usize,
    pub ios_devices: usize,
    pub macos_devices: usize,
    pub watchos_devices: usize,
    pub android_devices: usize,
    pub windows_devices: usize,
    pub provider_routes: usize,
}

pub struct DeviceRegistry {
    state: RwLock<DeviceRegistryState>,
}

#[derive(Default)]
struct DeviceRegistryState {
    by_device: HashMap<String, DeviceRouteRecord>,
    by_provider: HashMap<ProviderTokenKey, String>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        DeviceRegistry {
            state: RwLock::new(DeviceRegistryState::default()),
        }
    }

    pub fn register_device(
        &self,
        platform: &str,
        device_key: Option<&str>,
    ) -> Result<String, String> {
        let now = chrono::Utc::now().timestamp();
        let mut state = self.state.write();
        if let Some(key) = device_key.map(str::trim).filter(|value| !value.is_empty()) {
            if state.by_device.contains_key(key) {
                return Ok(key.to_string());
            }
            // Unknown device_key should be discarded. Behave as "device_key not provided":
            // issue a new one instead of accepting unknown key from client.
        }

        let key = loop {
            let candidate = generate_device_key();
            if !state.by_device.contains_key(candidate.as_str()) {
                break candidate;
            }
        };

        state
            .by_device
            .insert(key.clone(), default_route_for_platform(platform, now));
        Ok(key)
    }

    pub fn restore_route(
        &self,
        device_key: &str,
        mut route: DeviceRouteRecord,
    ) -> Result<(), String> {
        let key = device_key.trim();
        if key.is_empty() {
            return Err("device_key is required".to_string());
        }
        route.platform = route.platform.trim().to_ascii_lowercase();
        if route.platform.is_empty() {
            return Err("platform is required".to_string());
        }
        route.provider_token = normalized_provider_token(route.provider_token);

        let mut state = self.state.write();
        if let Some(previous) = state.by_device.get(key)
            && let Some(old_key) = ProviderTokenKey::from_route(previous)
        {
            state.by_provider.remove(&old_key);
        }
        if let Some(new_key) = ProviderTokenKey::from_route(&route) {
            state.by_provider.insert(new_key, key.to_string());
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
        let now = chrono::Utc::now().timestamp();
        let mut state = self.state.write();
        let old_key = state
            .by_device
            .get(device_key)
            .ok_or_else(|| "device_key not found".to_string())?;
        let old_key = ProviderTokenKey::from_route(old_key);

        if let Some(old_key) = old_key {
            state.by_provider.remove(&old_key);
        }

        let (result, new_key) = {
            let rec = state
                .by_device
                .get_mut(device_key)
                .ok_or_else(|| "device_key not found".to_string())?;

            rec.channel_type = channel_type;
            rec.provider_token = normalized_provider_token(provider_token);
            rec.updated_at = now;

            (rec.clone(), ProviderTokenKey::from_route(rec))
        };

        if let Some(new_key) = new_key {
            state.by_provider.insert(new_key, device_key.to_string());
        }

        Ok(result)
    }

    pub fn clear_channel(
        &self,
        device_key: &str,
        channel_type: DeviceChannelType,
    ) -> Result<DeviceRouteRecord, String> {
        let now = chrono::Utc::now().timestamp();
        let mut state = self.state.write();
        let old_key = state
            .by_device
            .get(device_key)
            .ok_or_else(|| "device_key not found".to_string())?;
        let old_key = ProviderTokenKey::from_route(old_key);
        if let Some(old_key) = old_key {
            state.by_provider.remove(&old_key);
        }
        let result = {
            let rec = state
                .by_device
                .get_mut(device_key)
                .ok_or_else(|| "device_key not found".to_string())?;
            if rec.channel_type == channel_type {
                rec.provider_token = None;
                rec.updated_at = now;
            }
            rec.clone()
        };
        Ok(result)
    }

    pub fn get(&self, device_key: &str) -> Option<DeviceRouteRecord> {
        let state = self.state.read();
        state.by_device.get(device_key).cloned()
    }

    pub fn find_by_provider_token(
        &self,
        platform: &str,
        provider_token: &str,
    ) -> Option<DeviceRouteRecord> {
        let key = ProviderTokenKey::new(platform, provider_token)?;
        let state = self.state.read();
        let device_key = state.by_provider.get(&key)?;
        state.by_device.get(device_key.as_str()).cloned()
    }

    pub fn find_device_key_by_provider_token(
        &self,
        platform: &str,
        provider_token: &str,
    ) -> Option<String> {
        let key = ProviderTokenKey::new(platform, provider_token)?;
        let state = self.state.read();
        state.by_provider.get(&key).cloned()
    }

    pub fn resolve_provider_route_by_token(
        &self,
        platform: &str,
        provider_token: &str,
    ) -> Option<String> {
        let key = ProviderTokenKey::new(platform, provider_token)?;
        let state = self.state.read();
        state.by_provider.get(&key).cloned()
    }

    pub fn derive_private_device_id(device_key: &str) -> [u8; 16] {
        let hash = blake3::hash(device_key.as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&hash.as_bytes()[..16]);
        out
    }

    pub fn stats(&self) -> DeviceRegistryStats {
        let state = self.state.read();
        let mut stats = DeviceRegistryStats {
            total_devices: state.by_device.len(),
            provider_routes: state.by_provider.len(),
            ..DeviceRegistryStats::default()
        };

        for route in state.by_device.values() {
            match route.platform.as_str() {
                "ios" => stats.ios_devices += 1,
                "macos" => stats.macos_devices += 1,
                "watchos" => stats.watchos_devices += 1,
                "android" => stats.android_devices += 1,
                "windows" => stats.windows_devices += 1,
                _ => {}
            }
        }

        stats
    }

    pub fn clear_all(&self) {
        let mut state = self.state.write();
        state.by_device.clear();
        state.by_provider.clear();
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn normalized_provider_token(provider_token: Option<String>) -> Option<String> {
    provider_token.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn default_route_for_platform(platform: &str, updated_at: i64) -> DeviceRouteRecord {
    DeviceRouteRecord {
        platform: platform.trim().to_ascii_lowercase(),
        channel_type: default_channel_for_platform(platform),
        provider_token: None,
        updated_at,
    }
}

fn generate_device_key() -> String {
    generate_hex_id_128()
}

fn default_channel_for_platform(platform: &str) -> DeviceChannelType {
    let trimmed = platform.trim();
    if trimmed.eq_ignore_ascii_case("android") {
        DeviceChannelType::Fcm
    } else if trimmed.eq_ignore_ascii_case("windows") || trimmed.eq_ignore_ascii_case("win") {
        DeviceChannelType::Wns
    } else {
        DeviceChannelType::Apns
    }
}

#[derive(Debug, Clone, Eq)]
struct ProviderTokenKey {
    platform: String,
    token: String,
}

impl ProviderTokenKey {
    fn new(platform: &str, token: &str) -> Option<Self> {
        let normalized_platform = platform.trim().to_ascii_lowercase();
        let normalized_token = token.trim();
        if normalized_platform.is_empty() || normalized_token.is_empty() {
            return None;
        }
        Some(Self {
            platform: normalized_platform,
            token: normalized_token.to_string(),
        })
    }

    fn from_route(route: &DeviceRouteRecord) -> Option<Self> {
        let token = route.provider_token.as_deref()?;
        Self::new(route.platform.as_str(), token)
    }
}

impl PartialEq for ProviderTokenKey {
    fn eq(&self, other: &Self) -> bool {
        self.platform == other.platform && self.token == other.token
    }
}

impl Hash for ProviderTokenKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.platform.hash(state);
        self.token.hash(state);
    }
}
