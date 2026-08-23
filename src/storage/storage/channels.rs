use super::*;
use crate::storage::database::{
    ChannelQueryDatabaseAccess, PrivateChannelDatabaseAccess, ProviderSubscriptionDatabaseAccess,
};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Notify, Semaphore};

const DISPATCH_TARGETS_CACHE_EFFECTIVE_AT_SKEW_MS: i64 = 5;
const PASSWORD_KDF_CONCURRENCY: usize = 4;
const PASSWORD_KDF_MAX_PENDING_UNIQUE: usize = 128;
const PASSWORD_KDF_PERMIT_WAIT: Duration = Duration::from_secs(3);
const PASSWORD_SINGLEFLIGHT_WAIT: Duration = Duration::from_secs(10);
const PASSWORD_SUCCESS_CACHE_TTL: Duration = Duration::from_secs(5);
const PASSWORD_SUCCESS_CACHE_CAPACITY: usize = 4_096;
static PASSWORD_KDF_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(PASSWORD_KDF_CONCURRENCY)));
static PASSWORD_KDF_PENDING_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(PASSWORD_KDF_MAX_PENDING_UNIQUE)));

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ChannelPasswordProof {
    channel_id: [u8; 16],
    proof: [u8; blake3::OUT_LEN],
}

#[derive(Clone)]
enum SharedPasswordResult {
    Verified(String),
    Mismatch,
    Busy,
    Failed(String),
}

impl SharedPasswordResult {
    fn into_store_result(self) -> StoreResult<String> {
        match self {
            Self::Verified(password_hash) => Ok(password_hash),
            Self::Mismatch => Err(StoreError::ChannelPasswordMismatch),
            Self::Busy => Err(StoreError::PasswordKdfBusy),
            Self::Failed(detail) => Err(StoreError::PasswordHash(detail)),
        }
    }

    fn from_store_result(result: &StoreResult<String>) -> Self {
        match result {
            Ok(password_hash) => Self::Verified(password_hash.clone()),
            Err(StoreError::ChannelPasswordMismatch) => Self::Mismatch,
            Err(StoreError::PasswordKdfBusy) => Self::Busy,
            Err(StoreError::PasswordHash(detail)) => Self::Failed(detail.clone()),
            Err(err) => Self::Failed(err.to_string()),
        }
    }
}

struct ChannelPasswordFlight {
    result: Mutex<Option<SharedPasswordResult>>,
    completed: Notify,
}

impl ChannelPasswordFlight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            completed: Notify::new(),
        }
    }

    fn result(&self) -> Option<SharedPasswordResult> {
        self.result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn complete(&self, result: SharedPasswordResult) {
        *self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.completed.notify_waiters();
    }
}

pub(super) struct ChannelPasswordGate {
    proof_key: [u8; blake3::KEY_LEN],
    successes: Mutex<HashMap<ChannelPasswordProof, (Instant, String)>>,
    flights: Mutex<HashMap<ChannelPasswordProof, Arc<ChannelPasswordFlight>>>,
    #[cfg(test)]
    kdf_runs: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for ChannelPasswordGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let success_count = self
            .successes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        let flight_count = self
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        formatter
            .debug_struct("ChannelPasswordGate")
            .field("success_count", &success_count)
            .field("flight_count", &flight_count)
            .finish_non_exhaustive()
    }
}

impl ChannelPasswordGate {
    pub(super) fn new() -> Self {
        Self {
            proof_key: rand::random(),
            successes: Mutex::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            #[cfg(test)]
            kdf_runs: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn proof(
        &self,
        channel_id: [u8; 16],
        password_hash: &str,
        password: &str,
    ) -> ChannelPasswordProof {
        let mut hasher = blake3::Hasher::new_keyed(&self.proof_key);
        hasher.update(b"pushgo.gateway.channel.password.success.v1");
        hasher.update(&channel_id);
        hasher.update(&(password_hash.len() as u64).to_le_bytes());
        hasher.update(password_hash.as_bytes());
        hasher.update(&(password.len() as u64).to_le_bytes());
        hasher.update(password.as_bytes());
        ChannelPasswordProof {
            channel_id,
            proof: *hasher.finalize().as_bytes(),
        }
    }

    fn cached_success(&self, proof: ChannelPasswordProof) -> Option<String> {
        let now = Instant::now();
        let mut successes = self
            .successes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match successes.get(&proof).cloned() {
            Some((expires_at, password_hash)) if expires_at > now => Some(password_hash),
            Some(_) => {
                successes.remove(&proof);
                None
            }
            None => None,
        }
    }

    fn cache_success(&self, proof: ChannelPasswordProof, password_hash: String) {
        let now = Instant::now();
        let mut successes = self
            .successes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        successes.retain(|_, (expires_at, _)| *expires_at > now);
        if successes.len() >= PASSWORD_SUCCESS_CACHE_CAPACITY
            && let Some(evicted) = successes.keys().next().copied()
        {
            successes.remove(&evicted);
        }
        successes.insert(proof, (now + PASSWORD_SUCCESS_CACHE_TTL, password_hash));
    }

    fn invalidate_channel(&self, channel_id: [u8; 16]) {
        self.successes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|proof, _| proof.channel_id != channel_id);
    }

    fn join_or_start(&self, proof: ChannelPasswordProof) -> (Arc<ChannelPasswordFlight>, bool) {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(flight) = flights.get(&proof) {
            return (Arc::clone(flight), false);
        }
        let flight = Arc::new(ChannelPasswordFlight::new());
        flights.insert(proof, Arc::clone(&flight));
        (flight, true)
    }

    fn finish(
        &self,
        proof: ChannelPasswordProof,
        flight: &Arc<ChannelPasswordFlight>,
        result: SharedPasswordResult,
    ) {
        flight.complete(result);
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if flights
            .get(&proof)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            flights.remove(&proof);
        }
    }

    #[cfg(test)]
    fn record_kdf_run(&self) {
        self.kdf_runs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(test))]
    fn record_kdf_run(&self) {}

    #[cfg(test)]
    pub(super) fn reset_kdf_runs(&self) {
        self.kdf_runs.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(super) fn kdf_runs(&self) -> usize {
        self.kdf_runs.load(std::sync::atomic::Ordering::Relaxed)
    }
}

struct ChannelPasswordFlightGuard {
    gate: Arc<ChannelPasswordGate>,
    proof: ChannelPasswordProof,
    flight: Arc<ChannelPasswordFlight>,
    armed: bool,
}

impl ChannelPasswordFlightGuard {
    fn new(
        gate: Arc<ChannelPasswordGate>,
        proof: ChannelPasswordProof,
        flight: Arc<ChannelPasswordFlight>,
    ) -> Self {
        Self {
            gate,
            proof,
            flight,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChannelPasswordFlightGuard {
    fn drop(&mut self) {
        if self.armed {
            self.gate
                .finish(self.proof, &self.flight, SharedPasswordResult::Busy);
        }
    }
}

async fn wait_for_password_flight(flight: &ChannelPasswordFlight) -> StoreResult<String> {
    loop {
        let notified = flight.completed.notified();
        if let Some(result) = flight.result() {
            return result.into_store_result();
        }
        tokio::time::timeout(PASSWORD_SINGLEFLIGHT_WAIT, notified)
            .await
            .map_err(|_| StoreError::PasswordKdfBusy)?;
    }
}

async fn acquire_password_kdf_permits() -> StoreResult<(
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
)> {
    let pending = Arc::clone(&PASSWORD_KDF_PENDING_PERMITS)
        .try_acquire_owned()
        .map_err(|_| StoreError::PasswordKdfBusy)?;
    let execution = tokio::time::timeout(
        PASSWORD_KDF_PERMIT_WAIT,
        Arc::clone(&PASSWORD_KDF_PERMITS).acquire_owned(),
    )
    .await
    .map_err(|_| StoreError::PasswordKdfBusy)?
    .map_err(|_| StoreError::PasswordKdfBusy)?;
    Ok((pending, execution))
}

#[allow(dead_code)]
async fn encode_channel_auth_input_async(
    _gate: Arc<ChannelPasswordGate>,
    password: &str,
) -> StoreResult<String> {
    let (pending, execution) = acquire_password_kdf_permits().await?;
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        let _pending = pending;
        let _execution = execution;
        hash_channel_password(&password)
    })
    .await
    .map_err(|err| StoreError::PasswordHash(err.to_string()))?
}

async fn verify_channel_password_async(
    gate: Arc<ChannelPasswordGate>,
    password_hash: &str,
    password: &str,
) -> StoreResult<ChannelPasswordVerifyOutcome> {
    let (pending, execution) = acquire_password_kdf_permits().await?;
    let password_hash = password_hash.to_string();
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        let _pending = pending;
        let _execution = execution;
        gate.record_kdf_run();
        verify_channel_password(&password_hash, &password)
    })
    .await
    .map_err(|err| StoreError::PasswordHash(format!("password verification task failed: {err}")))?
}

impl Storage {
    pub async fn subscribe_channel_for_device_key(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
        device_key: &str,
        provider_token: &str,
        platform: Platform,
    ) -> StoreResult<SubscribeOutcome> {
        let device_info = DeviceInfo::from_token(platform, provider_token)?;
        let device_id = device_info.device_id();

        let password_hash = if let Some(id) = channel_id {
            let info = self
                .load_channel_info_for_password(id)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            self.verify_channel_password_and_maybe_upgrade(
                id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?
        } else {
            hash_channel_password(password)?
        };

        let outcome = self
            .db
            .subscribe_channel_for_device_key(
                channel_id,
                alias,
                &password_hash,
                device_key,
                provider_token,
                platform,
            )
            .await?;

        self.cache.put_device(device_id, &device_info);
        self.cache.invalidate_channel_devices(outcome.channel_id);
        self.cache.put_channel_info(
            outcome.channel_id,
            &ChannelInfo {
                alias: outcome.alias.clone(),
                password_hash,
            },
        );

        Ok(outcome)
    }

    pub async fn unsubscribe_channel_for_device_key(
        &self,
        channel_id: [u8; 16],
        device_key: &str,
    ) -> StoreResult<bool> {
        let removed = self
            .db
            .unsubscribe_channel_for_device_key(channel_id, device_key)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(removed)
    }

    pub async fn unsubscribe_channel_if_provider_route_current(
        &self,
        channel_id: [u8; 16],
        device_key: &str,
        platform: Platform,
        provider_token: &str,
        route_updated_at: i64,
    ) -> StoreResult<bool> {
        let removed = self
            .db
            .unsubscribe_channel_if_provider_route_current(
                channel_id,
                device_key,
                platform,
                provider_token,
                route_updated_at,
            )
            .await?;
        if removed {
            self.cache.invalidate_channel_devices(channel_id);
        }
        Ok(removed)
    }

    pub async fn channel_info(&self, channel_id: [u8; 16]) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            return Ok(Some(info));
        }
        let info = self.db.channel_info(channel_id).await?;
        if let Some(ref info_ref) = info {
            self.cache.put_channel_info(channel_id, info_ref);
        }
        Ok(info)
    }

    pub async fn list_channel_devices(&self, channel_id: [u8; 16]) -> StoreResult<Vec<DeviceInfo>> {
        if let Some(devices) = self.cache.get_channel_devices(channel_id) {
            return Ok(devices);
        }
        let devices = self.db.list_channel_devices(channel_id).await?;
        self.cache.put_channel_devices(channel_id, &devices);
        Ok(devices)
    }

    pub async fn list_channel_dispatch_targets(
        &self,
        channel_id: [u8; 16],
        effective_at: i64,
    ) -> StoreResult<Vec<DispatchTarget>> {
        let now = chrono::Utc::now().timestamp_millis();
        let use_cache = (effective_at - now).abs() <= DISPATCH_TARGETS_CACHE_EFFECTIVE_AT_SKEW_MS;

        if use_cache && let Some(entry) = self.cache.get_channel_dispatch_targets(channel_id) {
            let age_ms = chrono::Utc::now().timestamp_millis() - entry.cached_at_ms;
            if age_ms >= 0 && age_ms <= self.cache.dispatch_targets_cache_ttl_ms() {
                return Ok(entry.targets);
            }
        }

        let targets = self
            .db
            .list_channel_dispatch_targets(channel_id, effective_at)
            .await?;

        if use_cache {
            self.cache
                .put_channel_dispatch_targets(channel_id, &targets);
        }

        Ok(targets)
    }

    pub async fn list_subscribed_channels_for_device_key(
        &self,
        device_key: &str,
    ) -> StoreResult<Vec<[u8; 16]>> {
        self.db
            .list_subscribed_channels_for_device_key(device_key)
            .await
    }

    pub async fn list_private_subscribed_channels_for_device(
        &self,
        device_id: DeviceId,
    ) -> StoreResult<Vec<[u8; 16]>> {
        self.db
            .list_private_subscribed_channels_for_device(device_id)
            .await
    }

    pub async fn channel_info_with_password(
        &self,
        channel_id: [u8; 16],
        password: &str,
    ) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            let password_hash = self
                .verify_channel_password_and_maybe_upgrade(
                    channel_id,
                    &info.password_hash,
                    password,
                    Some(&info.alias),
                )
                .await?;
            return Ok(Some(ChannelInfo {
                alias: info.alias,
                password_hash,
            }));
        }
        let Some(info) = self.load_channel_info_for_password(channel_id).await? else {
            return Ok(None);
        };
        let password_hash = self
            .verify_channel_password_and_maybe_upgrade(
                channel_id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?;
        let info = ChannelInfo {
            alias: info.alias,
            password_hash,
        };
        self.cache.put_channel_info(channel_id, &info);
        Ok(Some(info))
    }

    pub async fn rename_channel(
        &self,
        channel_id: [u8; 16],
        password: &str,
        alias: &str,
    ) -> StoreResult<()> {
        let loaded = self
            .load_channel_info_for_password(channel_id)
            .await?
            .ok_or(StoreError::ChannelNotFound)?;
        let password_hash = self
            .verify_channel_password_and_maybe_upgrade(
                channel_id,
                &loaded.password_hash,
                password,
                Some(&loaded.alias),
            )
            .await?;
        self.db.rename_channel(channel_id, alias).await?;
        self.cache.put_channel_info(
            channel_id,
            &ChannelInfo {
                alias: alias.to_string(),
                password_hash,
            },
        );
        Ok(())
    }

    pub async fn upsert_private_channel(
        &self,
        channel_id: Option<[u8; 16]>,
        alias: Option<&str>,
        password: &str,
    ) -> StoreResult<SubscribeOutcome> {
        let password_hash = if let Some(id) = channel_id {
            let info = self
                .load_channel_info_for_password(id)
                .await?
                .ok_or(StoreError::ChannelNotFound)?;
            self.verify_channel_password_and_maybe_upgrade(
                id,
                &info.password_hash,
                password,
                Some(&info.alias),
            )
            .await?
        } else {
            hash_channel_password(password)?
        };
        let outcome = self
            .db
            .upsert_private_channel(channel_id, alias, &password_hash)
            .await?;
        self.cache.invalidate_channel_devices(outcome.channel_id);
        self.cache.put_channel_info(
            outcome.channel_id,
            &ChannelInfo {
                alias: outcome.alias.clone(),
                password_hash,
            },
        );
        Ok(outcome)
    }

    pub async fn private_subscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        self.db
            .private_subscribe_channel(channel_id, device_id)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(())
    }

    pub async fn private_unsubscribe_channel(
        &self,
        channel_id: [u8; 16],
        device_id: DeviceId,
    ) -> StoreResult<()> {
        self.db
            .private_unsubscribe_channel(channel_id, device_id)
            .await?;
        self.cache.invalidate_channel_devices(channel_id);
        Ok(())
    }

    pub async fn list_private_subscribers(
        &self,
        channel_id: [u8; 16],
        subscribed_at_or_before: i64,
    ) -> StoreResult<Vec<DeviceId>> {
        self.db
            .list_private_subscribers(channel_id, subscribed_at_or_before)
            .await
    }

    async fn verify_channel_password_and_maybe_upgrade(
        &self,
        channel_id: [u8; 16],
        password_hash: &str,
        password: &str,
        alias: Option<&str>,
    ) -> StoreResult<String> {
        if channel_password_uses_current_scheme(password_hash) {
            verify_channel_password(password_hash, password)?;
            return Ok(password_hash.to_string());
        }

        let gate = Arc::clone(&self.channel_password_gate);
        let proof = gate.proof(channel_id, password_hash, password);
        if let Some(cached_hash) = gate.cached_success(proof) {
            return Ok(cached_hash);
        }

        let (flight, leader) = gate.join_or_start(proof);
        if !leader {
            return wait_for_password_flight(&flight).await;
        }
        let mut flight_guard =
            ChannelPasswordFlightGuard::new(Arc::clone(&gate), proof, Arc::clone(&flight));

        let result = async {
            let verify_outcome =
                verify_channel_password_async(Arc::clone(&gate), password_hash, password).await?;
            if !verify_outcome.needs_upgrade() {
                gate.cache_success(proof, password_hash.to_string());
                return Ok(password_hash.to_string());
            }

            let upgraded_hash = hash_channel_password(password)?;
            self.db
                .update_channel_password_hash(channel_id, upgraded_hash.as_str())
                .await?;
            gate.invalidate_channel(channel_id);
            if let Some(alias) = alias {
                self.cache.put_channel_info(
                    channel_id,
                    &ChannelInfo {
                        alias: alias.to_string(),
                        password_hash: upgraded_hash.clone(),
                    },
                );
            } else {
                self.cache.invalidate_channel_info(channel_id);
            }
            gate.cache_success(proof, upgraded_hash.clone());
            Ok(upgraded_hash)
        }
        .await;

        let shared = SharedPasswordResult::from_store_result(&result);
        gate.finish(proof, &flight, shared);
        flight_guard.disarm();
        result
    }

    async fn load_channel_info_for_password(
        &self,
        channel_id: [u8; 16],
    ) -> StoreResult<Option<ChannelInfo>> {
        if let Some(info) = self.cache.get_channel_info(channel_id) {
            return Ok(Some(info));
        }
        let loaded = self.db.channel_info_with_password(channel_id).await?;
        let Some((info, hash)) = loaded else {
            return Ok(None);
        };
        let info = ChannelInfo {
            alias: info.alias,
            password_hash: hash,
        };
        self.cache.put_channel_info(channel_id, &info);
        Ok(Some(info))
    }
}
