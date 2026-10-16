//! Explicitly opt-in, local synthetic Provider substitutes for the *normal*
//! Gateway executable. No HTTP server, token service, trust override or second
//! storage lifecycle lives here. Records observe calls, not receipt COMMIT.
use crate::{
    Error,
    providers::{
        ApnsClient, BoxFuture, DispatchResult, FcmClient, ProviderFailureKind, TokenInfo,
        WnsClient, apns::ApnsPayload, fcm::FcmPayload, wns::WnsPayload,
    },
    storage::Platform,
};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs::File, io::Write, path::Path, sync::Arc, time::Duration};

const RESOURCE_INTERVAL: Duration = Duration::from_secs(5);
const RESOURCE_MAX_SAMPLES: usize = 512;
const RESOURCE_MAX_ENTRY_BYTES: usize = 64 * 1024;
const RESOURCE_MAX_FILE_BYTES: usize = 31 * 1024 * 1024;
const RESOURCE_MAX_PROFILE_BYTES: usize = 1024 * 1024;

/// A QA-only observer of the existing product owners. It neither acquires a
/// database connection nor owns work, a server, credentials or another ledger.
pub(crate) struct ResourceObservation {
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl ResourceObservation {
    pub(crate) fn start(
        directory: &Path,
        storage: crate::storage::Storage,
        private: Option<Arc<crate::private::PrivateState>>,
        counters: Arc<crate::ordinary::Counters>,
        budgets: Arc<crate::dispatch::ProviderBudgets>,
        allocator: fn() -> Value,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(directory)?;
        let file = observation_file(&directory.join("resources.jsonl"))?;
        // Reserve both fresh outputs before starting. Existing evidence is
        // never appended to, truncated or silently reused.
        let mut profile_file = observation_file(&directory.join("resources-final-profile.json"))?;
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
            let mut samples = 0;
            let mut bytes = 0;
            let mut ticker = tokio::time::interval(RESOURCE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let stopping = tokio::select! {
                    biased;
                    _ = &mut stopped => true,
                    _ = ticker.tick() => false,
                };
                let runtime = tokio::runtime::Handle::current().metrics();
                let value = json!({
                    "sequence": samples,
                    "at_ms": chrono::Utc::now().timestamp_millis(),
                    "elapsed_ms": started.elapsed().as_millis(),
                    "phase": if stopping { "shutdown" } else { "sample" },
                    "pid": std::process::id(),
                    "limits": {"interval_seconds": RESOURCE_INTERVAL.as_secs(), "max_samples": RESOURCE_MAX_SAMPLES, "max_entry_bytes": RESOURCE_MAX_ENTRY_BYTES, "max_resources_bytes": RESOURCE_MAX_FILE_BYTES, "max_final_profile_bytes": RESOURCE_MAX_PROFILE_BYTES},
                    "tokio": {"num_alive_tasks": runtime.num_alive_tasks(), "num_workers": runtime.num_workers(), "global_queue_depth": runtime.global_queue_depth()},
                    "ordinary": ordinary_resource_snapshot(&counters),
                    "provider_budget": budgets.resource_snapshot(),
                    "private": private.as_ref().map(|private| private.memory_snapshot()),
                    "storage_cache": storage.cache_memory_snapshot(),
                    "database_pools": storage.resource_pool_snapshot(),
                    "allocator": allocator(),
                    "semantics": "five-second samples, not continuous peaks; all live tasks include this QA task; metadata/byte counters only; SQL backlog observed separately"
                });
                let mut encoded = serde_json::to_vec(&value)?;
                encoded.push(b'\n');
                if encoded.len() > RESOURCE_MAX_ENTRY_BYTES {
                    return Err(std::io::Error::other("QA resource sample exceeded 64KiB"));
                }
                if samples == RESOURCE_MAX_SAMPLES
                    || bytes + encoded.len() > RESOURCE_MAX_FILE_BYTES
                {
                    break;
                }
                writer.write_all(&encoded)?;
                writer.flush()?;
                samples += 1;
                bytes += encoded.len();
                if stopping || samples == RESOURCE_MAX_SAMPLES {
                    break;
                }
            }
            // Detailed fixed-cardinality SQL histograms are copied once, never
            // every five seconds. The two observation files together stay
            // below 32MiB; sampling stops rather than rotating or accumulating.
            let profile = serde_json::to_vec(&json!({
                "at_ms": chrono::Utc::now().timestamp_millis(),
                "samples": samples,
                "resource_bytes": bytes,
                "profile": counters.profile.snapshot(),
                "scope": "final cumulative caller-lifetime histograms; SQL inclusive and nested durations cannot be summed as independent wall time"
            }))?;
            if profile.len() > RESOURCE_MAX_PROFILE_BYTES {
                return Err(std::io::Error::other("QA resource profile exceeded 1MiB"));
            }
            profile_file.write_all(&profile)?;
            profile_file.flush()?;
            writer.flush()
        });
        Ok(Self { stop, task })
    }

    pub(crate) async fn shutdown_until(
        self,
        deadline: tokio::time::Instant,
    ) -> std::io::Result<()> {
        let _ = self.stop.send(());
        let mut task = self.task;
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(std::io::Error::other(error)),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "QA resource observer did not drain",
                ))
            }
        }
    }
}

fn observation_file(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn ordinary_resource_snapshot(counters: &crate::ordinary::Counters) -> Value {
    use std::sync::atomic::{AtomicU64, Ordering};
    let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let get3 = |values: &[AtomicU64; 3]| values.each_ref().map(get);
    json!({
        "provider_order": ["FCM", "APNS", "WNS"],
        "provider_pumps_alive": get(&counters.num_alive),
        "owned_attempts": get(&counters.owned_attempts),
        "network_inflight": get(&counters.network_inflight),
        "receipts_owned": get(&counters.receipts_owned),
        "provider_owned": get3(&counters.provider_owned),
        "claim_reservations": get3(&counters.claim_reservations),
        "provider_targets": get3(&counters.provider_targets),
        "http_connections": get(&counters.http_connections),
        "admission_commits": get(&counters.admission_commits),
        "receipt_commits": get(&counters.receipt_commits),
        "ack_commits": get(&counters.ack_commits),
        "network_attempts": get(&counters.network_attempts),
        "claim_queries": get(&counters.claim_queries),
        "provider_claim_queries": get3(&counters.provider_claim_queries),
        "sql_operations_estimate": get(&counters.sql_operations),
        "db_errors": get(&counters.db_errors),
        "peak_owned_attempts": get(&counters.peak_owned_attempts),
        "peak_network_inflight": get(&counters.peak_network_inflight),
        "peak_receipts_owned": get(&counters.peak_receipts_owned),
        "peak_claim_reservations": get3(&counters.peak_claim_reservations),
        "peak_http_connections": get(&counters.peak_http_connections),
        "gate_wait": {"samples": get(&counters.gate_wait_samples), "total_us": get(&counters.gate_wait_total_us), "max_us": get(&counters.gate_wait_max_us)},
        "admission_commit": {"samples": get(&counters.admission_commit_samples), "total_us": get(&counters.admission_commit_total_us), "max_us": get(&counters.admission_commit_max_us)},
        "receipt_commit": {"samples": get(&counters.receipt_commit_samples), "total_us": get(&counters.receipt_commit_total_us), "max_us": get(&counters.receipt_commit_max_us)},
        "timings": counters.timings.snapshot(),
        "scope": "owned_attempts includes receipt COMMIT wait; provider_targets is configured activity target, not actual tasks; sql_operations is instrumentation helper estimate, not engine statement count"
    })
}

const MAX_RECORDS: usize = 256;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_RECORD_FILE_BYTES: u64 = (MAX_RECORDS * MAX_RECORD_BYTES) as u64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    synthetic_only: bool,
    #[serde(default = "default_status")]
    status: u16,
    #[serde(default)]
    statuses: Vec<u16>,
    #[serde(default)]
    delay_ms: u64,
}
fn default_status() -> u16 {
    202
}

struct State {
    file: File,
    records: usize,
    calls: u64,
    bytes: u64,
}
struct MockClient {
    scenario: Scenario,
    state: Mutex<State>,
}

/// One observation owner is shared by all three existing Provider interfaces.
pub struct ProductMockClients(Arc<MockClient>);
impl ProductMockClients {
    pub fn from_directory(directory: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = directory.canonicalize()?;
        let scenario_path = directory.join("scenario.json");
        if std::fs::metadata(&scenario_path)?.len() > 4096 {
            return Err("QA Provider scenario exceeds 4KiB".into());
        }
        let scenario: Scenario = serde_json::from_slice(&std::fs::read(scenario_path)?)?;
        if !scenario.synthetic_only
            || scenario.delay_ms > 10_000
            || scenario.statuses.len() > 32
            || !std::iter::once(&scenario.status)
                .chain(&scenario.statuses)
                .all(|status| *status == 0 || (200..=599).contains(status))
        {
            return Err(
                "QA Providers require synthetic_only=true, bounded delay and bounded status plan"
                    .into(),
            );
        }
        let record_path = directory.join("records.jsonl");
        let (records, bytes) = if record_path.exists() {
            let bytes = std::fs::metadata(&record_path)?.len();
            if bytes > MAX_RECORD_FILE_BYTES {
                return Err("QA Provider records exceed their fixed file budget".into());
            }
            let contents = std::fs::read_to_string(&record_path)?;
            if contents
                .lines()
                .any(|line| line.len() + 1 > MAX_RECORD_BYTES)
            {
                return Err("QA Provider record exceeds its fixed entry budget".into());
            }
            let records = contents.lines().count();
            if records > MAX_RECORDS {
                return Err("QA Provider record count exceeds its fixed budget".into());
            }
            (records, bytes)
        } else {
            (0, 0)
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(record_path)?;
        Ok(Self(Arc::new(MockClient {
            scenario,
            state: Mutex::new(State {
                file,
                records,
                calls: records as u64,
                bytes,
            }),
        })))
    }

    pub fn clients(&self) -> (Arc<dyn ApnsClient>, Arc<dyn FcmClient>, Arc<dyn WnsClient>) {
        (self.0.clone(), self.0.clone(), self.0.clone())
    }
}

impl MockClient {
    fn record(
        &self,
        provider: &str,
        platform: &str,
        target: &str,
        wire: &[u8],
        data: Value,
    ) -> Result<u16, Error> {
        let mut state = self.state.lock();
        let index = usize::try_from(state.calls).unwrap_or(usize::MAX);
        state.calls = state.calls.saturating_add(1);
        let status = self
            .scenario
            .statuses
            .get(index)
            .or_else(|| self.scenario.statuses.last())
            .copied()
            .unwrap_or(self.scenario.status);
        if state.records < MAX_RECORDS {
            let mut record = json!({
                "sequence":state.calls,"provider":provider,"platform":platform,
                "target_hash":blake3::hash(target.as_bytes()).to_hex().as_str(),
                "planned_status":status,"started_at_ms":chrono::Utc::now().timestamp_millis(),
                "wire_len":wire.len(),"wire_hash":blake3::hash(wire).to_hex().as_str(),
                "data":data,"wire":serde_json::from_slice::<Value>(wire).unwrap_or(Value::Null),
            });
            let mut encoded =
                serde_json::to_vec(&record).map_err(|error| Error::Internal(error.to_string()))?;
            if encoded.len() + 1 > MAX_RECORD_BYTES {
                // Observation omission never alters the sent business payload.
                record["data"] = Value::Null;
                record["wire"] = Value::Null;
                record["payload_omitted_from_observation"] = Value::Bool(true);
                encoded = serde_json::to_vec(&record)
                    .map_err(|error| Error::Internal(error.to_string()))?;
            }
            encoded.push(b'\n');
            if state.bytes.saturating_add(encoded.len() as u64) > MAX_RECORD_FILE_BYTES {
                return Ok(status);
            }
            state.file.write_all(&encoded).map_err(|error| {
                Error::Internal(format!("QA Provider observation failed: {error}"))
            })?;
            state.file.flush().map_err(|error| {
                Error::Internal(format!("QA Provider observation flush failed: {error}"))
            })?;
            state.records += 1;
            state.bytes += encoded.len() as u64;
        }
        Ok(status)
    }

    async fn finish(&self, status: Result<u16, Error>) -> DispatchResult {
        let status = match status {
            Ok(status) => status,
            Err(error) => return DispatchResult::transport(error),
        };
        if self.scenario.delay_ms != 0 {
            tokio::time::sleep(Duration::from_millis(self.scenario.delay_ms)).await;
        }
        if (200..=299).contains(&status) {
            return DispatchResult::success(status);
        }
        DispatchResult {
            success: false,
            status_code: status,
            error: None,
            failure_kind: Some(match status {
                0 => ProviderFailureKind::Transport,
                429 => ProviderFailureKind::RateLimited,
                500..=599 => ProviderFailureKind::TemporarilyUnavailable,
                _ => ProviderFailureKind::Rejected,
            }),
            retry_after_millis: Some(100),
        }
    }
}

fn token_info() -> TokenInfo {
    TokenInfo {
        token: Arc::from("qa-synthetic-access-value"),
        expires_in: 3600,
    }
}

impl ApnsClient for MockClient {
    fn send_to_device<'a>(
        &'a self,
        target: &'a str,
        platform: Platform,
        payload: Arc<ApnsPayload>,
        _collapse_id: Option<Arc<str>>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            let result = match payload.encoded_body() {
                Ok(wire) => {
                    let data = serde_json::to_value(payload.snapshot())
                        .ok()
                        .and_then(|snapshot| snapshot.get("data").cloned())
                        .unwrap_or(Value::Null);
                    self.record("APNS", platform.name(), target, &wire, data)
                }
                Err(error) => Err(Error::Internal(error.to_string())),
            };
            self.finish(result).await
        })
    }
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async { Ok(token_info()) })
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        ApnsClient::token_info(self)
    }
}
impl FcmClient for MockClient {
    fn send_to_device<'a>(
        &'a self,
        target: &'a str,
        payload: Arc<FcmPayload>,
        prepared_body: Option<Arc<[u8]>>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            let result = match prepared_body
                .map(Ok)
                .unwrap_or_else(|| payload.encoded_body(target))
            {
                Ok(wire) => self.record(
                    "FCM",
                    "android",
                    target,
                    &wire,
                    serde_json::to_value(payload.data()).unwrap_or(Value::Null),
                ),
                Err(error) => Err(Error::Internal(error.to_string())),
            };
            self.finish(result).await
        })
    }
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async { Ok(token_info()) })
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        FcmClient::token_info(self)
    }
}
impl WnsClient for MockClient {
    fn send_to_device<'a>(
        &'a self,
        target: &'a str,
        payload: Arc<WnsPayload>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            let result = match payload.encoded_body() {
                Ok(wire) => self.record(
                    "WNS",
                    "windows",
                    target,
                    &wire,
                    serde_json::to_value(payload.data()).unwrap_or(Value::Null),
                ),
                Err(error) => Err(Error::Internal(error.to_string())),
            };
            self.finish(result).await
        })
    }
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        Box::pin(async { Ok(token_info()) })
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>> {
        WnsClient::token_info(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn observation_count_and_file_bytes_stay_bounded() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("scenario.json"),
            br#"{"synthetic_only":true}"#,
        )
        .unwrap();
        let clients = ProductMockClients::from_directory(directory.path()).unwrap();
        let (_, fcm, _) = clients.clients();
        let data: hashbrown::HashMap<String, String> =
            hashbrown::HashMap::from_iter([("title".into(), "QA observation bound".into())]);
        let payload = Arc::new(FcmPayload::new(data, "NORMAL", None));
        for _ in 0..(MAX_RECORDS + 4) {
            assert!(
                fcm.send_to_device("qa-synthetic-target", payload.clone(), None)
                    .await
                    .success
            );
        }
        let records = std::fs::read_to_string(directory.path().join("records.jsonl")).unwrap();
        assert_eq!(records.lines().count(), MAX_RECORDS);
        assert!(records.len() as u64 <= MAX_RECORD_FILE_BYTES);
        assert_eq!(clients.0.state.lock().calls, (MAX_RECORDS + 4) as u64);
    }

    #[test]
    fn fixture_requires_explicit_synthetic_marker() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("scenario.json"),
            br#"{"synthetic_only":false}"#,
        )
        .unwrap();
        assert!(ProductMockClients::from_directory(directory.path()).is_err());
    }
}
