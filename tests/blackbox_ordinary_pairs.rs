//! Bounded normal-product comparison and explicit diagnostic profiles over HTTP/TCP MQTT5.
//! Delivery-load can opt into one V2 HTTP peer with a test-owned durable journal;
//! it is a benchmark peer, not an Android/Apple/Windows product client.
//! Default runs use no QA mode, fixture server or Provider substitution. An
//! explicit ordinary delivery-load flag may request only product QA profiling.
//! Database
//! reads every 100ms provide visibility upper bounds, not COMMIT timestamps.
use futures_util::{StreamExt, stream};
use pushgo_gateway::ordinary::metrics::Histogram;
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{Connection, Row, SqliteConnection};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::Notify, task::JoinHandle};

#[path = "support/product_mqtt.rs"]
mod product_mqtt;
use product_mqtt::{ProductMqttClient, ProductMqttReceiveStats};

const MESSAGES: usize = 136;
const HARD_LIMIT: Duration = Duration::from_secs(100);
const DRAIN_LIMIT: Duration = Duration::from_secs(30);
const MAX_LOAD_MESSAGES: usize = 12_000;
const MAX_LOAD_TARGETS: usize = 4;
const MAX_LOAD_HTTP_CONCURRENCY: usize = 64;
const MAX_LOAD_RATE_PER_SECOND: u32 = 500;
const MAX_LOAD_DURATION_SECONDS: u64 = 720;
const MAX_RUN_DIRECTORY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PROCESS_RSS_KIB: u64 = 1_048_576;
const MAX_PENDING_TARGETS: usize = 16_384;
const HTTP_PULL_PAGE_LIMIT: usize = 200;

fn driver_timing_enabled(setting: Option<&str>) -> Result<bool, String> {
    match setting {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err("C13_DRIVER_TIMING must be absent,0 or1".into()),
    }
}

fn gateway_qa_profile_enabled(
    mode: RunMode,
    backend: &str,
    setting: Option<&str>,
) -> Result<bool, String> {
    match setting {
        None | Some("0") => Ok(false),
        Some("1") if mode.is_delivery_load() && backend == "ordinary" => Ok(true),
        Some("1") => Err("C13_GATEWAY_QA_PROFILE=1 requires delivery-load ordinary mode".into()),
        Some(_) => Err("C13_GATEWAY_QA_PROFILE must be absent,0 or1".into()),
    }
}

fn gateway_qa_profile_directory(
    directory: &Path,
    enabled: bool,
) -> Result<Option<PathBuf>, String> {
    if !enabled {
        return Ok(None);
    }
    let path = directory.join("gateway-qa-profile");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(path)),
        Ok(_) => Err("refusing existing gateway-qa-profile output".into()),
        Err(error) => Err(format!("cannot inspect gateway-qa-profile output: {error}")),
    }
}

fn take_puback_to_receive_gap(
    last_ack: &mut Option<Instant>,
    receive_started: Option<Instant>,
) -> Option<Duration> {
    last_ack
        .take()
        .zip(receive_started)
        .map(|(ack, receive)| receive.duration_since(ack))
}

#[derive(Default)]
struct MqttDriverTiming {
    packet_ready_to_json_complete: Histogram,
    packet_ready_to_verify_return: Histogram,
    verify_return_to_puback_write_complete: Histogram,
    packet_ready_to_puback_write_complete: Histogram,
    puback_write: Histogram,
    last_puback_to_first_receive: Histogram,
    last_puback_to_first_receive_after_disconnect: Histogram,
    receive_success: Histogram,
    receive_timeout: Histogram,
    socket_drop_to_reconnect_complete: Histogram,
    receive_calls: AtomicU64,
    receive_timeouts: AtomicU64,
    publish_received: AtomicU64,
    ready_parses: AtomicU64,
    read_calls: AtomicU64,
    read_bytes: AtomicU64,
    buffered_before_total: AtomicU64,
    buffered_after_total: AtomicU64,
    buffered_before_max: AtomicU64,
    buffered_after_max: AtomicU64,
    buffered_peak: AtomicU64,
}
impl MqttDriverTiming {
    fn record_receive(&self, stats: ProductMqttReceiveStats, received: bool, publish: bool) {
        self.receive_calls.fetch_add(1, Ordering::Relaxed);
        self.receive_timeouts
            .fetch_add(u64::from(!received), Ordering::Relaxed);
        self.publish_received
            .fetch_add(u64::from(publish), Ordering::Relaxed);
        self.ready_parses
            .fetch_add(stats.ready_parses, Ordering::Relaxed);
        self.read_calls
            .fetch_add(stats.read_calls, Ordering::Relaxed);
        self.read_bytes
            .fetch_add(stats.read_bytes, Ordering::Relaxed);
        self.buffered_before_total
            .fetch_add(stats.buffered_before as u64, Ordering::Relaxed);
        self.buffered_after_total
            .fetch_add(stats.buffered_after as u64, Ordering::Relaxed);
        self.buffered_before_max
            .fetch_max(stats.buffered_before as u64, Ordering::Relaxed);
        self.buffered_after_max
            .fetch_max(stats.buffered_after as u64, Ordering::Relaxed);
        self.buffered_peak
            .fetch_max(stats.buffered_peak as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        json!({
            "packet_ready_to_json_complete": self.packet_ready_to_json_complete.snapshot(),
            "packet_ready_to_verify_return": self.packet_ready_to_verify_return.snapshot(),
            "verify_return_to_puback_write_complete": self.verify_return_to_puback_write_complete.snapshot(),
            "packet_ready_to_puback_write_complete": self.packet_ready_to_puback_write_complete.snapshot(),
            "puback_write": self.puback_write.snapshot(),
            "last_puback_to_first_receive": self.last_puback_to_first_receive.snapshot(),
            "last_puback_to_first_receive_after_disconnect": self.last_puback_to_first_receive_after_disconnect.snapshot(),
            "receive_success": self.receive_success.snapshot(),
            "receive_timeout": self.receive_timeout.snapshot(),
            "socket_drop_to_reconnect_complete": self.socket_drop_to_reconnect_complete.snapshot(),
            "receive_counts": {
                "calls":self.receive_calls.load(Ordering::Relaxed),
                "timeouts":self.receive_timeouts.load(Ordering::Relaxed),
                "publish_packets":self.publish_received.load(Ordering::Relaxed),
                "ready_packet_parses":self.ready_parses.load(Ordering::Relaxed),
                "read_calls_including_timeout":self.read_calls.load(Ordering::Relaxed),
                "read_bytes":self.read_bytes.load(Ordering::Relaxed),
                "buffered_before_total_bytes":self.buffered_before_total.load(Ordering::Relaxed),
                "buffered_after_total_bytes":self.buffered_after_total.load(Ordering::Relaxed),
                "buffered_before_max_bytes":self.buffered_before_max.load(Ordering::Relaxed),
                "buffered_after_max_bytes":self.buffered_after_max.load(Ordering::Relaxed),
                "buffered_peak_bytes":self.buffered_peak.load(Ordering::Relaxed)
            },
            "receive_scope":"caller wait/parse/scheduling; kernel readiness is unknown; success includes non-PUBLISH packets; timeout may retain partial bytes; read calls are wrapper attempts, not syscalls; buffer bytes are logical lengths, not allocation capacity; one last-PUBACK gap sample only at the first following receive call; held disconnect gap reported separately"
        })
    }
}

struct DriverTiming {
    enabled: bool,
    verify_expected_wait: Histogram,
    verify_expected_hold: Histogram,
    submit_expected_wait: Histogram,
    submit_expected_hold: Histogram,
    response_json_complete_to_accepted_record: Histogram,
    evidence_encode: Histogram,
    evidence_file_wait: Histogram,
    evidence_file_hold: Histogram,
    http_journal_save_transaction: Histogram,
    http_journal_save_commit: Histogram,
    http_journal_ack_marker_transaction: Histogram,
    http_journal_ack_marker_commit: Histogram,
    mqtt: [MqttDriverTiming; MAX_LOAD_TARGETS],
}
impl DriverTiming {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            verify_expected_wait: Histogram::default(),
            verify_expected_hold: Histogram::default(),
            submit_expected_wait: Histogram::default(),
            submit_expected_hold: Histogram::default(),
            response_json_complete_to_accepted_record: Histogram::default(),
            evidence_encode: Histogram::default(),
            evidence_file_wait: Histogram::default(),
            evidence_file_hold: Histogram::default(),
            http_journal_save_transaction: Histogram::default(),
            http_journal_save_commit: Histogram::default(),
            http_journal_ack_marker_transaction: Histogram::default(),
            http_journal_ack_marker_commit: Histogram::default(),
            mqtt: std::array::from_fn(|_| MqttDriverTiming::default()),
        }
    }

    fn start(&self) -> Option<Instant> {
        if self.enabled {
            Some(Instant::now())
        } else {
            None
        }
    }

    fn record_between(&self, histogram: &Histogram, start: Option<Instant>, end: Option<Instant>) {
        if self.enabled
            && let (Some(start), Some(end)) = (start, end)
        {
            histogram.record(end.duration_since(start));
        }
    }

    fn finish(&self, histogram: &Histogram, start: Option<Instant>) {
        if self.enabled
            && let Some(start) = start
        {
            histogram.record(start.elapsed());
        }
    }

    fn snapshot(&self) -> Option<Value> {
        self.enabled.then(|| json!({
            "scope": "caller wall time; phases can be nested and must not be added; log2 microsecond bucket quantiles are upper bounds; cumulative snapshots are not exact atomic cuts",
            "expected_guard_hold_scope": "identity binding, received/accepted facts and event-data preparation; released before evidence encoding/writes and submit Notify",
            "evidence_file_hold_scope": "synchronous write_all and flush while holding the original file mutex; encoding is outside this mutex and measured separately; no physical write count is inferred",
            "mqtt_packet_ready_scope": "after the test MQTT decoder returns a PUBLISH, not kernel socket arrival or server send time",
            "verify_expected_wait": self.verify_expected_wait.snapshot(),
            "verify_expected_hold": self.verify_expected_hold.snapshot(),
            "submit_expected_wait": self.submit_expected_wait.snapshot(),
            "submit_expected_hold": self.submit_expected_hold.snapshot(),
            "response_json_complete_to_accepted_record": self.response_json_complete_to_accepted_record.snapshot(),
            "evidence_encode": self.evidence_encode.snapshot(),
            "evidence_file_wait": self.evidence_file_wait.snapshot(),
            "evidence_file_hold": self.evidence_file_hold.snapshot(),
            "http_journal_save_transaction": self.http_journal_save_transaction.snapshot(),
            "http_journal_save_commit": self.http_journal_save_commit.snapshot(),
            "http_journal_ack_marker_transaction": self.http_journal_ack_marker_transaction.snapshot(),
            "http_journal_ack_marker_commit": self.http_journal_ack_marker_commit.snapshot(),
            "mqtt_by_device_index": self.mqtt.iter().enumerate().map(|(slot, timing)| json!({"slot":slot,"timings":timing.snapshot()})).collect::<Vec<_>>()
        }))
    }
}

#[derive(Clone, Copy)]
struct MqttPacketTiming {
    slot: usize,
    ready: Instant,
    json_complete: Instant,
}

#[derive(Clone, Copy)]
struct MqttPendingTiming {
    slot: usize,
    ready: Instant,
    verify_returned: Instant,
}

fn http_pull_peer_enabled(
    mode: RunMode,
    backend: &str,
    setting: Option<&str>,
) -> Result<bool, String> {
    match setting {
        None | Some("0") => Ok(false),
        Some("1") if mode.is_delivery_load() && backend == "ordinary" => {
            if mode.target_devices() != 4 {
                return Err("HTTP mixed load requires exactly1 HTTP and3 MQTT targets".into());
            }
            if mode.load_plan().unwrap().disconnect_device == 0 {
                return Err("HTTP peer0 cannot be the MQTT disconnect target".into());
            }
            Ok(true)
        }
        Some("1") => Err("C13_HTTP_PULL_PEER=1 requires delivery-load ordinary mode".into()),
        Some(_) => Err("C13_HTTP_PULL_PEER must be absent,0 or1".into()),
    }
}

fn pull_payload_data(payload: &Value) -> Result<Value, String> {
    let fields = payload
        .as_object()
        .ok_or_else(|| "V2 Pull payload must be a string map".to_string())?;
    if fields.values().any(|field| !field.is_string()) {
        return Err("V2 Pull payload contains a non-string field".into());
    }
    for required in ["title", "body", "message_id", "metadata"] {
        if !fields.contains_key(required) {
            return Err(format!("V2 Pull payload missing {required}"));
        }
    }
    let mut normalized = fields.clone();
    let metadata = serde_json::from_str(fields["metadata"].as_str().unwrap())
        .map_err(|_| "V2 Pull metadata is not valid JSON".to_string())?;
    normalized.insert("metadata".into(), metadata);
    Ok(Value::Object(normalized))
}

fn pull_scan_progress(page: &Value) -> Result<(bool, bool, Option<String>), String> {
    let complete = page["scan_complete"]
        .as_bool()
        .ok_or("HTTP peer scan_complete absent or invalid")?;
    let more = page["has_more"]
        .as_bool()
        .ok_or("HTTP peer has_more absent or invalid")?;
    let next = match page.get("next_page_token") {
        Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 2048 => {
            Some(value.clone())
        }
        _ => return Err("HTTP peer next_page_token absent or invalid".into()),
    };
    if more == complete || (complete && next.is_some()) || (!complete && next.is_none()) {
        return Err("HTTP peer invalid finite-scan continuation".into());
    }
    Ok((complete, more, next))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoadStageName {
    Low,
    Sustained20,
    Sustained40,
    Sustained80,
    Burst200,
    Recovery80,
}
impl LoadStageName {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "sustained_20" => Some(Self::Sustained20),
            "sustained_40" => Some(Self::Sustained40),
            "sustained_80" => Some(Self::Sustained80),
            "burst_200" => Some(Self::Burst200),
            "recovery_80" => Some(Self::Recovery80),
            _ => None,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Sustained20 => "sustained_20",
            Self::Sustained40 => "sustained_40",
            Self::Sustained80 => "sustained_80",
            Self::Burst200 => "burst_200",
            Self::Recovery80 => "recovery_80",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LoadStage {
    name: LoadStageName,
    messages: usize,
    rate_per_second: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LoadPlan {
    stages: [LoadStage; 6],
    target_devices: usize,
    http_concurrency: usize,
    disconnect_stage: usize,
    disconnect_device: usize,
    disconnect_seconds: u64,
    warm_idle_seconds: u64,
    post_drain_idle_seconds: u64,
    drain_limit_seconds: u64,
    hard_limit_seconds: u64,
}
impl LoadPlan {
    fn representative() -> Self {
        Self {
            stages: [
                LoadStage {
                    name: LoadStageName::Low,
                    messages: 30,
                    rate_per_second: 1,
                },
                LoadStage {
                    name: LoadStageName::Sustained20,
                    messages: 1_200,
                    rate_per_second: 20,
                },
                LoadStage {
                    name: LoadStageName::Sustained40,
                    messages: 2_400,
                    rate_per_second: 40,
                },
                LoadStage {
                    name: LoadStageName::Sustained80,
                    messages: 4_800,
                    rate_per_second: 80,
                },
                LoadStage {
                    name: LoadStageName::Burst200,
                    messages: 1_000,
                    rate_per_second: 200,
                },
                LoadStage {
                    name: LoadStageName::Recovery80,
                    messages: 800,
                    rate_per_second: 80,
                },
            ],
            target_devices: 4,
            http_concurrency: 64,
            disconnect_stage: 5,
            disconnect_device: 3,
            disconnect_seconds: 10,
            warm_idle_seconds: 30,
            post_drain_idle_seconds: 60,
            drain_limit_seconds: 60,
            hard_limit_seconds: 720,
        }
    }

    fn from_environment() -> Self {
        let raw = match std::env::var("C13_LOAD_PLAN_JSON") {
            Ok(raw) => raw,
            Err(std::env::VarError::NotPresent) => return Self::representative(),
            Err(error) => panic!("cannot read C13_LOAD_PLAN_JSON: {error}"),
        };
        let value: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("invalid C13_LOAD_PLAN_JSON: {error}"));
        Self::from_value(&value).unwrap_or_else(|error| panic!("invalid load plan: {error}"))
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let integer = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{name} must be a nonnegative integer"))
        };
        if integer("version")? != 1 {
            return Err("load plan version must be 1".into());
        }
        let stage_values = value
            .get("stages")
            .and_then(Value::as_array)
            .ok_or_else(|| "stages must be an array".to_string())?;
        if stage_values.len() != 6 {
            return Err("stages must contain the six bounded phases".into());
        }
        let mut stages = Self::representative().stages;
        for (index, stage) in stage_values.iter().enumerate() {
            let name = stage
                .get("name")
                .and_then(Value::as_str)
                .and_then(LoadStageName::parse)
                .ok_or_else(|| format!("stages[{index}].name is unsupported"))?;
            if name != stages[index].name {
                return Err(format!(
                    "stages[{index}] is out of the required phase order"
                ));
            }
            let messages: usize = stage
                .get("messages")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("stages[{index}].messages must be an integer"))?
                .try_into()
                .map_err(|_| format!("stages[{index}].messages is too large"))?;
            let rate: u32 = stage
                .get("rate_per_second")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("stages[{index}].rate_per_second must be an integer"))?
                .try_into()
                .map_err(|_| format!("stages[{index}].rate_per_second is too large"))?;
            stages[index].messages = messages;
            stages[index].rate_per_second = rate;
        }
        let disconnect_stage_name = value
            .get("disconnect_stage")
            .and_then(Value::as_str)
            .and_then(LoadStageName::parse)
            .ok_or_else(|| "disconnect_stage must name a configured phase".to_string())?;
        let disconnect_stage = stages
            .iter()
            .position(|stage| stage.name == disconnect_stage_name)
            .ok_or_else(|| "disconnect_stage is absent from stages".to_string())?;
        let plan = Self {
            stages,
            target_devices: integer("target_devices")?
                .try_into()
                .map_err(|_| "target_devices is too large".to_string())?,
            http_concurrency: integer("http_concurrency")?
                .try_into()
                .map_err(|_| "http_concurrency is too large".to_string())?,
            disconnect_stage,
            disconnect_device: integer("disconnect_device")?
                .try_into()
                .map_err(|_| "disconnect_device is too large".to_string())?,
            disconnect_seconds: integer("disconnect_seconds")?,
            warm_idle_seconds: integer("warm_idle_seconds")?,
            post_drain_idle_seconds: integer("post_drain_idle_seconds")?,
            drain_limit_seconds: integer("drain_limit_seconds")?,
            hard_limit_seconds: integer("hard_limit_seconds")?,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(self) -> Result<(), String> {
        if !(2..=MAX_LOAD_TARGETS).contains(&self.target_devices) {
            return Err(format!(
                "target_devices must be between 2 and {MAX_LOAD_TARGETS}"
            ));
        }
        if !(1..=MAX_LOAD_HTTP_CONCURRENCY).contains(&self.http_concurrency) {
            return Err(format!(
                "http_concurrency must be between 1 and {MAX_LOAD_HTTP_CONCURRENCY}"
            ));
        }
        if self.disconnect_device >= self.target_devices {
            return Err("disconnect_device must identify a configured target".into());
        }
        if self.disconnect_seconds == 0
            || self.warm_idle_seconds == 0
            || self.post_drain_idle_seconds == 0
            || self.drain_limit_seconds == 0
            || self.hard_limit_seconds == 0
            || self.hard_limit_seconds > MAX_LOAD_DURATION_SECONDS
        {
            return Err(format!(
                "durations must be nonzero and hard_limit_seconds <= {MAX_LOAD_DURATION_SECONDS}"
            ));
        }
        for stage in self.stages {
            if stage.messages == 0 || stage.rate_per_second == 0 {
                return Err("every phase must have positive messages and rate".into());
            }
            if stage.messages > MAX_LOAD_MESSAGES {
                return Err(format!("a phase exceeds {MAX_LOAD_MESSAGES} messages"));
            }
            if stage.rate_per_second > MAX_LOAD_RATE_PER_SECOND {
                return Err(format!(
                    "phase rate exceeds {MAX_LOAD_RATE_PER_SECOND} messages/second"
                ));
            }
        }
        let messages = self.messages();
        if messages > MAX_LOAD_MESSAGES {
            return Err(format!("planned messages exceed {MAX_LOAD_MESSAGES}"));
        }
        let phase_seconds: u64 = self
            .stages
            .iter()
            .map(|stage| {
                ((stage.messages as u64) + (stage.rate_per_second as u64) - 1)
                    / stage.rate_per_second as u64
            })
            .sum();
        let required_seconds = self.warm_idle_seconds
            + phase_seconds
            + self.drain_limit_seconds
            + self.post_drain_idle_seconds;
        if required_seconds > self.hard_limit_seconds {
            return Err(
                "the fixed schedule plus drain/idle windows exceeds hard_limit_seconds".into(),
            );
        }
        let disconnected_stage = self.stages[self.disconnect_stage];
        let disconnected_stage_seconds =
            (disconnected_stage.messages as u64 + disconnected_stage.rate_per_second as u64 - 1)
                / disconnected_stage.rate_per_second as u64;
        if self.disconnect_seconds > disconnected_stage_seconds {
            return Err("disconnect interval must fit inside its configured stage".into());
        }
        Ok(())
    }

    fn messages(self) -> usize {
        self.stages.iter().map(|stage| stage.messages).sum()
    }
    fn stage_duration(stage: LoadStage) -> Duration {
        let nanos =
            (stage.messages as u128 * 1_000_000_000u128).div_ceil(stage.rate_per_second as u128);
        Duration::from_nanos(nanos as u64)
    }
    fn stage_offset(self, stage_index: usize) -> Duration {
        self.stages[..stage_index]
            .iter()
            .copied()
            .map(Self::stage_duration)
            .sum()
    }
    fn disconnect_offset(self) -> Duration {
        self.stage_offset(self.disconnect_stage)
    }
    fn planned_offset(self, index: usize) -> Duration {
        let mut remaining = index;
        let mut offset = Duration::ZERO;
        for stage in self.stages {
            if remaining < stage.messages {
                let nanos = (remaining as u128 * 1_000_000_000u128) / stage.rate_per_second as u128;
                return offset + Duration::from_nanos(nanos as u64);
            }
            remaining -= stage.messages;
            offset += Self::stage_duration(stage);
        }
        panic!("load message index out of bounds");
    }
    fn stage_name(self, index: usize) -> &'static str {
        let mut remaining = index;
        for stage in self.stages {
            if remaining < stage.messages {
                return stage.name.name();
            }
            remaining -= stage.messages;
        }
        panic!("load message index out of bounds");
    }
    fn phase_offsets(self) -> Vec<(Duration, &'static str)> {
        let mut offset = Duration::ZERO;
        self.stages
            .iter()
            .copied()
            .map(|stage| {
                let current = (offset, stage.name.name());
                offset += Self::stage_duration(stage);
                current
            })
            .collect()
    }
    fn to_value(self) -> Value {
        json!({
            "version": 1,
            "target_devices": self.target_devices,
            "http_concurrency": self.http_concurrency,
            "disconnect_stage": self.stages[self.disconnect_stage].name.name(),
            "disconnect_device": self.disconnect_device,
            "disconnect_seconds": self.disconnect_seconds,
            "warm_idle_seconds": self.warm_idle_seconds,
            "post_drain_idle_seconds": self.post_drain_idle_seconds,
            "drain_limit_seconds": self.drain_limit_seconds,
            "hard_limit_seconds": self.hard_limit_seconds,
            "safety_caps": {
                "max_messages": MAX_LOAD_MESSAGES,
                "max_targets": MAX_LOAD_TARGETS,
                "max_http_concurrency": MAX_LOAD_HTTP_CONCURRENCY,
                "max_rate_per_second": MAX_LOAD_RATE_PER_SECOND,
                "max_runtime_seconds": MAX_LOAD_DURATION_SECONDS,
                "max_run_directory_bytes": MAX_RUN_DIRECTORY_BYTES,
                "max_process_rss_kib": MAX_PROCESS_RSS_KIB,
                "max_pending_targets": MAX_PENDING_TARGETS
            },
            "stages": self.stages.iter().map(|stage| json!({
                "name": stage.name.name(),
                "messages": stage.messages,
                "rate_per_second": stage.rate_per_second
            })).collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Formal,
    Preflight,
    DeliveryLoad(LoadPlan),
}
impl RunMode {
    fn from_environment() -> Self {
        match std::env::var("C13_RUN_MODE") {
            Ok(value) if value == "formal" => Self::Formal,
            Ok(value) if value == "preflight" => Self::Preflight,
            Ok(value) if value == "delivery-load" => {
                Self::DeliveryLoad(LoadPlan::from_environment())
            }
            Ok(other) => {
                panic!("unsupported C13_RUN_MODE {other:?}; use formal, preflight or delivery-load")
            }
            Err(std::env::VarError::NotPresent) => Self::Formal,
            Err(error) => panic!("cannot read C13_RUN_MODE: {error}"),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Formal => "formal",
            Self::Preflight => "preflight",
            Self::DeliveryLoad(_) => "delivery-load",
        }
    }
    fn is_delivery_load(self) -> bool {
        matches!(self, Self::DeliveryLoad(_))
    }
    fn load_plan(self) -> Option<LoadPlan> {
        match self {
            Self::DeliveryLoad(plan) => Some(plan),
            Self::Formal | Self::Preflight => None,
        }
    }
    fn messages(self) -> usize {
        match self {
            Self::Formal => MESSAGES,
            Self::Preflight => 3,
            Self::DeliveryLoad(plan) => plan.messages(),
        }
    }
    fn targets_per_message(self) -> usize {
        match self {
            Self::Formal | Self::Preflight => 2,
            Self::DeliveryLoad(plan) => plan.target_devices,
        }
    }
    fn targets(self) -> usize {
        self.messages() * self.targets_per_message()
    }
    fn target_devices(self) -> usize {
        self.targets_per_message()
    }
    fn http_concurrency(self) -> usize {
        self.load_plan().map_or(8, |plan| plan.http_concurrency)
    }
    fn hard_limit(self) -> Duration {
        match self {
            Self::Formal => HARD_LIMIT,
            Self::Preflight => Duration::from_secs(45),
            Self::DeliveryLoad(plan) => Duration::from_secs(plan.hard_limit_seconds),
        }
    }
    fn drain_limit(self) -> Duration {
        match self {
            Self::Formal | Self::DeliveryLoad(_) => self.load_plan().map_or(DRAIN_LIMIT, |plan| {
                Duration::from_secs(plan.drain_limit_seconds)
            }),
            Self::Preflight => Duration::from_secs(15),
        }
    }
    fn warm_idle(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(10),
            Self::Preflight => Duration::from_secs(1),
            Self::DeliveryLoad(plan) => Duration::from_secs(plan.warm_idle_seconds),
        }
    }
    fn post_drain_idle(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(35),
            Self::Preflight => Duration::from_secs(2),
            Self::DeliveryLoad(plan) => Duration::from_secs(plan.post_drain_idle_seconds),
        }
    }
    fn hold_delay(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(6),
            Self::Preflight => Duration::ZERO,
            Self::DeliveryLoad(plan) => plan.disconnect_offset(),
        }
    }
    fn hold_duration(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(5),
            Self::Preflight => Duration::from_millis(500),
            Self::DeliveryLoad(plan) => Duration::from_secs(plan.disconnect_seconds),
        }
    }
    fn planned_offset(self, index: usize) -> Duration {
        match self {
            Self::Formal if index < 8 => Duration::from_millis(index as u64 * 500),
            Self::Formal if index < 24 => Duration::from_millis(4000 + (index as u64 - 8) * 125),
            Self::Formal => Duration::from_millis(6000 + (index as u64 - 24) * 10),
            Self::Preflight => Duration::from_millis(index as u64 * 250),
            Self::DeliveryLoad(plan) => plan.planned_offset(index),
        }
    }
    fn stage(self, index: usize) -> &'static str {
        match self {
            Self::Formal if index < 8 => "low",
            Self::Formal if index < 24 => "ramp",
            Self::Formal => "burst",
            Self::Preflight => "preflight",
            Self::DeliveryLoad(plan) => plan.stage_name(index),
        }
    }
    fn phase_offsets(self) -> Vec<(Duration, &'static str)> {
        match self {
            Self::DeliveryLoad(plan) => plan.phase_offsets(),
            _ => vec![
                (Duration::from_secs(4), "ramp_started"),
                (self.hold_delay(), "burst_started"),
                (self.hold_delay() + self.hold_duration(), "held_ack_release"),
            ],
        }
    }
}

fn validate_fresh_run_directory(directory: &Path) -> Result<(), String> {
    if !directory.is_absolute() {
        return Err("run directory must be absolute".into());
    }
    if directory.exists() {
        return Err("run directory already exists; refusing to overwrite evidence".into());
    }
    if directory.parent().is_none() {
        return Err("run directory must have a parent".into());
    }
    if directory
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("run directory must not contain parent traversal".into());
    }
    Ok(())
}

fn validate_executable_binary(binary: &Path) -> Result<(), String> {
    if !binary.is_absolute() {
        return Err("Gateway binary path must be absolute".into());
    }
    let metadata = std::fs::metadata(binary).map_err(|error| format!("Gateway binary: {error}"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("Gateway binary must be a regular executable file".into());
    }
    Ok(())
}

fn validate_terminal_counts(
    mode: RunMode,
    persisted: usize,
    received: usize,
    pubacks: usize,
    terminal: usize,
    released: usize,
    residual: usize,
) -> Result<(), String> {
    if mode.messages() == 0 || mode.targets() == 0 {
        return Err("planned cohort has zero messages or targets".into());
    }
    for (name, actual, expected) in [
        ("persisted messages", persisted, mode.messages()),
        ("peer receives", received, mode.targets()),
        ("positive ACK evidence", pubacks, mode.targets()),
        ("positive terminal targets", terminal, mode.targets()),
        ("released bodies", released, mode.messages()),
    ] {
        if actual != expected {
            return Err(format!("{name}: observed {actual}, expected {expected}"));
        }
    }
    if residual != 0 {
        return Err(format!("residual target backlog: {residual}"));
    }
    Ok(())
}

#[cfg(test)]
mod harness_preflight_tests {
    use super::*;

    #[test]
    fn rejects_unsafe_or_existing_run_paths() {
        assert!(validate_fresh_run_directory(Path::new("relative/run")).is_err());
        assert!(validate_fresh_run_directory(Path::new("/tmp/../unsafe/run")).is_err());
        assert!(validate_fresh_run_directory(Path::new("/")).is_err());
    }

    #[test]
    fn rejects_incomplete_or_backlogged_terminal_evidence() {
        assert!(validate_terminal_counts(RunMode::Preflight, 3, 6, 6, 6, 3, 0).is_ok());
        assert!(validate_terminal_counts(RunMode::Preflight, 0, 6, 6, 6, 3, 0).is_err());
        assert!(validate_terminal_counts(RunMode::Preflight, 3, 5, 6, 6, 3, 0).is_err());
        assert!(validate_terminal_counts(RunMode::Preflight, 3, 6, 5, 5, 3, 0).is_err());
        assert!(validate_terminal_counts(RunMode::Preflight, 3, 6, 6, 6, 3, 1).is_err());
    }

    #[test]
    fn delivery_load_plan_is_bounded_and_uses_absolute_offer_times() {
        let plan = LoadPlan::representative();
        plan.validate().unwrap();
        let mode = RunMode::DeliveryLoad(plan);
        assert_eq!(mode.messages(), 10_230);
        assert_eq!(mode.targets(), 40_920);
        assert_eq!(mode.target_devices(), 4);
        assert_eq!(mode.http_concurrency(), 64);
        assert_eq!(mode.planned_offset(30), Duration::from_secs(30));
        assert_eq!(mode.planned_offset(1_230), Duration::from_secs(90));
        assert_eq!(mode.planned_offset(3_630), Duration::from_secs(150));
        assert_eq!(mode.planned_offset(8_430), Duration::from_secs(210));
        assert_eq!(mode.planned_offset(9_430), Duration::from_secs(215));
        assert_eq!(
            mode.planned_offset(10_229),
            Duration::from_micros(224_987_500)
        );
        assert_eq!(plan.disconnect_offset(), Duration::from_secs(215));
        assert_eq!(mode.phase_offsets().len(), 6);
        assert_eq!(plan.to_value()["safety_caps"]["max_messages"], 12_000);
    }

    #[test]
    fn delivery_load_plan_rejects_unsafe_limits_and_invalid_stage_order() {
        let plan = LoadPlan::representative();
        let mut value = plan.to_value();
        value["target_devices"] = json!(5);
        assert!(LoadPlan::from_value(&value).is_err());

        let mut value = plan.to_value();
        value["http_concurrency"] = json!(65);
        assert!(LoadPlan::from_value(&value).is_err());

        let mut value = plan.to_value();
        value["stages"][0]["messages"] = json!(12_001);
        assert!(LoadPlan::from_value(&value).is_err());

        let mut value = plan.to_value();
        value["stages"][1]["name"] = json!("recovery_80");
        assert!(LoadPlan::from_value(&value).is_err());

        let mut value = plan.to_value();
        value["hard_limit_seconds"] = json!(721);
        assert!(LoadPlan::from_value(&value).is_err());
    }

    #[test]
    fn terminal_aggregation_preserves_complete_and_partial_message_evidence() {
        let mut terminal = BTreeSet::new();
        for operation in 0..100 {
            for device in 0..if operation % 5 == 0 { 3 } else { 4 } {
                terminal.insert((format!("operation-{operation}"), format!("device-{device}")));
            }
        }
        assert!(!terminal.insert(("operation-1".into(), "device-0".into())));
        let counts = terminal_counts_by_operation(&terminal);
        for operation in 0..100 {
            let key = format!("operation-{operation}");
            let previous = terminal.iter().filter(|(id, _)| id == &key).count();
            assert_eq!(counts.get(key.as_str()).copied().unwrap_or(0), previous);
            assert_eq!(previous == 4, operation % 5 != 0);
        }
        assert_eq!(counts.get("not-received"), None);
    }

    #[test]
    fn terminal_oracle_requires_matching_identity_receive_ack_and_committed_absence() {
        let target = (
            "accepted-operation".to_string(),
            "actual-device".to_string(),
        );
        let other = (target.0.clone(), "other-device".to_string());
        let known = BTreeSet::from([target.0.clone()]);
        let received = BTreeSet::from([target.clone()]);
        let written = BTreeSet::from([target.clone()]);
        let row = BTreeSet::from([target.clone()]);
        let empty = BTreeSet::new();
        assert!(has_positive_terminal_evidence(
            &target, &known, &received, &written, &empty, &empty, None
        ));
        // A running Provider row may remain after client ACK until receipt
        // COMMIT. Its actual acked_at is positive, unlike its state string.
        assert!(has_positive_terminal_evidence(
            &target,
            &known,
            &received,
            &written,
            &row,
            &row,
            Some(&received)
        ));
        assert!(!has_positive_terminal_evidence(
            &target,
            &known,
            &received,
            &written,
            &row,
            &empty,
            Some(&received)
        ));
        assert!(!has_positive_terminal_evidence(
            &target,
            &known,
            &received,
            &written,
            &row,
            &row,
            Some(&empty)
        ));
        assert!(!has_positive_terminal_evidence(
            &target,
            &BTreeSet::new(),
            &received,
            &written,
            &empty,
            &empty,
            None
        ));
        assert!(!has_positive_terminal_evidence(
            &target, &known, &empty, &written, &empty, &empty, None
        ));
        assert!(!has_positive_terminal_evidence(
            &target, &known, &received, &empty, &empty, &empty, None
        ));
        assert!(!has_positive_terminal_evidence(
            &target, &known, &received, &written, &row, &empty, None
        ));
        assert!(!has_positive_terminal_evidence(
            &other, &known, &received, &written, &empty, &empty, None
        ));
    }

    #[test]
    fn mixed_http_peer_is_explicit_and_cannot_replace_the_disconnect_target() {
        let mode = RunMode::DeliveryLoad(LoadPlan::representative());
        assert_eq!(http_pull_peer_enabled(mode, "ordinary", None), Ok(false));
        assert_eq!(
            http_pull_peer_enabled(mode, "ordinary", Some("1")),
            Ok(true)
        );
        assert!(http_pull_peer_enabled(RunMode::Formal, "ordinary", Some("1")).is_err());
        assert!(http_pull_peer_enabled(RunMode::Preflight, "ordinary", Some("1")).is_err());
        assert!(http_pull_peer_enabled(mode, "main", Some("1")).is_err());
        assert!(http_pull_peer_enabled(mode, "ordinary", Some("unexpected")).is_err());
        let mut plan = LoadPlan::representative();
        plan.disconnect_device = 0;
        assert!(
            http_pull_peer_enabled(RunMode::DeliveryLoad(plan), "ordinary", Some("1")).is_err()
        );
    }

    #[test]
    fn http_payload_coercion_preserves_strings_and_parses_only_metadata() {
        let value = json!({"title":"operation","body":r#"中文🙂\""#,"message_id":"identity", "metadata":r#"{"negative":-42,"fraction":0.125}"#});
        let parsed = pull_payload_data(&value).unwrap();
        assert_eq!(parsed["body"], value["body"]);
        assert_eq!(parsed["message_id"], value["message_id"]);
        assert_eq!(parsed["metadata"], json!({"negative":-42,"fraction":0.125}));
        let mut invalid = value.clone();
        invalid["metadata"] = json!({"negative":-42});
        assert!(pull_payload_data(&invalid).is_err());
        invalid["metadata"] = json!("not JSON");
        assert!(pull_payload_data(&invalid).is_err());
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("message_id");
        assert!(pull_payload_data(&missing).is_err());
    }

    #[test]
    fn http_scan_progress_requires_the_complete_explicit_envelope() {
        let complete = json!({"scan_complete":true,"has_more":false,"next_page_token":null});
        let more =
            json!({"scan_complete":false,"has_more":true,"next_page_token":"opaque-test-value"});
        assert_eq!(pull_scan_progress(&complete).unwrap(), (true, false, None));
        assert_eq!(
            pull_scan_progress(&more).unwrap(),
            (false, true, Some("opaque-test-value".into()))
        );
        for field in ["scan_complete", "has_more", "next_page_token"] {
            let mut missing = complete.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(pull_scan_progress(&missing).is_err());
        }
        for invalid in [
            json!(1),
            json!(false),
            json!({}),
            json!([]),
            json!(""),
            json!("x".repeat(2049)),
        ] {
            let mut value = complete.clone();
            value["next_page_token"] = invalid;
            assert!(pull_scan_progress(&value).is_err());
        }
        let mut missing_continuation = more.clone();
        missing_continuation["next_page_token"] = Value::Null;
        assert!(pull_scan_progress(&missing_continuation).is_err());
        let mut unexpected_continuation = complete.clone();
        unexpected_continuation["next_page_token"] = json!("opaque-test-value");
        assert!(pull_scan_progress(&unexpected_continuation).is_err());
        let mut inconsistent = complete;
        inconsistent["has_more"] = json!(true);
        assert!(pull_scan_progress(&inconsistent).is_err());
    }

    #[test]
    fn directory_accounting_keeps_live_files_and_accepts_removed_entries() {
        let directory = tempfile::tempdir().unwrap();
        let transient = directory.path().join("gateway.sqlite-journal");
        std::fs::write(&transient, [0_u8; 17]).unwrap();
        std::fs::write(directory.path().join("gateway.sqlite"), [0_u8; 23]).unwrap();
        let removed_entry = std::fs::read_dir(directory.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.path() == transient)
            .unwrap();
        assert_eq!(metadata_bytes_or_gone(removed_entry.metadata()), Some(17));
        assert_eq!(run_directory_bytes(directory.path()), 40);
        std::fs::remove_file(transient).unwrap();
        assert_eq!(metadata_bytes_or_gone(removed_entry.metadata()), None);
        assert_eq!(run_directory_bytes(directory.path()), 23);
        assert!(
            std::panic::catch_unwind(|| {
                metadata_bytes_or_gone(Err(std::io::Error::from(
                    std::io::ErrorKind::PermissionDenied,
                )))
            })
            .is_err()
        );
    }

    #[test]
    fn driver_timing_is_strictly_opt_in_and_disabled_samples_stay_empty() {
        assert_eq!(driver_timing_enabled(None), Ok(false));
        assert_eq!(driver_timing_enabled(Some("0")), Ok(false));
        assert_eq!(driver_timing_enabled(Some("1")), Ok(true));
        assert!(driver_timing_enabled(Some("true")).is_err());
        let disabled = DriverTiming::new(false);
        assert!(disabled.start().is_none());
        let at = Instant::now();
        disabled.record_between(
            &disabled.verify_expected_wait,
            Some(at),
            Some(at + Duration::from_micros(17)),
        );
        assert_eq!(disabled.verify_expected_wait.snapshot()["samples"], 0);
        assert!(disabled.snapshot().is_none());
    }

    #[test]
    fn driver_timing_snapshot_keeps_fixed_peer_slots_and_phase_counts() {
        let timing = DriverTiming::new(true);
        let at = Instant::now();
        timing.record_between(
            &timing.verify_expected_wait,
            Some(at),
            Some(at + Duration::from_micros(17)),
        );
        timing.record_between(&timing.verify_expected_wait, None, Some(at));
        timing.record_between(
            &timing.mqtt[2].packet_ready_to_verify_return,
            Some(at),
            Some(at + Duration::from_micros(41)),
        );
        let snapshot = timing.snapshot().unwrap();
        assert_eq!(snapshot["verify_expected_wait"]["samples"], 1);
        assert_eq!(snapshot["verify_expected_wait"]["total_us"], 17);
        assert_eq!(snapshot["evidence_file_hold"]["samples"], 0);
        let peers = snapshot["mqtt_by_device_index"].as_array().unwrap();
        assert_eq!(peers.len(), MAX_LOAD_TARGETS);
        assert_eq!(peers[2]["slot"], 2);
        assert_eq!(
            peers[2]["timings"]["packet_ready_to_verify_return"]["samples"],
            1
        );
        assert_eq!(
            peers[1]["timings"]["packet_ready_to_verify_return"]["samples"],
            0
        );
        assert!(
            peers[2]["timings"]["packet_ready_to_verify_return"]["p95_upper_us"]
                .as_u64()
                .unwrap()
                >= 41
        );
    }

    fn unbound_expected() -> Arc<Expected> {
        Arc::new(Expected {
            body_hash: "fixed-body-hash".into(),
            body_bytes: 17,
            metadata: json!({"nested":{"values":[-42,0.125,"中文🙂"]}}),
            message_id: None,
            delivery_id: None,
        })
    }

    #[test]
    fn expected_cow_binding_preserves_older_observer_snapshots_and_same_value_identity() {
        let mut current = unbound_expected();
        let before_http = current.clone();
        bind_expected_identity(&mut current, "message", None);
        assert!(before_http.message_id.is_none());
        assert!(before_http.delivery_id.is_none());
        assert_eq!(current.message_id.as_deref(), Some("message"));
        assert!(current.delivery_id.is_none());
        assert!(!Arc::ptr_eq(&before_http, &current));

        let before_peer = current.clone();
        bind_expected_identity(&mut current, "message", Some("delivery"));
        assert_eq!(before_peer.message_id.as_deref(), Some("message"));
        assert!(before_peer.delivery_id.is_none());
        assert_eq!(current.delivery_id.as_deref(), Some("delivery"));
        assert!(!Arc::ptr_eq(&before_peer, &current));
        assert_eq!(current.body_hash, before_http.body_hash);
        assert_eq!(current.body_bytes, before_http.body_bytes);
        assert_eq!(current.metadata, before_http.metadata);

        let bound_snapshot = current.clone();
        bind_expected_identity(&mut current, "message", Some("delivery"));
        bind_expected_identity(&mut current, "message", None);
        assert!(Arc::ptr_eq(&bound_snapshot, &current));
    }

    #[test]
    fn expected_binding_accepts_both_arrival_orders_and_rejects_changed_ids_without_overwrite() {
        for peer_first in [false, true] {
            let mut current = unbound_expected();
            if peer_first {
                bind_expected_identity(&mut current, "message", Some("delivery"));
                bind_expected_identity(&mut current, "message", None);
            } else {
                bind_expected_identity(&mut current, "message", None);
                bind_expected_identity(&mut current, "message", Some("delivery"));
            }
            let saved = current.clone();
            for (message, delivery) in [
                ("other-message", None),
                ("other-message", Some("delivery")),
                ("message", Some("other-delivery")),
            ] {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        bind_expected_identity(&mut current, message, delivery);
                    }))
                    .is_err()
                );
                assert!(Arc::ptr_eq(&saved, &current));
                assert_eq!(current.message_id.as_deref(), Some("message"));
                assert_eq!(current.delivery_id.as_deref(), Some("delivery"));
            }
        }
    }

    #[test]
    fn evidence_keeps_unicode_and_newlines_intact_for_concurrent_writers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let evidence = Arc::new(Evidence {
            start: Instant::now(),
            file: Mutex::new(private_file(&path)),
            timing: DriverTiming::new(false),
        });
        let writers: Vec<_> = (0..4)
            .map(|writer| {
                let evidence = evidence.clone();
                std::thread::spawn(move || {
                    for sequence in 0..16 {
                        evidence.record("encoding-test", json!({"writer":writer,"sequence":sequence,"text":"中文🙂\nquoted \"value\"\\suffix"}));
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.ends_with('\n'));
        let mut identities = BTreeSet::new();
        for line in text.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["kind"], "encoding-test");
            assert!(row["elapsed_us"].is_u64());
            assert_eq!(row["data"]["text"], "中文🙂\nquoted \"value\"\\suffix");
            assert!(identities.insert((
                row["data"]["writer"].as_u64().unwrap(),
                row["data"]["sequence"].as_u64().unwrap()
            )));
        }
        assert_eq!(identities.len(), 64);
    }

    #[test]
    fn evidence_write_failure_remains_fatal_and_does_not_report_success() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("read-only-evidence.jsonl");
        std::fs::write(&path, b"original\n").unwrap();
        let evidence = Evidence {
            start: Instant::now(),
            file: Mutex::new(File::open(&path).unwrap()),
            timing: DriverTiming::new(false),
        };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                evidence.record("must-fail", json!({"success":true}));
            }))
            .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"original\n");
    }

    #[test]
    fn gateway_qa_profile_is_opt_in_mode_limited_and_uses_only_a_fresh_fixed_child() {
        let mode = RunMode::DeliveryLoad(LoadPlan::representative());
        assert_eq!(
            gateway_qa_profile_enabled(mode, "ordinary", None),
            Ok(false)
        );
        assert_eq!(
            gateway_qa_profile_enabled(mode, "ordinary", Some("0")),
            Ok(false)
        );
        assert_eq!(
            gateway_qa_profile_enabled(mode, "ordinary", Some("1")),
            Ok(true)
        );
        assert!(gateway_qa_profile_enabled(mode, "main", Some("1")).is_err());
        assert!(gateway_qa_profile_enabled(RunMode::Formal, "ordinary", Some("1")).is_err());
        assert!(gateway_qa_profile_enabled(RunMode::Preflight, "ordinary", Some("1")).is_err());
        assert!(gateway_qa_profile_enabled(mode, "ordinary", Some("true")).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            gateway_qa_profile_directory(directory.path(), false).unwrap(),
            None
        );
        let profile = gateway_qa_profile_directory(directory.path(), true)
            .unwrap()
            .unwrap();
        assert_eq!(profile, directory.path().join("gateway-qa-profile"));
        assert_eq!(profile.parent(), Some(directory.path()));
        assert!(!profile.exists());
        std::fs::create_dir(&profile).unwrap();
        assert!(gateway_qa_profile_directory(directory.path(), true).is_err());
        assert_eq!(
            gateway_qa_profile_directory(directory.path(), false).unwrap(),
            None
        );
    }

    #[test]
    fn last_puback_gap_is_consumed_by_only_the_first_following_receive() {
        let at = Instant::now();
        let mut last = Some(at);
        assert_eq!(
            take_puback_to_receive_gap(&mut last, Some(at + Duration::from_millis(3))),
            Some(Duration::from_millis(3))
        );
        assert!(last.is_none());
        assert_eq!(
            take_puback_to_receive_gap(&mut last, Some(at + Duration::from_secs(330))),
            None
        );
        let mut disabled = Some(at);
        assert_eq!(take_puback_to_receive_gap(&mut disabled, None), None);
        assert!(disabled.is_none());
    }

    #[test]
    fn mqtt_receive_counters_distinguish_packets_timeouts_reads_and_buffered_bytes() {
        let timing = MqttDriverTiming::default();
        timing.record_receive(
            ProductMqttReceiveStats {
                buffered_before: 17,
                buffered_after: 0,
                buffered_peak: 17,
                read_calls: 0,
                read_bytes: 0,
                ready_parses: 1,
            },
            true,
            false,
        );
        timing.record_receive(
            ProductMqttReceiveStats {
                buffered_before: 0,
                buffered_after: 16,
                buffered_peak: 16,
                read_calls: 1,
                read_bytes: 16,
                ready_parses: 0,
            },
            false,
            false,
        );
        timing.record_receive(
            ProductMqttReceiveStats {
                buffered_before: 16,
                buffered_after: 8,
                buffered_peak: 64,
                read_calls: 1,
                read_bytes: 48,
                ready_parses: 1,
            },
            true,
            true,
        );
        let counts = timing.snapshot()["receive_counts"].clone();
        assert_eq!(counts["calls"], 3);
        assert_eq!(counts["timeouts"], 1);
        assert_eq!(counts["publish_packets"], 1);
        assert_eq!(counts["ready_packet_parses"], 2);
        assert_eq!(counts["read_calls_including_timeout"], 2);
        assert_eq!(counts["read_bytes"], 64);
        assert_eq!(counts["buffered_before_total_bytes"], 33);
        assert_eq!(counts["buffered_after_total_bytes"], 24);
        assert_eq!(counts["buffered_peak_bytes"], 64);
    }
}

struct Evidence {
    start: Instant,
    file: Mutex<File>,
    timing: DriverTiming,
}
impl Evidence {
    fn us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
    fn record(&self, kind: &str, data: Value) {
        let row = json!({"elapsed_us":self.us(),"kind":kind,"data":data});
        let encoding = self.timing.start();
        let mut encoded = serde_json::to_vec(&row).unwrap();
        encoded.push(b'\n');
        self.timing.finish(&self.timing.evidence_encode, encoding);
        let waiting = self.timing.start();
        let mut file = self.file.lock().unwrap();
        let holding = self.timing.start();
        self.timing
            .record_between(&self.timing.evidence_file_wait, waiting, holding);
        file.write_all(&encoded).unwrap();
        file.flush().unwrap();
        self.timing.finish(&self.timing.evidence_file_hold, holding);
    }

    fn instant_us(&self, instant: Instant) -> u64 {
        instant.duration_since(self.start).as_micros() as u64
    }
}
#[derive(Clone)]
struct Expected {
    body_hash: String,
    body_bytes: usize,
    metadata: Value,
    message_id: Option<String>,
    delivery_id: Option<String>,
}

fn bind_expected_identity(item: &mut Arc<Expected>, message: &str, delivery: Option<&str>) {
    if let Some(id) = &item.message_id {
        assert_eq!(id, message);
    }
    if let (Some(id), Some(delivery)) = (&item.delivery_id, delivery) {
        assert_eq!(id, delivery);
    }
    // Only first binding changes the value. An observer may retain an earlier
    // Arc snapshot across SQL awaits; COW preserves that snapshot's identities.
    if item.message_id.is_none() || (delivery.is_some() && item.delivery_id.is_none()) {
        let item = Arc::make_mut(item);
        if item.message_id.is_none() {
            item.message_id = Some(message.into());
        }
        if let Some(delivery) = delivery
            && item.delivery_id.is_none()
        {
            item.delivery_id = Some(delivery.into());
        }
    }
}

struct Shared {
    evidence: Arc<Evidence>,
    mode: RunMode,
    http_pull_peer: bool,
    http_wake: Notify,
    journaled: Mutex<BTreeSet<(String, String)>>,
    stop: AtomicBool,
    hold_from_us: AtomicU64,
    hold_until_us: AtomicU64,
    failure: Mutex<Option<String>>,
    expected: Mutex<BTreeMap<String, Arc<Expected>>>,
    received: Mutex<BTreeSet<(String, String)>>,
    ack_sent: Mutex<BTreeSet<(String, String)>>,
    committed: Mutex<BTreeSet<(String, String)>>,
    accepted: Mutex<BTreeSet<String>>,
    body_released: Mutex<BTreeSet<String>>,
    persisted: Mutex<BTreeSet<String>>,
    residual_targets: AtomicU64,
}
impl Shared {
    fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.http_wake.notify_one();
    }
    fn check(&self) {
        let failure = self.failure.lock().unwrap().clone();
        assert!(failure.is_none(), "background failure: {failure:?}");
    }
    fn fail(&self, message: String) {
        self.evidence.record("error", json!({"message":message}));
        *self.failure.lock().unwrap() = Some(message);
    }
    fn verify(
        &self,
        peer: &str,
        device: &str,
        data: &Value,
        delivery: &str,
        packet_timing: Option<MqttPacketTiming>,
    ) -> String {
        let op = data["title"].as_str().expect("message title").to_owned();
        let waiting = self.evidence.timing.start();
        let mut expected = self.expected.lock().unwrap();
        let holding = self.evidence.timing.start();
        self.evidence.timing.record_between(
            &self.evidence.timing.verify_expected_wait,
            waiting,
            holding,
        );
        let item = expected.get_mut(&op).expect("fixed offered cohort");
        let body = data["body"].as_str().expect("whole body");
        assert_eq!(body.len(), item.body_bytes);
        assert_eq!(
            blake3::hash(body.as_bytes()).to_hex().to_string(),
            item.body_hash
        );
        assert_eq!(&data["metadata"], &item.metadata);
        let message = data["message_id"].as_str().expect("stable message id");
        bind_expected_identity(item, message, Some(delivery));
        let duplicate = !self
            .received
            .lock()
            .unwrap()
            .insert((op.clone(), device.into()));
        let duplicate_event = duplicate
            .then(|| json!({"peer":peer,"device_key":device,"op_id":op,"delivery_id":delivery}));
        let mut event = json!({"peer":peer,"device_key":device,"op_id":op,"delivery_id":delivery,"message_id":message,"body_bytes":body.len(),"body_hash":item.body_hash,"metadata":item.metadata});
        if let Some(record_ready) = self.evidence.timing.start() {
            let mut timing = json!({
                "expected_wait_started_elapsed_us": waiting.map(|at| self.evidence.instant_us(at)),
                "expected_lock_acquired_elapsed_us": holding.map(|at| self.evidence.instant_us(at)),
                "validation_record_ready_elapsed_us": self.evidence.instant_us(record_ready)
            });
            if let Some(packet) = packet_timing {
                timing["mqtt_device_index"] = json!(packet.slot);
                timing["mqtt_packet_ready_elapsed_us"] =
                    json!(self.evidence.instant_us(packet.ready));
                timing["mqtt_json_complete_elapsed_us"] =
                    json!(self.evidence.instant_us(packet.json_complete));
            }
            event["driver_timing"] = timing;
        }
        self.evidence
            .timing
            .finish(&self.evidence.timing.verify_expected_hold, holding);
        drop(expected);
        // Identity/facts and all event data are ready before releasing the
        // expected lock. Preserve duplicate evidence before its original error.
        if let Some(duplicate_event) = duplicate_event {
            self.evidence
                .record("duplicate_peer_receive", duplicate_event);
            assert_ne!(
                self.mode,
                RunMode::Preflight,
                "unexpected duplicate MQTT receive in tiny preflight for {op} on {device}"
            );
        }
        self.evidence.record("peer_receive", event);
        op
    }
    fn ack(&self, peer: &str, device: &str, op: &str, delivery: &str, protocol: &str) {
        let first = self
            .ack_sent
            .lock()
            .unwrap()
            .insert((op.into(), device.into()));
        assert!(
            first || self.mode != RunMode::Preflight,
            "unexpected duplicate ACK in tiny preflight"
        );
        self.evidence.record("ack_sent",json!({"peer":peer,"device_key":device,"op_id":op,"delivery_id":delivery,"protocol":protocol,"semantics":if protocol=="http-v2" {"HTTP V2 ACK success after test peer journal COMMIT; server terminal proof observed separately"} else {"PUBACK write completed; not durable proof"}}));
    }
}
struct BackgroundGuard(Arc<Shared>, String);
impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        if !self.0.stop.load(Ordering::Relaxed) {
            self.0
                .fail(format!("{} exited before owner stopped it", self.1));
        }
    }
}
struct StopGuard(Arc<Shared>);
impl Drop for StopGuard {
    fn drop(&mut self) {
        self.0.request_stop();
    }
}
struct Device {
    key: String,
    id: Vec<u8>,
    http_pull: bool,
}
struct Product {
    child: Child,
    directory: PathBuf,
    binary: PathBuf,
    base: String,
    synthetic_credential: String,
    http: Client,
    mqtt_port: u16,
    backend: String,
}
fn private_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn guard_disk(path: &Path) {
    let out = Command::new("df").arg("-Pk").arg(path).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let available = text
        .lines()
        .last()
        .unwrap()
        .split_whitespace()
        .nth(3)
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024;
    assert!(
        available >= 4 * 1024 * 1024 * 1024 + 512 * 1024 * 1024,
        "resource STOP: below 4GiB floor + 512MiB reserve (available={available})"
    );
}
fn file_hash(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = blake3::Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let count = file.read(&mut buf).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buf[..count]);
    }
    hash.finalize().to_hex().to_string()
}
impl Product {
    async fn spawn(
        directory: PathBuf,
        evidence: &Evidence,
        mode: RunMode,
        qa_profile: bool,
    ) -> Self {
        guard_disk(&directory);
        let profile_directory = gateway_qa_profile_directory(&directory, qa_profile)
            .unwrap_or_else(|error| panic!("{error}"));
        let binary = PathBuf::from(
            std::env::var_os("C12_GATEWAY_BINARY")
                .expect("absolute normal product binary required"),
        );
        validate_executable_binary(&binary).unwrap_or_else(|error| panic!("{error}"));
        let database = directory.join("gateway.sqlite");
        let log_path = directory.join("gateway.log");
        let config_path = directory.join("gateway.config.json");
        for output in [&database, &log_path, &config_path] {
            assert!(
                !output.exists(),
                "refusing to overwrite explicit run output {}",
                output.display()
            );
            assert_eq!(
                output.parent(),
                Some(directory.as_path()),
                "all run outputs must remain inside the fresh run directory"
            );
        }
        let backend = std::env::var("C12_LEDGER_KIND").expect("main or ordinary oracle required");
        assert!(matches!(backend.as_str(), "main" | "ordinary"));
        let setting = std::env::var("C13_HTTP_PULL_PEER").ok();
        let mixed = http_pull_peer_enabled(mode, &backend, setting.as_deref()).unwrap();
        let peer_description = if mixed {
            "three TCP MQTT5 peers and one normal V2 HTTP Pull/ACK peer"
        } else {
            "TCP MQTT5 loopback peers"
        };
        let provider_description = if mixed {
            "synthetic FCM route only; Token Service unavailable at loopback port1; no external Provider"
        } else {
            "none; Token Service unused at loopback port1"
        };
        let synthetic_credential =
            std::env::var("C12_TEST_SECRET").expect("process-local synthetic credential required");
        assert!(synthetic_credential.len() >= 24);
        let http_port = port();
        let mqtt_port = port();
        let base = format!("http://127.0.0.1:{http_port}");
        let config = json!({
            "binary": binary,
            "binary_blake3": file_hash(&binary),
            "mode": mode.name(),
            "oracle": backend,
            "runtime_profile": "small",
            "private_transports": peer_description,
            "provider": provider_description,
            "http_pull_peer": mixed,
            "http_wake": if mixed {"controlled submit-success Notify, not external Provider wake latency"} else {"not used"},
            "qa": qa_profile,
            "gateway_qa_profile_directory":profile_directory,
            "measurement_scope":if qa_profile {"diagnostic QA-instrumented product; not the sealed normal A/B artifact; Provider substitution remains disabled"} else {"normal product; no Gateway QA profiling requested"},
            "database": database,
            "http_bind": format!("127.0.0.1:{http_port}"),
            "mqtt_bind": format!("127.0.0.1:{mqtt_port}"),
            "messages": mode.messages(),
            "target_devices": mode.target_devices(),
            "targets": mode.targets(),
            "http_concurrency_max": mode.http_concurrency(),
            "load_plan": mode.load_plan().map(LoadPlan::to_value),
        });
        let mut config_file = private_file(&config_path);
        serde_json::to_writer_pretty(&mut config_file, &config).unwrap();
        config_file.write_all(b"\n").unwrap();
        config_file.flush().unwrap();
        let log = private_file(&log_path);
        let mut command = Command::new(&binary);
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("PUSHGO_")) {
            command.env_remove(key);
        }
        command.args([
            "--http-addr",
            &format!("127.0.0.1:{http_port}"),
            "--db-url",
            &format!("sqlite://{}?mode=rwc", database.display()),
            "--runtime-profile",
            "small",
            "--token",
            &synthetic_credential,
            "--token-service-url",
            "http://127.0.0.1:1",
            "--private-transports",
            "mqtt",
            "--mqtt-bind",
            &format!("127.0.0.1:{mqtt_port}"),
            "--mqtt-port",
            &mqtt_port.to_string(),
            "--observability-log-level",
            "info",
        ]);
        if let Some(directory) = &profile_directory {
            command.arg("--qa-resource-observation-dir").arg(directory);
        }
        let child = command
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut product = Self {
            child,
            directory,
            binary,
            base,
            synthetic_credential,
            http: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            mqtt_port,
            backend,
        };
        evidence.record("configuration",json!({"mode":mode.name(),"config_file":config_path,"database_file":database,"log_file":log_path,"binary":product.binary,"binary_blake3":file_hash(&product.binary),"oracle":product.backend,"runtime_profile":"small","private_transports":peer_description,"http_pull_peer":mixed,"http_wake":if mixed {"controlled submit-success Notify, not external Provider wake latency"} else {"not used"},"target_devices":mode.target_devices(),"provider":provider_description,"qa":qa_profile,"gateway_qa_profile_directory":profile_directory,"measurement_scope":if qa_profile {"diagnostic QA-instrumented product; not the sealed normal A/B artifact; Provider substitution remains disabled"} else {"normal product; no Gateway QA profiling requested"},"messages":mode.messages(),"targets":mode.targets(),"warm_connections":8,"warm_idle_seconds":mode.warm_idle().as_secs(),"post_drain_idle_seconds":mode.post_drain_idle().as_secs(),"hard_limit_seconds":mode.hard_limit().as_secs(),"drain_limit_seconds":mode.drain_limit().as_secs(),"ack_hold_seconds":mode.hold_duration().as_secs_f64(),"observer_interval_ms":100,"http_concurrency_max":mode.http_concurrency(),"test_owned_background_tokio_tasks":mode.target_devices()+2,"test_owned_http_offer_futures_max":mode.http_concurrency(),"gateway_tokio_task_count":"not instrumented; process thread count is sampled instead","load_plan":mode.load_plan().map(LoadPlan::to_value),"database_process":"embedded SQLite shares Gateway process CPU/RSS","commit_oracle":"100ms committed reads are visibility upper bounds; HTTP requires local journal COMMIT and actual successful ACK plus server acked_at/target absence; not exact COMMIT timing","product_query_counts":"NOT RECORDED at normal info log level; no debug trace enabled"}));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                product.child.try_wait().unwrap().is_none(),
                "normal product exited during startup"
            );
            if product
                .http
                .get(&product.base)
                .bearer_auth(&product.synthetic_credential)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(Instant::now() < deadline, "product readiness timeout");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        resource_boundary(product.child.id(), evidence, "startup_ready", false);
        product
    }
    async fn post(&self, path: &str, input: Value) -> Value {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.synthetic_credential)
            .json(&input)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let value: Value = response.json().await.unwrap();
        assert_eq!(status, 200, "control path {path} failed");
        assert_eq!(
            value["success"], true,
            "control path {path} returned a business failure"
        );
        value
    }
    async fn device(&self, http_pull: bool) -> Device {
        let platform = if http_pull { "android" } else { "mqtt" };
        let key = self
            .post("/device/register", json!({"platform":platform}))
            .await["data"]["device_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let channel_type = if http_pull { "fcm" } else { "private" };
        let mut input = json!({"device_key":key,"platform":platform,"channel_type":channel_type});
        if http_pull {
            input["provider_token"] =
                json!(format!("synthetic-load-{:032x}", rand::random::<u128>()));
        }
        let route = self.post("/channel/device", input).await;
        assert_eq!(route["data"]["device_key"].as_str(), Some(key.as_str()));
        assert_eq!(route["data"]["channel_type"], channel_type);
        let mut connection = SqliteConnection::connect(&format!(
            "sqlite://{}?mode=ro",
            self.directory.join("gateway.sqlite").display()
        ))
        .await
        .unwrap();
        let id: Vec<u8> = sqlx::query_scalar("SELECT device_id FROM devices WHERE device_key=?")
            .bind(&key)
            .fetch_one(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        Device { key, id, http_pull }
    }
    async fn subscribe(&self, device: &str, channel: Option<&str>) -> String {
        let input = match channel {
            Some(channel) => {
                json!({"device_key":device,"channel_id":channel,"password":self.synthetic_credential})
            }
            None => {
                json!({"device_key":device,"channel_name":"c12-paired-mqtt","password":self.synthetic_credential})
            }
        };
        let response = self.post("/channel/subscribe", input).await;
        assert_eq!(response["data"]["subscribed"], true);
        response["data"]["channel_id"].as_str().unwrap().into()
    }
    async fn verify_connected_targets(
        &self,
        devices: &[Device],
        channel: &str,
        evidence: &Evidence,
    ) {
        let mut connection = SqliteConnection::connect(&format!(
            "sqlite://{}?mode=ro",
            self.directory.join("gateway.sqlite").display()
        ))
        .await
        .unwrap();
        let channel_id =
            pushgo_gateway::util::decode_crockford_base32_128(channel).expect("normal channel id");
        let now = chrono::Utc::now().timestamp_millis();
        // Main's actual private subscriber selector uses these canonical rows
        // and predicates (access/subscriptions.rs:list_private_subscribers).
        // C's ordinary_subscriptions/device_routes are views of the same rows.
        let rows=sqlx::query("SELECT d.device_key,d.device_id,d.platform,d.channel_type FROM channel_subscriptions s JOIN devices d ON d.device_id=s.device_id WHERE s.channel_id=? AND s.status='active' AND d.route_updated_at IS NOT NULL AND s.created_at<=? ORDER BY d.device_key").bind(&channel_id[..]).bind(now).fetch_all(&mut connection).await.unwrap();
        assert_eq!(
            rows.len(),
            devices.len(),
            "actual canonical selected recipients after CONNECT"
        );
        for device in devices {
            let row = rows
                .iter()
                .find(|row| row.get::<String, _>("device_key") == device.key)
                .expect("CONNECT must preserve the registered/subscribed device key");
            assert_eq!(
                row.get::<Vec<u8>, _>("device_id"),
                device.id,
                "CONNECT must preserve device identity"
            );
            assert_eq!(
                row.get::<String, _>("platform"),
                if device.http_pull { "android" } else { "mqtt" }
            );
            assert_eq!(
                row.get::<String, _>("channel_type"),
                if device.http_pull { "fcm" } else { "private" }
            );
        }
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND status='active'",
        )
        .bind(&channel_id[..])
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(active, devices.len() as i64);
        if self.backend == "ordinary" {
            let selected:i64=sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=lower(hex(?)) AND s.created_at<=? AND d.retired_at IS NULL AND ((d.channel_type='private' AND d.platform='mqtt') OR (d.channel_type='fcm' AND d.platform='android' AND d.provider='FCM' AND d.provider_token IS NOT NULL))").bind(&channel_id[..]).bind(now).fetch_one(&mut connection).await.unwrap();
            assert_eq!(
                selected,
                devices.len() as i64,
                "all recipients in C's canonical control projection"
            );
        }
        connection.close().await.unwrap();
        evidence.record("control_preflight",json!({"passed":true,"mqtt_devices":devices.iter().filter(|d|!d.http_pull).count(),"http_v2_devices":devices.iter().filter(|d|d.http_pull).count(),"original_device_keys_preserved":devices.len(),"original_device_ids_preserved":devices.len(),"canonical_active_subscriptions":active,"selected_targets":rows.len(),"scope":"actual canonical control selectors before measured offers; frozen target identities also checked against SQL throughout; admission success is never delivery completion"}));
    }
    async fn shutdown(&mut self, evidence: &Evidence) {
        evidence.record("shutdown_started", json!({}));
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                evidence.record(
                    "shutdown_complete",
                    json!({"exit_code":status.code(),"success":status.success()}),
                );
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "normal shutdown timeout");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
impl Drop for Product {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn peer(
    product: &Product,
    device: String,
    label: String,
    device_index: usize,
    held: bool,
    shared: Arc<Shared>,
) -> JoinHandle<()> {
    let port = product.mqtt_port;
    let credential = product.synthetic_credential.clone();
    let mut mqtt =
        ProductMqttClient::connect(product.mqtt_port, &device, &product.synthetic_credential).await;
    shared
        .evidence
        .record("peer_connected", json!({"peer":label,"device_key":device}));
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), label.clone());
        let mut pending = BTreeMap::<u16, (String, String, Option<MqttPendingTiming>)>::new();
        let mut last_ping = Instant::now();
        let mut disconnected_once = false;
        let mut last_ack_write_completed = None;
        let mut last_ack_crossed_disconnect = false;
        while !shared.stop.load(Ordering::Relaxed) {
            let now = shared.evidence.us();
            let from = shared.hold_from_us.load(Ordering::Relaxed);
            let until = shared.hold_until_us.load(Ordering::Relaxed);
            if shared.mode.is_delivery_load()
                && held
                && !disconnected_once
                && from > 0
                && now >= from
                && now < until
                && !pending.is_empty()
            {
                shared.evidence.record("peer_disconnected", json!({"peer":label,"device_key":device,"unacknowledged_local_packets":pending.len(),"semantics":"drop actual MQTT socket; no PUBACK for pending packets, durable Gateway responsibility remains"}));
                let disconnect_started = shared.evidence.timing.start();
                last_ack_crossed_disconnect = last_ack_write_completed.is_some();
                drop(mqtt);
                pending.clear();
                while shared.evidence.us() < until && !shared.stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if shared.stop.load(Ordering::Relaxed) {
                    return;
                }
                mqtt = ProductMqttClient::connect(port, &device, &credential).await;
                let reconnected = shared.evidence.timing.start();
                shared.evidence.timing.record_between(
                    &shared.evidence.timing.mqtt[device_index].socket_drop_to_reconnect_complete,
                    disconnect_started,
                    reconnected,
                );
                shared.evidence.record(
                    "peer_reconnected",
                    json!({"peer":label,"device_key":device,"same_identity":true}),
                );
                disconnected_once = true;
                last_ping = Instant::now();
            }
            if last_ping.elapsed() >= Duration::from_secs(5) {
                mqtt.ping().await;
                last_ping = Instant::now();
            }
            let now = shared.evidence.us();
            let holding = held
                && now >= shared.hold_from_us.load(Ordering::Relaxed)
                && now < shared.hold_until_us.load(Ordering::Relaxed);
            if !holding {
                for (packet, (op, delivery, timing)) in std::mem::take(&mut pending) {
                    let write_started = shared.evidence.timing.start();
                    mqtt.acknowledge(packet).await;
                    let write_completed = shared.evidence.timing.start();
                    last_ack_write_completed = write_completed;
                    let peer_timing = &shared.evidence.timing.mqtt[device_index];
                    shared.evidence.timing.record_between(
                        &peer_timing.puback_write,
                        write_started,
                        write_completed,
                    );
                    if let Some(timing) = timing {
                        let peer_timing = &shared.evidence.timing.mqtt[timing.slot];
                        shared.evidence.timing.record_between(
                            &peer_timing.verify_return_to_puback_write_complete,
                            Some(timing.verify_returned),
                            write_completed,
                        );
                        shared.evidence.timing.record_between(
                            &peer_timing.packet_ready_to_puback_write_complete,
                            Some(timing.ready),
                            write_completed,
                        );
                    }
                    shared.ack(&label, &device, &op, &delivery, "mqtt");
                }
            }
            let receive_started = shared.evidence.timing.start();
            if let Some(gap) =
                take_puback_to_receive_gap(&mut last_ack_write_completed, receive_started)
            {
                let peer_timing = &shared.evidence.timing.mqtt[device_index];
                let histogram = if last_ack_crossed_disconnect {
                    &peer_timing.last_puback_to_first_receive_after_disconnect
                } else {
                    &peer_timing.last_puback_to_first_receive
                };
                histogram.record(gap);
            }
            last_ack_crossed_disconnect = false;
            let (packet, stats) = mqtt
                .receive_with_stats(Duration::from_millis(50), shared.evidence.timing.enabled)
                .await;
            let receive_completed = shared.evidence.timing.start();
            if let Some(stats) = stats {
                let peer_timing = &shared.evidence.timing.mqtt[device_index];
                let histogram = if packet.is_some() {
                    &peer_timing.receive_success
                } else {
                    &peer_timing.receive_timeout
                };
                shared.evidence.timing.record_between(
                    histogram,
                    receive_started,
                    receive_completed,
                );
                peer_timing.record_receive(
                    stats,
                    packet.is_some(),
                    matches!(&packet, Some(mqttbytes::v5::Packet::Publish(_))),
                );
            }
            let Some(packet) = packet else {
                continue;
            };
            match packet {
                mqttbytes::v5::Packet::Publish(publish) => {
                    let packet_ready = receive_completed;
                    let envelope: Value = serde_json::from_slice(&publish.payload).unwrap();
                    let json_complete = shared.evidence.timing.start();
                    let peer_timing = &shared.evidence.timing.mqtt[device_index];
                    shared.evidence.timing.record_between(
                        &peer_timing.packet_ready_to_json_complete,
                        packet_ready,
                        json_complete,
                    );
                    let delivery = envelope["delivery_id"].as_str().unwrap().to_owned();
                    let packet_timing =
                        packet_ready
                            .zip(json_complete)
                            .map(|(ready, json_complete)| MqttPacketTiming {
                                slot: device_index,
                                ready,
                                json_complete,
                            });
                    let op =
                        shared.verify(&label, &device, &envelope["data"], &delivery, packet_timing);
                    let verify_returned = shared.evidence.timing.start();
                    shared.evidence.timing.record_between(
                        &peer_timing.packet_ready_to_verify_return,
                        packet_ready,
                        verify_returned,
                    );
                    let pending_timing =
                        packet_ready
                            .zip(verify_returned)
                            .map(|(ready, verify_returned)| MqttPendingTiming {
                                slot: device_index,
                                ready,
                                verify_returned,
                            });
                    pending.insert(publish.pkid, (op, delivery, pending_timing));
                    assert!(
                        pending.len() <= shared.mode.messages(),
                        "pending ACK bound for {} mode",
                        shared.mode.name()
                    );
                }
                mqttbytes::v5::Packet::PingResp => {}
                other => panic!("unexpected MQTT packet: {other:?}"),
            }
        }
        if shared.mode.is_delivery_load() && held {
            assert!(
                disconnected_once,
                "delivery-load must actually disconnect with an unacknowledged packet"
            );
        }
    })
}

async fn peer_http_post(
    client: &Client,
    base: &str,
    credential: &str,
    path: &str,
    input: Value,
) -> Result<Value, String> {
    let response = client
        .post(format!("{base}{path}"))
        .bearer_auth(credential)
        .json(&input)
        .send()
        .await
        .map_err(|_| format!("HTTP peer transport failure at {path}; pending journal retained"))?;
    let status = response.status();
    let value: Value = response
        .json()
        .await
        .map_err(|_| format!("HTTP peer invalid JSON at {path}"))?;
    if !status.is_success() || value["success"] != true {
        return Err(format!("HTTP peer rejected at {path}: status{status}"));
    }
    Ok(value["data"].clone())
}

async fn drain_http_peer_journal(
    client: &Client,
    base: &str,
    credential: &str,
    device: &str,
    journal: &mut SqliteConnection,
    shared: &Shared,
) -> Result<(), String> {
    // A failed/unknown ACK leaves the same pending rows durable. Reopening this
    // test-owned journal resumes those IDs; this is not a product ACK outbox.
    for _ in 0..=shared.mode.messages().div_ceil(HTTP_PULL_PAGE_LIMIT) {
        let rows = sqlx::query("SELECT delivery_id,op_id,payload FROM http_peer_journal WHERE device_key=? AND acked=0 ORDER BY rowid LIMIT ?")
            .bind(device).bind(HTTP_PULL_PAGE_LIMIT as i64)
            .fetch_all(&mut *journal).await.map_err(|_| "HTTP peer pending journal read failed")?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut acknowledged = Vec::with_capacity(rows.len());
        for row in rows {
            let delivery: String = row.get("delivery_id");
            let operation: String = row.get("op_id");
            let pair = (operation.clone(), device.to_string());
            if !shared.journaled.lock().unwrap().contains(&pair) {
                let payload: Value = serde_json::from_str(&row.get::<String, _>("payload"))
                    .map_err(|_| "HTTP peer stored payload invalid")?;
                let data = pull_payload_data(&payload)?;
                let observed = shared.verify("http-v2-0", device, &data, &delivery, None);
                if observed != operation {
                    return Err("HTTP peer journal identity mismatch".into());
                }
                shared.journaled.lock().unwrap().insert(pair);
            }
            acknowledged.push((operation, delivery));
        }
        let ids: Vec<_> = acknowledged.iter().map(|(_, id)| id.clone()).collect();
        let ack_started = Instant::now();
        let result = peer_http_post(
            client,
            base,
            credential,
            "/v2/messages/ack",
            json!({"device_key":device,"delivery_ids":ids}),
        )
        .await?;
        let http_elapsed_us = ack_started.elapsed().as_micros() as u64;
        let requested = result["requested_count"]
            .as_u64()
            .ok_or("HTTP peer ACK requested_count absent")?;
        let removed = result["removed_count"]
            .as_u64()
            .ok_or("HTTP peer ACK removed_count absent")?;
        if requested != acknowledged.len() as u64 || removed > requested {
            return Err("HTTP peer ACK count mismatch".into());
        }
        let transaction_started = shared.evidence.timing.start();
        let mut tx = journal
            .begin()
            .await
            .map_err(|_| "HTTP peer ACK journal begin failed")?;
        for (_, delivery) in &acknowledged {
            sqlx::query("UPDATE http_peer_journal SET acked=1 WHERE device_key=? AND delivery_id=? AND acked=0")
                .bind(device).bind(delivery).execute(&mut *tx).await.map_err(|_| "HTTP peer ACK journal update failed")?;
        }
        let commit_started = shared.evidence.timing.start();
        tx.commit()
            .await
            .map_err(|_| "HTTP peer ACK journal COMMIT failed")?;
        let commit_completed = shared.evidence.timing.start();
        shared.evidence.timing.record_between(
            &shared.evidence.timing.http_journal_ack_marker_commit,
            commit_started,
            commit_completed,
        );
        shared.evidence.timing.record_between(
            &shared.evidence.timing.http_journal_ack_marker_transaction,
            transaction_started,
            commit_completed,
        );
        for (operation, delivery) in acknowledged {
            shared.ack("http-v2-0", device, &operation, &delivery, "http-v2");
        }
        shared.evidence.record("http_peer_ack_batch", json!({"requested":requested,"removed":removed,"http_elapsed_us":http_elapsed_us,"journal_committed_before_ack":true,"semantics":"HTTP success, including idempotent zero removal; server acked_at/absence checked independently; event follows local ACK-marker COMMIT"}));
    }
    Err("HTTP peer pending journal drain exceeded finite cohort bound".into())
}

async fn http_pull_peer(product: &Product, device: String, shared: Arc<Shared>) -> JoinHandle<()> {
    let client = product.http.clone();
    let base = product.base.clone();
    let credential = product.synthetic_credential.clone();
    let journal_path = product.directory.join("http-peer-journal.sqlite");
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), "http-v2-0".into());
        let result: Result<(), String> = async {
            if !journal_path.exists() {
                drop(private_file(&journal_path));
            }
            let mut journal = SqliteConnection::connect(&format!("sqlite://{}?mode=rwc", journal_path.display()))
                .await.map_err(|_| "HTTP peer journal open failed")?;
            sqlx::query("PRAGMA synchronous=FULL").execute(&mut journal).await.map_err(|_| "HTTP peer journal durability setup failed")?;
            sqlx::query("CREATE TABLE IF NOT EXISTS http_peer_journal(device_key TEXT NOT NULL,delivery_id TEXT NOT NULL,op_id TEXT NOT NULL,payload TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(device_key,delivery_id))")
                .execute(&mut journal).await.map_err(|_| "HTTP peer journal schema failed")?;
            sqlx::query("CREATE INDEX IF NOT EXISTS http_peer_pending ON http_peer_journal(device_key) WHERE acked=0")
                .execute(&mut journal).await.map_err(|_| "HTTP peer journal pending index failed")?;
            shared.evidence.record("peer_connected", json!({"peer":"http-v2-0","device_key":device,"transport":"normal V2 HTTP Pull/ACK","journal":journal_path,"wake":"test-controlled submit-success Notify; not actual Provider wake latency"}));
            while !shared.stop.load(Ordering::Relaxed) {
                drain_http_peer_journal(&client, &base, &credential, &device, &mut journal, &shared).await?;
                let mut token: Option<String> = None;
                let mut token_hashes = BTreeSet::new();
                let mut complete = false;
                for page_index in 0..=shared.mode.messages() {
                    if shared.stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let started = Instant::now();
                    let request_started_elapsed_us = shared.evidence.us();
                    let mut input = json!({"device_key":device});
                    if let Some(value) = &token {
                        input["page_token"] = json!(value);
                    }
                    let page = peer_http_post(&client, &base, &credential, "/v2/messages/pull", input).await?;
                    let pull_elapsed_us = started.elapsed().as_micros() as u64;
                    let items = page["items"].as_array().ok_or("HTTP peer Pull items absent")?;
                    if items.len() > HTTP_PULL_PAGE_LIMIT {
                        return Err("HTTP peer Pull exceeded200item bound".into());
                    }
                    let (page_complete, more, next) = pull_scan_progress(&page)?;
                    complete = page_complete;
                    if let Some(value) = &next
                        && !token_hashes.insert(*blake3::hash(value.as_bytes()).as_bytes()) {
                        return Err("HTTP peer repeated opaque page token".into());
                    }
                    let mut saved = Vec::with_capacity(items.len());
                    let mut page_ids = BTreeSet::new();
                    let transaction_started = shared.evidence.timing.start();
                    let mut tx = journal.begin().await.map_err(|_| "HTTP peer save journal begin failed")?;
                    for item in items {
                        let delivery = item["delivery_id"].as_str().filter(|id| !id.is_empty()).ok_or("HTTP peer empty delivery identity")?;
                        if !page_ids.insert(delivery) {
                            return Err("HTTP peer repeated identity within page".into());
                        }
                        let data = pull_payload_data(&item["payload"])?;
                        let operation = shared.verify("http-v2-0", &device, &data, delivery, None);
                        let payload = serde_json::to_string(&item["payload"]).map_err(|_| "HTTP peer journal payload encode failed")?;
                        if let Some(old) = sqlx::query("SELECT op_id,payload FROM http_peer_journal WHERE device_key=? AND delivery_id=?")
                            .bind(&device).bind(delivery).fetch_optional(&mut *tx).await.map_err(|_| "HTTP peer duplicate lookup failed")? {
                            let old_payload: Value = serde_json::from_str(&old.get::<String,_>("payload"))
                                .map_err(|_| "HTTP peer stored replay payload invalid")?;
                            if old.get::<String,_>("op_id") != operation || old_payload != item["payload"] {
                                return Err("HTTP peer replay changed persisted content".into());
                            }
                            sqlx::query("UPDATE http_peer_journal SET acked=0 WHERE device_key=? AND delivery_id=?")
                                .bind(&device).bind(delivery).execute(&mut *tx).await.map_err(|_| "HTTP peer replay ACK responsibility failed")?;
                        } else {
                            sqlx::query("INSERT INTO http_peer_journal(device_key,delivery_id,op_id,payload) VALUES(?,?,?,?)")
                                .bind(&device).bind(delivery).bind(&operation).bind(payload).execute(&mut *tx).await.map_err(|_| "HTTP peer save failed")?;
                        }
                        saved.push((operation, delivery.to_string()));
                    }
                    let commit_started = shared.evidence.timing.start();
                    tx.commit().await.map_err(|_| "HTTP peer save journal COMMIT failed")?;
                    let commit_completed = shared.evidence.timing.start();
                    shared.evidence.timing.record_between(&shared.evidence.timing.http_journal_save_commit, commit_started, commit_completed);
                    shared.evidence.timing.record_between(&shared.evidence.timing.http_journal_save_transaction, transaction_started, commit_completed);
                    for (operation, delivery) in &saved {
                        shared.journaled.lock().unwrap().insert((operation.clone(), device.clone()));
                        shared.evidence.record("http_peer_journal_commit", json!({"peer":"http-v2-0","op_id":operation,"device_key":device,"delivery_id":delivery,"semantics":"test-owned peer SQLite COMMIT completed before HTTP ACK; not an App product-store measurement"}));
                    }
                    if !saved.is_empty() {
                        shared.evidence.record("peer_durable_save_commit", json!({"peer":"http-v2-0","items":saved.len(),"storage":"test-owned SQLite journal; not a product-client persistence result"}));
                    }
                    shared.evidence.record("http_peer_pull_page", json!({"page_index":page_index,"request_started_elapsed_us":request_started_elapsed_us,"request_token_present":token.is_some(),"next_token_present":next.is_some(),"scan_complete":complete,"has_more":more,"items":items.len(),"elapsed_us":pull_elapsed_us,"through_journal_commit_us":started.elapsed().as_micros() as u64,"opaque_tokens_logged":false}));
                    drain_http_peer_journal(&client, &base, &credential, &device, &mut journal, &shared).await?;
                    if complete {
                        break;
                    }
                    token = next;
                }
                if !complete && !shared.stop.load(Ordering::Relaxed) {
                    return Err("HTTP peer scan exceeded finite cohort page bound".into());
                }
                if !shared.stop.load(Ordering::Relaxed) {
                    // notify_one retains one permit when admission races this
                    // wait or another page. No empty polling during final idle.
                    shared.http_wake.notified().await;
                }
            }
            journal.close().await.map_err(|_| "HTTP peer journal close failed")?;
            Ok(())
        }.await;
        if let Err(error) = result {
            shared.fail(error);
        }
    })
}
fn process_usage(pid: u32) -> Value {
    let output = Command::new("ps")
        .args(["-o", "cputime=,rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let parts: Vec<_> = text.split_whitespace().collect();
    assert_eq!(parts.len(), 2);
    let cpu = parts[0]
        .split(':')
        .rev()
        .enumerate()
        .map(|(i, v)| v.parse::<f64>().unwrap() * 60_f64.powi(i as i32))
        .sum::<f64>();
    let os_thread_count = Command::new("ps")
        .args(["-M", "-p", &pid.to_string(), "-o", "pid="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        });
    let rss_kib = parts[1].parse::<u64>().unwrap();
    assert!(
        rss_kib <= MAX_PROCESS_RSS_KIB,
        "resource STOP: process {pid} RSS {rss_kib}KiB exceeds {MAX_PROCESS_RSS_KIB}KiB"
    );
    json!({"pid":pid,"cpu_seconds":cpu,"rss_kib":rss_kib,"os_thread_count":os_thread_count})
}

fn metadata_bytes_or_gone(metadata: std::io::Result<std::fs::Metadata>) -> Option<u64> {
    match metadata {
        Ok(metadata) => Some(metadata.len()),
        // SQLite can remove its short-lived journal after read_dir enumerated
        // it. It no longer consumes space; all other I/O failures remain fatal.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("run-directory metadata check failed: {error}"),
    }
}

fn run_directory_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("run-directory size check failed: {error}"))
        .filter_map(|entry| {
            let entry =
                entry.unwrap_or_else(|error| panic!("run-directory entry check failed: {error}"));
            metadata_bytes_or_gone(entry.metadata())
        })
        .sum()
}
fn resource_boundary(pid: u32, evidence: &Evidence, phase: &str, sockets: bool) {
    // Capture before this resource sample writes its own evidence. Reading the
    // fixed histograms must not recursively log or include this event's I/O.
    let timing = evidence.timing.snapshot();
    let mut data = json!({"phase":phase,"gateway":process_usage(pid),"harness_including_peers_and_observer":process_usage(std::process::id())});
    if let Some(timing) = timing {
        data["driver_timing"] = timing;
    }
    if sockets {
        // Only this synthetic Gateway's TCP endpoint metadata is inspected;
        // process arguments and environment are never requested or recorded.
        data["established_tcp"] = match Command::new("lsof")
            .args([
                "-nP",
                "-a",
                "-p",
                &pid.to_string(),
                "-iTCP",
                "-sTCP:ESTABLISHED",
                "-Fn",
            ])
            .output()
        {
            Ok(output) if output.status.success() || output.status.code() == Some(1) => {
                let text = String::from_utf8(output.stdout).unwrap();
                let endpoints: Vec<_> = text
                    .lines()
                    .filter_map(|line| line.strip_prefix('n'))
                    .collect();
                json!({"available":true,"count":endpoints.len(),"endpoints":endpoints})
            }
            Ok(output) => json!({"available":false,"exit_code":output.status.code()}),
            Err(_) => json!({"available":false,"reason":"lsof unavailable"}),
        };
    }
    evidence.record("phase_resources", data);
}

// The positive terminal set is established below from actual receive/PUBACK
// evidence and committed SQL state. Count it once, not once per message: an
// O(messages * completed_targets) observer can otherwise throttle its own peers.
fn terminal_counts_by_operation(terminal: &BTreeSet<(String, String)>) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for (operation, _) in terminal {
        *counts.entry(operation.as_str()).or_insert(0) += 1;
    }
    counts
}

fn has_positive_terminal_evidence(
    target: &(String, String),
    known_messages: &BTreeSet<String>,
    received: &BTreeSet<(String, String)>,
    ack_written: &BTreeSet<(String, String)>,
    existing_targets: &BTreeSet<(String, String)>,
    server_acked: &BTreeSet<(String, String)>,
    durable_journal: Option<&BTreeSet<(String, String)>>,
) -> bool {
    known_messages.contains(&target.0)
        && received.contains(target)
        && ack_written.contains(target)
        && (!existing_targets.contains(target) || server_acked.contains(target))
        && durable_journal.is_none_or(|journal| journal.contains(target))
}

fn observer(product: &Product, devices: &[Device], shared: Arc<Shared>) -> JoinHandle<()> {
    let database = product.directory.join("gateway.sqlite");
    let backend = product.backend.clone();
    let pid = product.child.id();
    let keys = devices.iter().map(|d| d.key.clone()).collect::<Vec<_>>();
    let ids = devices.iter().map(|d| d.id.clone()).collect::<Vec<_>>();
    let http_device = devices.iter().find(|d| d.http_pull).map(|d| d.key.clone());
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), "database observer".to_string());
        let selected = if backend == "main" {
            database.with_file_name("gateway.delivery.sqlite")
        } else {
            database.clone()
        };
        let mut connection =
            SqliteConnection::connect(&format!("sqlite://{}?mode=ro", selected.display()))
                .await
                .unwrap();
        for file in [
            database.clone(),
            database.with_file_name("gateway.delivery.sqlite"),
            database.with_file_name("gateway.dispatch.sqlite"),
        ] {
            let mut metadata =
                SqliteConnection::connect(&format!("sqlite://{}?mode=ro", file.display()))
                    .await
                    .unwrap();
            let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut metadata)
                .await
                .unwrap();
            let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
                .fetch_one(&mut metadata)
                .await
                .unwrap();
            shared.evidence.record("database_configuration",json!({"file":file,"oracle_file":selected,"journal_mode":journal,"page_size":page_size,"read_connection":"RO metadata only; synchronous/cache settings are connection-local and not inferred from this connection","writer_configuration":"SqliteSynchronous::Extra from version-bound src/storage/database/sqlite/bootstrap.rs connect-options construction; verified by source, not this observer"}));
            metadata.close().await.unwrap();
        }
        let mut tick = 0u64;
        let mut previous_cycle_started = None;
        while !shared.stop.load(Ordering::Relaxed) {
            let cycle_started = Instant::now();
            let cycle_start_interval_us = previous_cycle_started
                .replace(cycle_started)
                .map(|previous| cycle_started.duration_since(previous).as_micros() as u64);
            let expected = shared.expected.lock().unwrap().clone();
            let ack_sent = shared.ack_sent.lock().unwrap().clone();
            let received = shared.received.lock().unwrap().clone();
            let accepted = shared.accepted.lock().unwrap().clone();
            let journaled = shared.journaled.lock().unwrap().clone();
            let snapshot_us = cycle_started.elapsed().as_micros() as u64;
            let mut ro_query_elapsed_us = 0u64;
            let mut terminal = BTreeSet::new();
            let mut state_counts = BTreeMap::<String, usize>::new();
            let mut oldest: Option<i64> = None;
            let mut ordinary_pending = None;
            let payloads;
            let expired;
            let now = chrono::Utc::now().timestamp_millis();
            if backend == "main" {
                // Old MQTT PUBACK writes an actual acked row. Empty/nonexistent
                // outboxes cannot make a target complete in this oracle.
                let query_started = Instant::now();
                let rows=sqlx::query("SELECT device_id,delivery_id,status,created_at,acked_at FROM private_outbox ORDER BY delivery_id,device_id LIMIT ?").bind(shared.mode.targets() as i64 + 1).fetch_all(&mut connection).await.unwrap();
                ro_query_elapsed_us += query_started.elapsed().as_micros() as u64;
                assert!(
                    rows.len() <= shared.mode.targets(),
                    "fresh cohort outbox bound"
                );
                let delivery_pairs: Vec<_> = expected
                    .iter()
                    .filter_map(|(op, e)| e.delivery_id.as_ref().map(|id| (id.clone(), op.clone())))
                    .collect();
                let by_delivery: BTreeMap<_, _> = delivery_pairs.iter().cloned().collect();
                assert_eq!(
                    by_delivery.len(),
                    delivery_pairs.len(),
                    "duplicate actual MQTT delivery identity"
                );
                let all_delivery_ids_known = by_delivery.len() == expected.len();
                let mut outbox_pairs = BTreeSet::new();
                for row in rows {
                    let device_id: Vec<u8> = row.get("device_id");
                    let delivery: String = row.get("delivery_id");
                    let state: String = row.get("status");
                    let Some(op) = by_delivery.get(&delivery) else {
                        assert!(
                            !all_delivery_ids_known,
                            "unexpected persisted outbox delivery outside accepted cohort"
                        );
                        if state != "acked" {
                            let created: i64 = row.get("created_at");
                            oldest = Some(oldest.map_or(created, |old| old.min(created)));
                        }
                        *state_counts.entry(state).or_default() += 1;
                        continue;
                    };
                    let index = ids
                        .iter()
                        .position(|id| *id == device_id)
                        .expect("unexpected persisted outbox target device");
                    let pair = (op.clone(), keys[index].clone());
                    assert!(
                        outbox_pairs.insert(pair.clone()),
                        "duplicate persisted outbox target"
                    );
                    shared.persisted.lock().unwrap().insert(op.clone());
                    *state_counts.entry(state.clone()).or_default() += 1;
                    if state != "acked" {
                        let created: i64 = row.get("created_at");
                        oldest = Some(oldest.map_or(created, |old| old.min(created)));
                    }
                    if state == "acked"
                        && row.get::<Option<i64>, _>("acked_at").is_some()
                        && ack_sent.contains(&pair)
                        && received.contains(&pair)
                    {
                        terminal.insert(pair);
                    }
                }
                let query_started = Instant::now();
                let rows =
                    sqlx::query("SELECT delivery_id,expires_at FROM private_payloads LIMIT ?")
                        .bind(shared.mode.messages() as i64 + 1)
                        .fetch_all(&mut connection)
                        .await
                        .unwrap();
                ro_query_elapsed_us += query_started.elapsed().as_micros() as u64;
                assert!(rows.len() <= shared.mode.messages());
                payloads = rows.len();
                let body_ids: BTreeSet<String> =
                    rows.iter().map(|r| r.get("delivery_id")).collect();
                if all_delivery_ids_known {
                    assert!(
                        body_ids.iter().all(|id| by_delivery.contains_key(id)),
                        "unexpected persisted payload outside accepted cohort"
                    );
                }
                expired = rows
                    .iter()
                    .filter(|r| r.get::<i64, _>("expires_at") <= now)
                    .count();
                let completed_per_message = terminal_counts_by_operation(&terminal);
                for (op, item) in &expected {
                    if let Some(delivery) = &item.delivery_id
                        && !body_ids.contains(delivery)
                        && completed_per_message.get(op.as_str()).copied().unwrap_or(0)
                            == shared.mode.targets_per_message()
                        && shared.body_released.lock().unwrap().insert(op.clone())
                    {
                        shared.evidence.record(
                            "body_release_commit_visible_upper_bound",
                            json!({"op_id":op}),
                        );
                    }
                }
            } else {
                // Identity must exist, both peers must have received and sent
                // successful PUBACK, then a target's absence is terminal proof.
                let query_started = Instant::now();
                let messages=sqlx::query("SELECT op_id,message_id,delivery_id,payload_bytes,expires_at FROM ordinary_messages LIMIT ?").bind(shared.mode.messages() as i64 + 1).fetch_all(&mut connection).await.unwrap();
                ro_query_elapsed_us += query_started.elapsed().as_micros() as u64;
                assert!(messages.len() <= shared.mode.messages());
                let mut message_ids = BTreeSet::new();
                let mut message_ops = BTreeSet::new();
                for row in &messages {
                    let op: String = row.get("op_id");
                    let item = expected
                        .get(&op)
                        .expect("unexpected persisted message outside accepted cohort");
                    assert!(
                        message_ops.insert(op.clone()),
                        "duplicate persisted ordinary message"
                    );
                    if let (Some(delivery), Some(message)) = (&item.delivery_id, &item.message_id) {
                        assert_eq!(
                            row.get::<String, _>("delivery_id"),
                            *delivery,
                            "durable and actual MQTT delivery identities match"
                        );
                        assert_eq!(
                            row.get::<String, _>("message_id"),
                            *message,
                            "durable and actual HTTP/MQTT message identities match"
                        );
                        if accepted.contains(&op) {
                            message_ids.insert(op.clone());
                            if shared.persisted.lock().unwrap().insert(op.clone())
                                && shared.mode.is_delivery_load()
                            {
                                shared.evidence.record("persist_commit_visible_upper_bound", json!({"op_id":op,"semantics":"100ms observer after successful HTTP response; not exact COMMIT timestamp"}));
                            }
                        }
                    }
                }
                if accepted.len() == shared.mode.messages()
                    && expected.values().all(|item| item.delivery_id.is_some())
                {
                    assert_eq!(
                        message_ids.len(),
                        shared.mode.messages(),
                        "all accepted messages must be persisted with matching identities"
                    );
                }
                let query_started = Instant::now();
                let rows=sqlx::query("SELECT m.op_id,t.device_key,t.state,t.accepted_at,t.acked_at FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id LIMIT ?").bind(shared.mode.targets() as i64 + 1).fetch_all(&mut connection).await.unwrap();
                ro_query_elapsed_us += query_started.elapsed().as_micros() as u64;
                assert!(rows.len() <= shared.mode.targets());
                let mut existing = BTreeSet::new();
                let mut server_acked = BTreeSet::new();
                let mut unacked = 0usize;
                for row in rows {
                    let op: String = row.get("op_id");
                    let key: String = row.get("device_key");
                    let state: String = row.get("state");
                    *state_counts.entry(state).or_default() += 1;
                    assert!(
                        expected.contains_key(&op),
                        "unexpected persisted target outside accepted cohort"
                    );
                    assert!(keys.contains(&key), "unexpected persisted target device");
                    let pair = (op, key);
                    assert!(
                        existing.insert(pair.clone()),
                        "duplicate persisted target row"
                    );
                    if row.get::<Option<i64>, _>("acked_at").is_some() {
                        server_acked.insert(pair);
                    } else {
                        unacked += 1;
                        let accepted: i64 = row.get("accepted_at");
                        oldest = Some(oldest.map_or(accepted, |old| old.min(accepted)));
                    }
                }
                ordinary_pending = Some(unacked);
                for pair in &ack_sent {
                    if has_positive_terminal_evidence(
                        pair,
                        &message_ids,
                        &received,
                        &ack_sent,
                        &existing,
                        &server_acked,
                        (http_device.as_ref() == Some(&pair.1)).then_some(&journaled),
                    ) {
                        terminal.insert(pair.clone());
                    }
                }
                let completed_per_message = terminal_counts_by_operation(&terminal);
                let mut live_payloads = 0usize;
                let mut expired_payloads = 0usize;
                for row in messages {
                    let op: String = row.get("op_id");
                    let bytes: i64 = row.get("payload_bytes");
                    if bytes > 0 {
                        live_payloads += 1;
                        if row.get::<i64, _>("expires_at") <= now {
                            expired_payloads += 1;
                        }
                    } else if completed_per_message.get(op.as_str()).copied().unwrap_or(0)
                        == shared.mode.targets_per_message()
                        && shared.body_released.lock().unwrap().insert(op.clone())
                    {
                        shared.evidence.record(
                            "body_release_commit_visible_upper_bound",
                            json!({"op_id":op}),
                        );
                    }
                }
                payloads = live_payloads;
                expired = expired_payloads;
            }
            for pair in terminal {
                if shared.committed.lock().unwrap().insert(pair.clone()) {
                    shared.evidence.record("ack_commit_visible_upper_bound",json!({"op_id":pair.0,"device_key":pair.1,"oracle":backend,"semantics":"100ms polling plus scheduling/query delay; actual MQTT PUBACK or journal-backed successful HTTP ACK plus durable backend terminal state"}));
                }
            }
            let pending: usize = ordinary_pending.unwrap_or_else(|| {
                state_counts
                    .iter()
                    .filter(|(state, _)| state.as_str() != "acked")
                    .map(|(_, count)| *count)
                    .sum()
            });
            if pending > MAX_PENDING_TARGETS {
                shared.fail(format!(
                    "resource STOP: persisted backlog {pending} exceeds {MAX_PENDING_TARGETS} target records"
                ));
                break;
            }
            shared
                .residual_targets
                .store(pending as u64, Ordering::Relaxed);
            let active_before_sample_us = cycle_started.elapsed().as_micros() as u64;
            shared.evidence.record("database_sample",json!({"states":state_counts,"pending_targets":pending,"payload_count":payloads,"expired_payload_count":expired,"oldest_pending_age_ms":oldest.map(|ts|(now-ts).max(0)),"durable_targets_observed":shared.committed.lock().unwrap().len(),"observer_start_interval_us":cycle_start_interval_us,"observer_phase_us":{"snapshot":snapshot_us,"ro_query_elapsed":ro_query_elapsed_us,"correlation_and_evidence":active_before_sample_us.saturating_sub(snapshot_us+ro_query_elapsed_us),"active_before_sample":active_before_sample_us},"observer_timing_scope":"RO query elapsed includes harness decode/scheduling, not product SQL/COMMIT timing; resource-process sampling and100ms sleep follow this event"}));
            if tick.is_multiple_of(10) {
                guard_disk(database.parent().unwrap());
                let directory_bytes = run_directory_bytes(database.parent().unwrap());
                assert!(
                    directory_bytes <= MAX_RUN_DIRECTORY_BYTES,
                    "resource STOP: run directory is {directory_bytes} bytes, above {MAX_RUN_DIRECTORY_BYTES}"
                );
                let gateway = process_usage(pid);
                let harness_usage = process_usage(std::process::id());
                let files: Vec<_> = std::fs::read_dir(database.parent().unwrap())
                    .unwrap()
                    .map(|entry| entry.unwrap())
                    .filter(|entry| entry.file_name().to_string_lossy().contains(".sqlite"))
                    .filter_map(|entry| {
                        metadata_bytes_or_gone(entry.metadata())
                            .map(|bytes| json!({"name":entry.file_name(),"logical_bytes":bytes}))
                    })
                    .collect();
                shared.evidence.record("resources",json!({"gateway":gateway,"harness_including_peers_and_observer":harness_usage,"run_directory_bytes":directory_bytes,"run_directory_cap_bytes":MAX_RUN_DIRECTORY_BYTES,"database":"embedded; included in Gateway CPU/RSS","database_files":files,"process_threads":"OS thread count from ps -M when available; does not expose async task count"}));
            }
            tick += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        connection.close().await.unwrap();
    })
}

fn request(product: &Product, channel: &str, op: &str, ttl: i64) -> Value {
    json!({"channel_id":channel,"password":product.synthetic_credential,"op_id":op,"title":op,"body":format!("paired ordinary {op} 中文🙂"),"metadata":{"test":"fixed-normal-mqtt","negative":-42,"fraction":0.125},"ttl":ttl})
}
async fn wait(product: &mut Product, shared: &Shared, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        shared.check();
        assert!(
            product.child.try_wait().unwrap().is_none(),
            "normal Gateway exited"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn submit(product: &Product, shared: &Shared, input: Value, planned_us: u64) {
    let op = input["op_id"].as_str().unwrap().to_owned();
    let bytes = serde_json::to_vec(&input).unwrap();
    shared.evidence.record("http_started",json!({"op_id":op,"planned_offer_us":planned_us,"actual_http_start_us":shared.evidence.us(),"request_bytes":bytes.len()}));
    let response = product
        .http
        .post(format!("{}/message", product.base))
        .bearer_auth(&product.synthetic_credential)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await;
    match response {
        Ok(response) => {
            let status = response.status();
            let result: Value = match response.json().await {
                Ok(value) => value,
                Err(_) => {
                    shared.fail(format!("HTTP response JSON failed for {op}"));
                    return;
                }
            };
            let response_json_complete = shared.evidence.timing.start();
            if !status.is_success() || result["success"] != true {
                shared
                    .evidence
                    .record("http_failed", json!({"op_id":op,"status":status.as_u16()}));
                shared.fail(format!("admission status {} for {op}", status.as_u16()));
                return;
            }
            let message = result["data"]["message_id"]
                .as_str()
                .expect("normal product message id")
                .to_owned();
            let waiting = shared.evidence.timing.start();
            let mut expected = shared.expected.lock().unwrap();
            let holding = shared.evidence.timing.start();
            shared.evidence.timing.record_between(
                &shared.evidence.timing.submit_expected_wait,
                waiting,
                holding,
            );
            let item = expected.get_mut(&op).unwrap();
            bind_expected_identity(item, &message, None);
            assert!(
                shared.accepted.lock().unwrap().insert(op.clone()),
                "duplicate HTTP acceptance for {op}"
            );
            let accepted_record_ready = shared.evidence.timing.start();
            shared.evidence.timing.record_between(
                &shared
                    .evidence
                    .timing
                    .response_json_complete_to_accepted_record,
                response_json_complete,
                accepted_record_ready,
            );
            let mut event = json!({"op_id":op,"message_id":message,"planned_offer_us":planned_us,"status":status.as_u16(),"expected_targets":shared.mode.targets_per_message(),"delivery_complete":false,"semantics":"successful normal product admission response only; completion separately requires positive per-target durable ACK evidence"});
            if let (Some(json_complete), Some(record_ready)) =
                (response_json_complete, accepted_record_ready)
            {
                event["driver_timing"] = json!({
                    "response_json_complete_elapsed_us":shared.evidence.instant_us(json_complete),
                    "accepted_record_ready_elapsed_us":shared.evidence.instant_us(record_ready),
                    "expected_wait_started_elapsed_us":waiting.map(|at|shared.evidence.instant_us(at)),
                    "expected_lock_acquired_elapsed_us":holding.map(|at|shared.evidence.instant_us(at)),
                    "scope":"response JSON complete to accepted-record construction; client processing and expected-lock wait, not additional server latency or this record's file I/O"
                });
            }
            shared
                .evidence
                .timing
                .finish(&shared.evidence.timing.submit_expected_hold, holding);
            drop(expected);
            shared.evidence.record("http_accepted", event);
            if shared.http_pull_peer {
                shared.http_wake.notify_one();
            }
        }
        Err(error) => {
            shared.evidence.record(
                "http_failed",
                json!({"op_id":op,"timeout":error.is_timeout(),"connect":error.is_connect()}),
            );
            shared.fail(format!("HTTP transport failure for {op}"));
        }
    }
}
async fn journey(product: &mut Product, shared: Arc<Shared>, mode: RunMode) {
    let _stop_on_exit = StopGuard(shared.clone());
    let mut devices = Vec::with_capacity(mode.target_devices());
    for index in 0..mode.target_devices() {
        devices.push(product.device(shared.http_pull_peer && index == 0).await);
    }
    let channel = product.subscribe(&devices[0].key, None).await;
    for device in devices.iter().skip(1) {
        assert_eq!(
            channel,
            product.subscribe(&device.key, Some(&channel)).await
        );
    }
    let held_device = mode.load_plan().map_or(1, |plan| plan.disconnect_device);
    let mut peers = Vec::with_capacity(devices.len());
    for (index, device) in devices.iter().enumerate() {
        if device.http_pull {
            peers.push(http_pull_peer(product, device.key.clone(), shared.clone()).await);
            continue;
        }
        let label = if mode.load_plan().is_none() {
            (if index == held_device {
                "mqtt-held"
            } else {
                "mqtt-immediate"
            })
            .to_string()
        } else if index == held_device {
            format!("mqtt-held-{index}")
        } else {
            format!("mqtt-immediate-{index}")
        };
        peers.push(
            peer(
                product,
                device.key.clone(),
                label,
                index,
                index == held_device,
                shared.clone(),
            )
            .await,
        );
    }
    product
        .verify_connected_targets(&devices, &channel, &shared.evidence)
        .await;
    let observer = observer(product, &devices, shared.clone());
    resource_boundary(
        product.child.id(),
        &shared.evidence,
        "http_warm_started",
        false,
    );
    shared.evidence.record(
        "http_warm_started",
        json!({"connections":8,"not_admission_workload":true}),
    );
    let results = stream::iter(0..8)
        .map(|_| async {
            let response = product
                .http
                .get(&product.base)
                .bearer_auth(&product.synthetic_credential)
                .send()
                .await
                .unwrap();
            let status = response.status();
            // Consume the response before the warm phase ends so these real
            // HTTP/1.1 connections can enter the keepalive pool.
            response.bytes().await.unwrap();
            status
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    assert!(results.iter().all(|status| status.is_success()));
    shared.evidence.record(
        "http_warm_complete",
        json!({"successful_responses":results.len(),"idle_seconds":mode.warm_idle().as_secs()}),
    );
    resource_boundary(
        product.child.id(),
        &shared.evidence,
        "http_warm_complete",
        true,
    );
    wait(product, &shared, mode.warm_idle()).await;
    resource_boundary(
        product.child.id(),
        &shared.evidence,
        "warm_idle_complete",
        false,
    );
    let load_start = Instant::now();
    let load_start_us = shared.evidence.us();
    let disconnect_us = load_start_us + mode.hold_delay().as_micros() as u64;
    shared.hold_from_us.store(disconnect_us, Ordering::Relaxed);
    shared.hold_until_us.store(
        disconnect_us + mode.hold_duration().as_micros() as u64,
        Ordering::Relaxed,
    );
    let reconnect_us = disconnect_us + mode.hold_duration().as_micros() as u64;
    shared.evidence.record("load_started",json!({"mode":mode.name(),"planned_offer_start_us":load_start_us,"planned_disconnect_start_us":disconnect_us,"planned_reconnect_us":reconnect_us,"disconnect_device_index":mode.load_plan().map(|plan|plan.disconnect_device)}));
    resource_boundary(product.child.id(), &shared.evidence, "low_started", false);
    let phase_clock = {
        let shared = shared.clone();
        let pid = product.child.id();
        tokio::spawn(async move {
            for (offset, phase) in mode.phase_offsets() {
                tokio::time::sleep_until((load_start + offset).into()).await;
                if shared.stop.load(Ordering::Relaxed) {
                    break;
                }
                resource_boundary(pid, &shared.evidence, phase, false);
            }
        })
    };
    let ttl = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let schedule: Vec<_> = (0..mode.messages())
        .map(|index| {
            let offset = mode.planned_offset(index);
            let op = match mode {
                RunMode::Formal => format!("c12-pair-{index:03}"),
                RunMode::Preflight => format!("c13-preflight-{index:03}"),
                RunMode::DeliveryLoad(_) => format!("delivery-load-{index:05}"),
            };
            let input = request(product, &channel, &op, ttl);
            let body = input["body"].as_str().unwrap();
            assert!(
                shared
                    .expected
                    .lock()
                    .unwrap()
                    .insert(
                        op.clone(),
                        Arc::new(Expected {
                            body_hash: blake3::hash(body.as_bytes()).to_hex().to_string(),
                            body_bytes: body.len(),
                            metadata: input["metadata"].clone(),
                            message_id: None,
                            delivery_id: None
                        })
                    )
                    .is_none(),
                "duplicate planned operation id"
            );
            let planned = load_start_us + offset.as_micros() as u64;
            shared.evidence.record(
                "planned_offer",
                json!({"op_id":op,"planned_offer_us":planned,"stage":mode.stage(index)}),
            );
            (offset, planned, input)
        })
        .collect();
    assert_eq!(
        schedule.len(),
        mode.messages(),
        "nonzero planned cohort required"
    );
    assert!(
        mode.messages() > 0 && mode.targets() > 0,
        "zero-target runs are invalid evidence"
    );
    let last_offset = schedule.last().expect("nonempty schedule").0;
    let product_ref: &Product = product;
    stream::iter(schedule)
        .map(|(offset, planned, input)| {
            let shared = shared.clone();
            async move {
                tokio::time::sleep_until((load_start + offset).into()).await;
                shared.check();
                submit(product_ref, &shared, input, planned).await;
            }
        })
        .buffer_unordered(mode.http_concurrency())
        .collect::<Vec<_>>()
        .await;
    shared.check();
    assert_eq!(
        shared.accepted.lock().unwrap().len(),
        mode.messages(),
        "all planned HTTP offers must be accepted"
    );
    shared.evidence.record("all_http_complete",json!({"mode":mode.name(),"accepted":mode.messages(),"planned":mode.messages(),"fixed_schedule_end_us":load_start_us+last_offset.as_micros() as u64}));
    resource_boundary(
        product.child.id(),
        &shared.evidence,
        "all_http_complete",
        false,
    );
    let drain_deadline = load_start + last_offset + mode.drain_limit();
    shared.evidence.record("drain_deadline",json!({"mode":mode.name(),"last_scheduled_offer_us":load_start_us+last_offset.as_micros() as u64,"deadline_us":load_start_us+last_offset.as_micros() as u64+mode.drain_limit().as_micros() as u64,"semantics":"fixed last scheduled offer plus mode drain limit; never extended by slow HTTP"}));
    while shared.committed.lock().unwrap().len() < mode.targets()
        || shared.body_released.lock().unwrap().len() < mode.messages()
    {
        shared.check();
        if Instant::now() >= drain_deadline {
            let committed = shared.committed.lock().unwrap().len();
            shared.evidence.record("result",json!({"passed":false,"reason":"fixed last-offer drain deadline","mode":mode.name(),"planned_messages":mode.messages(),"planned_targets":mode.targets(),"accepted":shared.accepted.lock().unwrap().len(),"durable_terminal_targets":committed,"unfinished":mode.targets().saturating_sub(committed)}));
        }
        assert!(
            Instant::now() < drain_deadline,
            "{:?} drain deadline; accepted={}, received={}, ACK sent={}, committed={}, bodies released={}",
            mode.drain_limit(),
            shared.accepted.lock().unwrap().len(),
            shared.received.lock().unwrap().len(),
            shared.ack_sent.lock().unwrap().len(),
            shared.committed.lock().unwrap().len(),
            shared.body_released.lock().unwrap().len()
        );
        assert!(product.child.try_wait().unwrap().is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Also guard the zero-iteration case: slow HTTP must not let a cohort
    // already completed after the fixed deadline bypass the drain loop.
    assert!(
        Instant::now() < drain_deadline,
        "completed cohort observed after fixed last-offer+{:?} deadline",
        mode.drain_limit()
    );
    assert_eq!(
        shared.received.lock().unwrap().len(),
        mode.targets(),
        "missing or duplicate MQTT peer receive"
    );
    assert_eq!(
        shared.ack_sent.lock().unwrap().len(),
        mode.targets(),
        "missing or duplicate PUBACK"
    );
    shared.evidence.record("drained",json!({"mode":mode.name(),"accepted":mode.messages(),"received_targets":mode.targets(),"ack_sent_targets":mode.targets(),"durable_terminal_targets":mode.targets(),"body_released":mode.messages()}));
    resource_boundary(
        product.child.id(),
        &shared.evidence,
        "drained_idle_started",
        false,
    );
    wait(product, &shared, mode.post_drain_idle()).await;
    let idle_scope = if mode.is_delivery_load() {
        format!(
            "{}s after drain; active loopback MQTT peers and10Hz observer remain; HTTP peer has no idle polling; normal maintenance can run, but no real Provider pool or energy measurement is established",
            mode.post_drain_idle().as_secs()
        )
    } else {
        "formal mode covers30s pool idle setting; not300s maintenance or all network-client pools"
            .to_string()
    };
    shared.evidence.record("idle_complete",json!({"mode":mode.name(),"seconds":mode.post_drain_idle().as_secs(),"residual_targets":shared.residual_targets.load(Ordering::Relaxed),"covers":idle_scope}));
    resource_boundary(product.child.id(), &shared.evidence, "idle_complete", true);
    shared.request_stop();
    phase_clock.await.unwrap();
    for peer in peers {
        peer.await.unwrap();
    }
    observer.await.unwrap();
    shared.check();
    validate_terminal_counts(
        mode,
        shared.persisted.lock().unwrap().len(),
        shared.received.lock().unwrap().len(),
        shared.ack_sent.lock().unwrap().len(),
        shared.committed.lock().unwrap().len(),
        shared.body_released.lock().unwrap().len(),
        shared.residual_targets.load(Ordering::Relaxed) as usize,
    )
    .unwrap_or_else(|error| panic!("incomplete run evidence: {error}"));
    product.shutdown(&shared.evidence).await;
    let http_targets = if shared.http_pull_peer {
        mode.messages()
    } else {
        0
    };
    shared.evidence.record("result",json!({"passed":true,"mode":mode.name(),"messages":mode.messages(),"targets":mode.targets(),"persisted_messages":shared.persisted.lock().unwrap().len(),"received_targets":shared.received.lock().unwrap().len(),"ack_targets":shared.ack_sent.lock().unwrap().len(),"puback_targets":shared.ack_sent.lock().unwrap().len()-http_targets,"http_v2_ack_targets":http_targets,"http_peer_journaled_targets":shared.journaled.lock().unwrap().len(),"positive_terminal_targets":shared.committed.lock().unwrap().len(),"body_released":shared.body_released.lock().unwrap().len(),"residual_targets":shared.residual_targets.load(Ordering::Relaxed),"unfinished":0,"failed":0,"late_callback_definition":"all raw receives and per-protocol ACK evidence recorded; same-identity QoS1 retry allowed during MQTT disconnect; strict no duplicates in tiny preflight"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated paired evidence; explicit frozen normal binary and fresh directory required"]
async fn normal_sqlite_two_mqtt_fixed_paired_workload() {
    let mode = RunMode::from_environment();
    let timing_setting = std::env::var("C13_DRIVER_TIMING").ok();
    let driver_timing =
        driver_timing_enabled(timing_setting.as_deref()).unwrap_or_else(|error| panic!("{error}"));
    let setting = std::env::var("C13_HTTP_PULL_PEER").ok();
    let backend = std::env::var("C12_LEDGER_KIND").expect("main or ordinary oracle required");
    let http_pull_peer = http_pull_peer_enabled(mode, &backend, setting.as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    let profile_setting = std::env::var_os("C13_GATEWAY_QA_PROFILE");
    let profile_setting = profile_setting.as_ref().map(|setting| {
        setting
            .to_str()
            .expect("C13_GATEWAY_QA_PROFILE must be absent,0 or1")
    });
    let qa_profile = gateway_qa_profile_enabled(mode, &backend, profile_setting)
        .unwrap_or_else(|error| panic!("{error}"));
    let directory = PathBuf::from(
        std::env::var_os("C12_PAIR_DIRECTORY").expect("fresh absolute C12_PAIR_DIRECTORY required"),
    );
    validate_fresh_run_directory(&directory).unwrap_or_else(|error| panic!("{error}"));
    let binary = PathBuf::from(
        std::env::var_os("C12_GATEWAY_BINARY").expect("absolute normal product binary required"),
    );
    validate_executable_binary(&binary).unwrap_or_else(|error| panic!("{error}"));
    let parent = directory.parent().expect("absolute run directory parent");
    std::fs::create_dir_all(parent).unwrap_or_else(|error| {
        panic!(
            "cannot prepare explicit run-directory parent {}: {error}",
            parent.display()
        )
    });
    let canonical_parent = parent
        .canonicalize()
        .expect("canonical run-directory parent");
    let leaf = directory.file_name().expect("fresh run directory leaf");
    let directory = canonical_parent.join(leaf);
    validate_fresh_run_directory(&directory).unwrap_or_else(|error| panic!("{error}"));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let evidence = Arc::new(Evidence {
        start: Instant::now(),
        file: Mutex::new(private_file(&directory.join("journey.jsonl"))),
        timing: DriverTiming::new(driver_timing),
    });
    evidence.record(
        "run_mode",
        json!({"mode":mode.name(),"messages":mode.messages(),"targets":mode.targets(),"formal_schedule_unchanged":true,"driver_timing":driver_timing,"gateway_qa_profile":qa_profile}),
    );
    let shared = Arc::new(Shared {
        evidence: evidence.clone(),
        mode,
        http_pull_peer,
        http_wake: Notify::new(),
        journaled: Mutex::new(BTreeSet::new()),
        stop: AtomicBool::new(false),
        hold_from_us: AtomicU64::new(0),
        hold_until_us: AtomicU64::new(0),
        failure: Mutex::new(None),
        expected: Mutex::new(BTreeMap::new()),
        received: Mutex::new(BTreeSet::new()),
        ack_sent: Mutex::new(BTreeSet::new()),
        committed: Mutex::new(BTreeSet::new()),
        accepted: Mutex::new(BTreeSet::new()),
        body_released: Mutex::new(BTreeSet::new()),
        persisted: Mutex::new(BTreeSet::new()),
        residual_targets: AtomicU64::new(u64::MAX),
    });
    let outcome = tokio::time::timeout(mode.hard_limit(), async {
        let mut product = Product::spawn(directory, &evidence, mode, qa_profile).await;
        journey(&mut product, shared.clone(), mode).await;
    })
    .await;
    if outcome.is_err() {
        shared.request_stop();
        let committed = shared.committed.lock().unwrap().len();
        evidence.record("result",json!({"passed":false,"reason":"fixed mode hard deadline","mode":mode.name(),"accepted":shared.accepted.lock().unwrap().len(),"durable_terminal_targets":committed,"unfinished":mode.targets().saturating_sub(committed)}));
    }
    assert!(
        outcome.is_ok(),
        "fixed mode hard deadline exceeded: {:?}",
        mode.hard_limit()
    );
}
