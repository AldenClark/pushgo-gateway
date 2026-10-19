//! Bounded comparison of unchanged normal Gateway binaries over HTTP/TCP MQTT5.
//! No QA mode, fixture server or Provider substitution is involved. Database
//! reads every 100ms provide visibility upper bounds, not COMMIT timestamps.
use futures_util::{StreamExt, stream};
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
use tokio::task::JoinHandle;

#[path = "support/product_mqtt.rs"]
mod product_mqtt;
use product_mqtt::ProductMqttClient;

const MESSAGES: usize = 136;
const HARD_LIMIT: Duration = Duration::from_secs(100);
const DRAIN_LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Formal,
    Preflight,
}
impl RunMode {
    fn from_environment() -> Self {
        match std::env::var("C13_RUN_MODE") {
            Ok(value) if value == "formal" => Self::Formal,
            Ok(value) if value == "preflight" => Self::Preflight,
            Ok(other) => panic!("unsupported C13_RUN_MODE {other:?}; use formal or preflight"),
            Err(std::env::VarError::NotPresent) => Self::Formal,
            Err(error) => panic!("cannot read C13_RUN_MODE: {error}"),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Formal => "formal",
            Self::Preflight => "preflight",
        }
    }
    fn messages(self) -> usize {
        match self {
            Self::Formal => MESSAGES,
            Self::Preflight => 3,
        }
    }
    fn targets(self) -> usize {
        self.messages() * 2
    }
    fn hard_limit(self) -> Duration {
        match self {
            Self::Formal => HARD_LIMIT,
            Self::Preflight => Duration::from_secs(45),
        }
    }
    fn drain_limit(self) -> Duration {
        match self {
            Self::Formal => DRAIN_LIMIT,
            Self::Preflight => Duration::from_secs(15),
        }
    }
    fn warm_idle(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(10),
            Self::Preflight => Duration::from_secs(1),
        }
    }
    fn post_drain_idle(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(35),
            Self::Preflight => Duration::from_secs(2),
        }
    }
    fn hold_delay(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(6),
            Self::Preflight => Duration::ZERO,
        }
    }
    fn hold_duration(self) -> Duration {
        match self {
            Self::Formal => Duration::from_secs(5),
            Self::Preflight => Duration::from_millis(500),
        }
    }
    fn planned_offset(self, index: usize) -> Duration {
        match self {
            Self::Formal if index < 8 => Duration::from_millis(index as u64 * 500),
            Self::Formal if index < 24 => Duration::from_millis(4000 + (index as u64 - 8) * 125),
            Self::Formal => Duration::from_millis(6000 + (index as u64 - 24) * 10),
            Self::Preflight => Duration::from_millis(index as u64 * 250),
        }
    }
    fn stage(self, index: usize) -> &'static str {
        match self {
            Self::Formal if index < 8 => "low",
            Self::Formal if index < 24 => "ramp",
            Self::Formal => "burst",
            Self::Preflight => "preflight",
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
        ("PUBACKs", pubacks, mode.targets()),
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
}

struct Evidence {
    start: Instant,
    file: Mutex<File>,
}
impl Evidence {
    fn us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
    fn record(&self, kind: &str, data: Value) {
        let row = json!({"elapsed_us":self.us(),"kind":kind,"data":data});
        let mut file = self.file.lock().unwrap();
        serde_json::to_writer(&mut *file, &row).unwrap();
        file.write_all(b"\n").unwrap();
        file.flush().unwrap();
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
struct Shared {
    evidence: Arc<Evidence>,
    mode: RunMode,
    stop: AtomicBool,
    hold_from_us: AtomicU64,
    hold_until_us: AtomicU64,
    failure: Mutex<Option<String>>,
    expected: Mutex<BTreeMap<String, Expected>>,
    received: Mutex<BTreeSet<(String, String)>>,
    ack_sent: Mutex<BTreeSet<(String, String)>>,
    committed: Mutex<BTreeSet<(String, String)>>,
    accepted: Mutex<BTreeSet<String>>,
    body_released: Mutex<BTreeSet<String>>,
    persisted: Mutex<BTreeSet<String>>,
    residual_targets: AtomicU64,
}
impl Shared {
    fn check(&self) {
        let failure = self.failure.lock().unwrap().clone();
        assert!(failure.is_none(), "background failure: {failure:?}");
    }
    fn fail(&self, message: String) {
        self.evidence.record("error", json!({"message":message}));
        *self.failure.lock().unwrap() = Some(message);
    }
    fn verify(&self, peer: &str, device: &str, data: &Value, delivery: &str) -> String {
        let op = data["title"].as_str().expect("message title").to_owned();
        let mut expected = self.expected.lock().unwrap();
        let item = expected.get_mut(&op).expect("fixed offered cohort");
        let body = data["body"].as_str().expect("whole body");
        assert_eq!(body.len(), item.body_bytes);
        assert_eq!(
            blake3::hash(body.as_bytes()).to_hex().to_string(),
            item.body_hash
        );
        assert_eq!(&data["metadata"], &item.metadata);
        let message = data["message_id"].as_str().expect("stable message id");
        if let Some(id) = &item.message_id {
            assert_eq!(id, message);
        }
        if let Some(id) = &item.delivery_id {
            assert_eq!(id, delivery);
        }
        item.message_id = Some(message.into());
        item.delivery_id = Some(delivery.into());
        if !self
            .received
            .lock()
            .unwrap()
            .insert((op.clone(), device.into()))
        {
            self.evidence.record(
                "duplicate_peer_receive",
                json!({"peer":peer,"device_key":device,"op_id":op,"delivery_id":delivery}),
            );
            assert_eq!(
                self.mode,
                RunMode::Formal,
                "unexpected duplicate MQTT receive in tiny preflight for {op} on {device}"
            );
        }
        self.evidence.record("peer_receive",json!({"peer":peer,"device_key":device,"op_id":op,"delivery_id":delivery,"message_id":message,"body_bytes":body.len(),"body_hash":item.body_hash,"metadata":item.metadata}));
        op
    }
    fn ack(&self, peer: &str, device: &str, op: &str, delivery: &str) {
        let first = self
            .ack_sent
            .lock()
            .unwrap()
            .insert((op.into(), device.into()));
        assert!(
            first || self.mode == RunMode::Formal,
            "unexpected duplicate PUBACK in tiny preflight"
        );
        self.evidence.record("ack_sent",json!({"peer":peer,"device_key":device,"op_id":op,"delivery_id":delivery,"semantics":"PUBACK write completed; not durable proof"}));
    }
}
struct BackgroundGuard(Arc<Shared>, &'static str);
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
        self.0.stop.store(true, Ordering::Relaxed);
    }
}
struct Device {
    key: String,
    id: Vec<u8>,
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
    async fn spawn(directory: PathBuf, evidence: &Evidence, mode: RunMode) -> Self {
        guard_disk(&directory);
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
            "private_transports": "TCP MQTT5 only, two real loopback peers",
            "provider": "none; Token Service unused at loopback port 1",
            "qa": false,
            "database": database,
            "http_bind": format!("127.0.0.1:{http_port}"),
            "mqtt_bind": format!("127.0.0.1:{mqtt_port}"),
            "messages": mode.messages(),
            "targets": mode.targets(),
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
        let child = command
            .args([
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
            ])
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
        evidence.record("configuration",json!({"mode":mode.name(),"config_file":config_path,"database_file":database,"log_file":log_path,"binary":product.binary,"binary_blake3":file_hash(&product.binary),"oracle":product.backend,"runtime_profile":"small","private_transports":"TCP MQTT5 only, two real loopback peers","provider":"none; Token Service unused at loopback port 1","qa":false,"messages":mode.messages(),"targets":mode.targets(),"warm_connections":8,"warm_idle_seconds":mode.warm_idle().as_secs(),"post_drain_idle_seconds":mode.post_drain_idle().as_secs(),"hard_limit_seconds":mode.hard_limit().as_secs(),"drain_limit_seconds":mode.drain_limit().as_secs(),"ack_hold_seconds":mode.hold_duration().as_secs_f64(),"observer_interval_ms":100,"http_concurrency_max":8,"formal_schedule":{"messages":[8,16,112],"rates_per_second":[2,8,100]},"database_process":"embedded SQLite shares Gateway process CPU/RSS","commit_oracle":"100ms committed reads are visibility upper bounds; old requires actual acked outbox rows"}));
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
    async fn device(&self) -> Device {
        let key = self
            .post("/device/register", json!({"platform":"mqtt"}))
            .await["data"]["device_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let route = self
            .post(
                "/channel/device",
                json!({"device_key":key,"platform":"mqtt","channel_type":"private"}),
            )
            .await;
        assert_eq!(route["data"]["device_key"].as_str(), Some(key.as_str()));
        assert_eq!(route["data"]["channel_type"], "private");
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
        Device { key, id }
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
        devices: &[Device; 2],
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
        let rows=sqlx::query("SELECT d.device_key,d.device_id,d.platform,d.channel_type FROM channel_subscriptions s JOIN devices d ON d.device_id=s.device_id WHERE s.channel_id=? AND s.status='active' AND d.channel_type='private' AND d.route_updated_at IS NOT NULL AND s.created_at<=? ORDER BY d.device_key").bind(&channel_id[..]).bind(now).fetch_all(&mut connection).await.unwrap();
        assert_eq!(
            rows.len(),
            2,
            "two actual canonical selected recipients after CONNECT"
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
            assert_eq!(row.get::<String, _>("platform"), "mqtt");
            assert_eq!(row.get::<String, _>("channel_type"), "private");
        }
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id=? AND status='active'",
        )
        .bind(&channel_id[..])
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(active, 2);
        if self.backend == "ordinary" {
            let selected:i64=sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_subscriptions s JOIN ordinary_device_routes d ON d.device_key=s.device_key WHERE s.channel_id=lower(hex(?)) AND s.created_at<=? AND d.retired_at IS NULL AND d.channel_type='private' AND d.platform='mqtt'").bind(&channel_id[..]).bind(now).fetch_one(&mut connection).await.unwrap();
            assert_eq!(
                selected, 2,
                "two recipients in C's canonical control projection"
            );
        }
        connection.close().await.unwrap();
        evidence.record("control_preflight",json!({"passed":true,"platform":"mqtt","original_device_keys_preserved":2,"original_device_ids_preserved":2,"canonical_active_subscriptions":active,"selected_targets":rows.len(),"scope":"before any measured offer; admission success is never treated as delivery completion"}));
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
    label: &'static str,
    held: bool,
    shared: Arc<Shared>,
) -> JoinHandle<()> {
    let mut mqtt =
        ProductMqttClient::connect(product.mqtt_port, &device, &product.synthetic_credential).await;
    shared
        .evidence
        .record("peer_connected", json!({"peer":label,"device_key":device}));
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), label);
        let mut pending = BTreeMap::<u16, (String, String)>::new();
        let mut last_ping = Instant::now();
        while !shared.stop.load(Ordering::Relaxed) {
            if last_ping.elapsed() >= Duration::from_secs(5) {
                mqtt.ping().await;
                last_ping = Instant::now();
            }
            let now = shared.evidence.us();
            let holding = held
                && now >= shared.hold_from_us.load(Ordering::Relaxed)
                && now < shared.hold_until_us.load(Ordering::Relaxed);
            if !holding {
                for (packet, (op, delivery)) in std::mem::take(&mut pending) {
                    mqtt.acknowledge(packet).await;
                    shared.ack(label, &device, &op, &delivery);
                }
            }
            let Some(packet) = mqtt.receive(Duration::from_millis(50)).await else {
                continue;
            };
            match packet {
                mqttbytes::v5::Packet::Publish(publish) => {
                    let envelope: Value = serde_json::from_slice(&publish.payload).unwrap();
                    let delivery = envelope["delivery_id"].as_str().unwrap().to_owned();
                    let op = shared.verify(label, &device, &envelope["data"], &delivery);
                    pending.insert(publish.pkid, (op, delivery));
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
    json!({"pid":pid,"cpu_seconds":cpu,"rss_kib":parts[1].parse::<u64>().unwrap()})
}
fn resource_boundary(pid: u32, evidence: &Evidence, phase: &str, sockets: bool) {
    let mut data = json!({"phase":phase,"gateway":process_usage(pid),"harness_including_peers_and_observer":process_usage(std::process::id())});
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
fn observer(product: &Product, devices: &[Device; 2], shared: Arc<Shared>) -> JoinHandle<()> {
    let database = product.directory.join("gateway.sqlite");
    let backend = product.backend.clone();
    let pid = product.child.id();
    let keys = devices.each_ref().map(|d| d.key.clone());
    let ids = devices.each_ref().map(|d| d.id.clone());
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), "database observer");
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
        while !shared.stop.load(Ordering::Relaxed) {
            let expected = shared.expected.lock().unwrap().clone();
            let ack_sent = shared.ack_sent.lock().unwrap().clone();
            let received = shared.received.lock().unwrap().clone();
            let accepted = shared.accepted.lock().unwrap().clone();
            let mut terminal = BTreeSet::new();
            let mut state_counts = BTreeMap::<String, usize>::new();
            let mut oldest: Option<i64> = None;
            let payloads;
            let expired;
            let now = chrono::Utc::now().timestamp_millis();
            if backend == "main" {
                // Old MQTT PUBACK writes an actual acked row. Empty/nonexistent
                // outboxes cannot make a target complete in this oracle.
                let rows=sqlx::query("SELECT device_id,delivery_id,status,created_at,acked_at FROM private_outbox ORDER BY delivery_id,device_id LIMIT 273").fetch_all(&mut connection).await.unwrap();
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
                let rows =
                    sqlx::query("SELECT delivery_id,expires_at FROM private_payloads LIMIT 137")
                        .fetch_all(&mut connection)
                        .await
                        .unwrap();
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
                for (op, item) in &expected {
                    if let Some(delivery) = &item.delivery_id
                        && !body_ids.contains(delivery)
                        && terminal.iter().filter(|(id, _)| id == op).count() == 2
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
                let messages=sqlx::query("SELECT op_id,message_id,delivery_id,payload_bytes,expires_at FROM ordinary_messages LIMIT 137").fetch_all(&mut connection).await.unwrap();
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
                            shared.persisted.lock().unwrap().insert(op);
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
                let rows=sqlx::query("SELECT m.op_id,t.device_key,t.state,t.accepted_at FROM ordinary_targets t JOIN ordinary_messages m ON m.delivery_id=t.delivery_id LIMIT 273").fetch_all(&mut connection).await.unwrap();
                assert!(rows.len() <= shared.mode.targets());
                let mut existing = BTreeSet::new();
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
                    assert!(existing.insert((op, key)), "duplicate persisted target row");
                    let accepted: i64 = row.get("accepted_at");
                    oldest = Some(oldest.map_or(accepted, |old| old.min(accepted)));
                }
                for pair in &ack_sent {
                    if message_ids.contains(&pair.0)
                        && received.contains(pair)
                        && !existing.contains(pair)
                    {
                        terminal.insert(pair.clone());
                    }
                }
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
                    } else if terminal.iter().filter(|(id, _)| id == &op).count() == 2
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
                    shared.evidence.record("ack_commit_visible_upper_bound",json!({"op_id":pair.0,"device_key":pair.1,"oracle":backend,"semantics":"100ms polling plus scheduling/query delay; actual PUBACK plus durable backend terminal state"}));
                }
            }
            let pending: usize = state_counts
                .iter()
                .filter(|(state, _)| state.as_str() != "acked")
                .map(|(_, count)| *count)
                .sum();
            shared
                .residual_targets
                .store(pending as u64, Ordering::Relaxed);
            shared.evidence.record("database_sample",json!({"states":state_counts,"pending_targets":pending,"payload_count":payloads,"expired_payload_count":expired,"oldest_pending_age_ms":oldest.map(|ts|(now-ts).max(0)),"durable_targets_observed":shared.committed.lock().unwrap().len()}));
            if tick.is_multiple_of(10) {
                guard_disk(database.parent().unwrap());
                let files:Vec<_>=std::fs::read_dir(database.parent().unwrap()).unwrap().map(|entry|entry.unwrap()).filter(|entry|entry.file_name().to_string_lossy().contains(".sqlite")).map(|entry|json!({"name":entry.file_name(),"logical_bytes":entry.metadata().unwrap().len()})).collect();
                shared.evidence.record("resources",json!({"gateway":process_usage(pid),"harness_including_peers_and_observer":process_usage(std::process::id()),"database":"embedded; included in Gateway CPU/RSS","database_files":files}));
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
            let mut expected = shared.expected.lock().unwrap();
            let item = expected.get_mut(&op).unwrap();
            if let Some(previous) = &item.message_id {
                assert_eq!(previous, &message);
            }
            item.message_id = Some(message.clone());
            assert!(
                shared.accepted.lock().unwrap().insert(op.clone()),
                "duplicate HTTP acceptance for {op}"
            );
            shared.evidence.record("http_accepted",json!({"op_id":op,"message_id":message,"planned_offer_us":planned_us,"status":status.as_u16(),"expected_targets":2,"delivery_complete":false,"semantics":"successful normal product admission response only; completion separately requires two positive MQTT durable ACK oracles"}));
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
    let one = product.device().await;
    let two = product.device().await;
    let channel = product.subscribe(&one.key, None).await;
    assert_eq!(channel, product.subscribe(&two.key, Some(&channel)).await);
    let devices = [one, two];
    let peer_one = peer(
        product,
        devices[0].key.clone(),
        "mqtt-immediate",
        false,
        shared.clone(),
    )
    .await;
    let peer_two = peer(
        product,
        devices[1].key.clone(),
        "mqtt-held",
        true,
        shared.clone(),
    )
    .await;
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
    let burst_us = load_start_us + mode.hold_delay().as_micros() as u64;
    shared.hold_from_us.store(burst_us, Ordering::Relaxed);
    shared.hold_until_us.store(
        burst_us + mode.hold_duration().as_micros() as u64,
        Ordering::Relaxed,
    );
    let hold_until_us = burst_us + mode.hold_duration().as_micros() as u64;
    shared.evidence.record("load_started",json!({"mode":mode.name(),"planned_offer_start_us":load_start_us,"burst_start_us":burst_us,"held_ack_release_us":hold_until_us}));
    resource_boundary(product.child.id(), &shared.evidence, "low_started", false);
    let phase_clock = {
        let shared = shared.clone();
        let pid = product.child.id();
        tokio::spawn(async move {
            for (offset, phase) in [
                (Duration::from_secs(4), "ramp_started"),
                (mode.hold_delay(), "burst_started"),
                (mode.hold_delay() + mode.hold_duration(), "held_ack_release"),
            ] {
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
                        Expected {
                            body_hash: blake3::hash(body.as_bytes()).to_hex().to_string(),
                            body_bytes: body.len(),
                            metadata: input["metadata"].clone(),
                            message_id: None,
                            delivery_id: None
                        }
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
        .buffer_unordered(8)
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
        "completed cohort observed after fixed last-offer+30s deadline"
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
    shared.evidence.record("idle_complete",json!({"mode":mode.name(),"seconds":mode.post_drain_idle().as_secs(),"residual_targets":shared.residual_targets.load(Ordering::Relaxed),"covers":"formal mode covers 30s pool idle setting; not 300s maintenance or all network-client pools"}));
    resource_boundary(product.child.id(), &shared.evidence, "idle_complete", true);
    shared.stop.store(true, Ordering::Relaxed);
    phase_clock.await.unwrap();
    peer_one.await.unwrap();
    peer_two.await.unwrap();
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
    shared.evidence.record("result",json!({"passed":true,"mode":mode.name(),"messages":mode.messages(),"targets":mode.targets(),"persisted_messages":shared.persisted.lock().unwrap().len(),"received_targets":shared.received.lock().unwrap().len(),"puback_targets":shared.ack_sent.lock().unwrap().len(),"positive_terminal_targets":shared.committed.lock().unwrap().len(),"body_released":shared.body_released.lock().unwrap().len(),"residual_targets":shared.residual_targets.load(Ordering::Relaxed),"unfinished":0,"failed":0,"late_callback_definition":"all raw receives and PUBACK sends recorded; same-identity QoS1 retry allowed during formal ACK hold, strict no duplicates in tiny preflight"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated paired evidence; explicit frozen normal binary and fresh directory required"]
async fn normal_sqlite_two_mqtt_fixed_paired_workload() {
    let mode = RunMode::from_environment();
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
    });
    evidence.record(
        "run_mode",
        json!({"mode":mode.name(),"messages":mode.messages(),"targets":mode.targets(),"formal_schedule_unchanged":true}),
    );
    let shared = Arc::new(Shared {
        evidence: evidence.clone(),
        mode,
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
        let mut product = Product::spawn(directory, &evidence, mode).await;
        journey(&mut product, shared.clone(), mode).await;
    })
    .await;
    if outcome.is_err() {
        shared.stop.store(true, Ordering::Relaxed);
        let committed = shared.committed.lock().unwrap().len();
        evidence.record("result",json!({"passed":false,"reason":"fixed mode hard deadline","mode":mode.name(),"accepted":shared.accepted.lock().unwrap().len(),"durable_terminal_targets":committed,"unfinished":mode.targets().saturating_sub(committed)}));
    }
    assert!(
        outcome.is_ok(),
        "fixed mode hard deadline exceeded: {:?}",
        mode.hard_limit()
    );
}
