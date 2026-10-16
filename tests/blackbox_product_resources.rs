#![cfg(feature = "qa")]
//! Normal-product, fixed-input same-process resource journey. Only Provider IO
//! is replaced. Private WS and MQTT peers do not claim native-client coverage.
use futures_util::{SinkExt, StreamExt, stream};
use pushgo_warp_profile::{PrivatePayloadEnvelope, PushgoWireProfile};
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{Connection, Row, SqliteConnection};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Write,
    net::TcpListener,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use warp_link::warp_link_core::{AckMsg, AckStatus, DecodedServerFrame, HelloCtx, WireProfile};

#[path = "support/product_mqtt.rs"]
mod product_mqtt;
#[path = "support/product_ordinary_ledger.rs"]
mod product_ordinary_ledger;
use product_mqtt::ProductMqttClient;
use product_ordinary_ledger::{ProductLedger, guard_disk};

const SETTLE_LIMIT: Duration = Duration::from_secs(45);
const INPUTS_LIMIT: usize = 213;

struct Evidence {
    started: Instant,
    phase: Mutex<String>,
    file: Mutex<File>,
}
impl Evidence {
    fn micros(&self) -> u64 {
        self.started.elapsed().as_micros() as u64
    }
    fn record(&self, kind: &str, data: Value) {
        let row = json!({"elapsed_us":self.micros(),"phase":*self.phase.lock().unwrap(),"kind":kind,"data":data});
        let mut file = self.file.lock().unwrap();
        serde_json::to_writer(&mut *file, &row).unwrap();
        file.write_all(b"\n").unwrap();
        file.flush().unwrap();
    }
    fn phase(&self, name: &str) {
        *self.phase.lock().unwrap() = name.into();
        self.record("phase", json!({"name":name}));
        eprintln!("C11_PHASE {name}");
    }
}
#[derive(Clone)]
struct Expected {
    body_hash: String,
    body_bytes: usize,
    metadata: Value,
    message_id: Option<String>,
}
struct Shared {
    evidence: Arc<Evidence>,
    stop: AtomicBool,
    hold_ack: AtomicBool,
    failure: Mutex<Option<String>>,
    expected: Mutex<BTreeMap<String, Expected>>,
    peer_ids: Mutex<BTreeMap<(String, String), String>>,
    ack_sent: Mutex<BTreeSet<(String, String)>>,
    provider_visible: Mutex<BTreeMap<String, String>>,
    ack_visible: Mutex<BTreeSet<(String, String)>>,
    released: Mutex<BTreeSet<String>>,
}
impl Shared {
    fn check(&self) {
        let failure = self.failure.lock().unwrap().clone();
        assert!(
            failure.is_none(),
            "background peer/observer failed: {failure:?}"
        );
    }
    fn verify(&self, peer: &str, device: &str, delivery: &str, data: &Value) -> String {
        let op = data["title"].as_str().unwrap().to_owned();
        let expected = self
            .expected
            .lock()
            .unwrap()
            .get(&op)
            .cloned()
            .expect("offered synthetic input");
        let body = data["body"].as_str().unwrap();
        assert_eq!(body.len(), expected.body_bytes);
        assert_eq!(
            blake3::hash(body.as_bytes()).to_hex().to_string(),
            expected.body_hash
        );
        let metadata = match &data["metadata"] {
            Value::String(raw) => serde_json::from_str(raw).unwrap(),
            value => value.clone(),
        };
        assert_eq!(metadata, expected.metadata);
        let message = data["message_id"].as_str().unwrap();
        if let Some(expected_id) = &expected.message_id {
            assert_eq!(message, expected_id);
        }
        if let Some(previous) = self
            .peer_ids
            .lock()
            .unwrap()
            .insert((op.clone(), device.into()), message.into())
        {
            assert_eq!(previous, message);
        }
        self.evidence.record("peer_receive",json!({"peer":peer,"op_id":op,"delivery_id":delivery,"message_id":message,"body_bytes":body.len(),"body_hash":expected.body_hash}));
        op
    }
    fn ack(&self, peer: &str, op: &str, device: &str, delivery: &str) {
        self.ack_sent
            .lock()
            .unwrap()
            .insert((op.into(), device.into()));
        self.evidence.record("ack_sent",json!({"peer":peer,"op_id":op,"device_key":device,"delivery_id":delivery,"semantics":"send completion; not durable ACK proof"}));
    }
}
struct BackgroundGuard(Arc<Shared>, &'static str);
impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        if !self.0.stop.load(Ordering::Relaxed) {
            *self.0.failure.lock().unwrap() =
                Some(format!("{} ended before its owner stopped it", self.1));
        }
    }
}
struct Product {
    child: Child,
    directory: PathBuf,
    base: String,
    synthetic_credential: String,
    http: Client,
    mqtt_port: u16,
    ledger: ProductLedger,
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
impl Product {
    async fn spawn(directory: PathBuf, evidence: &Evidence) -> Self {
        guard_disk(&directory);
        let scenario = directory.join("providers");
        std::fs::create_dir(&scenario).unwrap();
        std::fs::set_permissions(&scenario, std::fs::Permissions::from_mode(0o700)).unwrap();
        private_file(&scenario.join("scenario.json"))
            .write_all(br#"{"synthetic_only":true,"status":202,"delay_ms":1000}"#)
            .unwrap();
        let http_port = port();
        let mqtt_port = port();
        let base = format!("http://127.0.0.1:{http_port}");
        let synthetic_credential = std::env::var("C11_TEST_SECRET").expect(
            "process-local synthetic C11_TEST_SECRET required; never use production credentials",
        );
        assert!(synthetic_credential.len() >= 24);
        let binary = std::env::var_os("C11_GATEWAY_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pushgo-gateway")));
        assert!(
            binary.is_absolute() && binary.is_file(),
            "normal Gateway binary must be an absolute existing file"
        );
        let ledger = ProductLedger::sqlite(&directory.join("gateway.sqlite"));
        let log = private_file(&directory.join("gateway.log"));
        let args = vec![
            "--http-addr".to_owned(),
            format!("127.0.0.1:{http_port}"),
            "--db-url".into(),
            ledger.url().into(),
            "--runtime-profile".into(),
            "small".into(),
            "--token".into(),
            synthetic_credential.clone(),
            "--token-service-url".into(),
            "http://127.0.0.1:1".into(),
            "--private-transports".into(),
            "wss,mqtt".into(),
            "--mqtt-bind".into(),
            format!("127.0.0.1:{mqtt_port}"),
            "--mqtt-port".into(),
            mqtt_port.to_string(),
            "--qa-provider-fixture-dir".into(),
            scenario.to_string_lossy().into_owned(),
            "--qa-resource-observation-dir".into(),
            directory
                .join("observations")
                .to_string_lossy()
                .into_owned(),
            "--observability-log-level".into(),
            "info".into(),
        ];
        let mut command = Command::new(&binary);
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("PUSHGO_")) {
            command.env_remove(key);
        }
        let child = command
            .args(&args)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let product = Self {
            child,
            directory,
            base,
            synthetic_credential,
            mqtt_port,
            ledger,
            http: Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
        };
        evidence.record("configuration",json!({"binary":binary,"profile":"small","provider_delay_ms":1000,"provider_budget":32,"transports":"loopback WS upgrade and TCP MQTT5; no native-client or TLS-WSS claim","database":"SQLite embedded in Gateway CPU/RSS","initial_idle_seconds":35,"post_cycle_idle_seconds":330,"maintenance_seconds":300,"pool_idle_seconds":30,"http_concurrency_limit":8,"input_limit":INPUTS_LIMIT,"commit_observation":"independent100ms SQLite reads give visibility upper bounds, not exact timestamps"}));
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
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
            assert!(
                Instant::now() < deadline,
                "normal product readiness timeout"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
        let result: Value = response.json().await.unwrap();
        assert_eq!(status, 200, "{path}: {result}");
        result
    }
    async fn device(&self, platform: &str, provider: Option<&str>) -> String {
        let key = self
            .post("/device/register", json!({"platform":platform}))
            .await["data"]["device_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut input = json!({"device_key":key,"platform":platform,"channel_type":provider.unwrap_or("private")});
        if provider.is_some() {
            input["provider_token"] = json!(format!(
                "c11-synthetic-target-{}",
                self.synthetic_credential
            ));
        }
        self.post("/channel/device", input).await;
        key
    }
    async fn subscribe(&self, key: &str, channel: Option<&str>, name: &str) -> String {
        let input = if let Some(channel) = channel {
            json!({"device_key":key,"channel_id":channel,"password":self.synthetic_credential})
        } else {
            json!({"device_key":key,"channel_name":name,"password":self.synthetic_credential})
        };
        self.post("/channel/subscribe", input).await["data"]["channel_id"]
            .as_str()
            .unwrap()
            .into()
    }
    async fn shutdown(&mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline);
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

async fn private_peer(product: &Product, device: String, shared: Arc<Shared>) -> JoinHandle<()> {
    let profile = Arc::new(PushgoWireProfile::new());
    let mut request = format!(
        "{}/private/ws",
        product.base.replacen("http://", "ws://", 1)
    )
    .into_client_request()
    .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "pushgo-private.v1".parse().unwrap(),
    );
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", product.synthetic_credential)
            .parse()
            .unwrap(),
    );
    let (mut ws, _) = connect_async(request).await.unwrap();
    let hello = profile
        .encode_client_hello(&HelloCtx {
            identity: device.clone(),
            auth_token: Some(product.synthetic_credential.clone()),
            resume_token: None,
            last_acked_seq: None,
            supported_wire_versions: Vec::new(),
            supported_payload_versions: Vec::new(),
            perf_tier: None,
            app_state: None,
            metadata: Default::default(),
        })
        .unwrap();
    ws.send(Message::Binary(hello.to_vec().into()))
        .await
        .unwrap();
    let welcome = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Binary(frame) = welcome else {
        panic!("expected binary WELCOME")
    };
    let DecodedServerFrame::Welcome(welcome) = profile.decode_server_frame(&frame).unwrap() else {
        panic!("expected WELCOME")
    };
    assert_eq!(welcome.max_frame_bytes, 131072);
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), "Private WS peer");
        let mut pending = BTreeMap::<String, (Option<u64>, String)>::new();
        loop {
            if !shared.hold_ack.load(Ordering::Relaxed) {
                for (id, (seq, op)) in std::mem::take(&mut pending) {
                    let ack = profile
                        .encode_client_ack(&AckMsg {
                            seq,
                            id: id.clone(),
                            status: AckStatus::Ok,
                        })
                        .unwrap();
                    ws.send(Message::Binary(ack.to_vec().into())).await.unwrap();
                    shared.ack("private-ws", &op, &device, &id);
                }
            }
            if shared.stop.load(Ordering::Relaxed) {
                ws.close(None).await.unwrap();
                break;
            }
            let next = match tokio::time::timeout(Duration::from_millis(100), ws.next()).await {
                Err(_) => continue,
                Ok(next) => next.expect("Private stays connected").unwrap(),
            };
            match next {
                Message::Binary(frame) => {
                    assert!(frame.len() <= 131072);
                    match profile.decode_server_frame(&frame).unwrap() {
                        DecodedServerFrame::Deliver(msg) => {
                            let envelope: PrivatePayloadEnvelope =
                                postcard::from_bytes(&msg.payload).unwrap();
                            let data = serde_json::to_value(envelope.data).unwrap();
                            let op = shared.verify("private-ws", &device, &msg.id, &data);
                            pending.insert(msg.id, (msg.seq, op));
                            assert!(pending.len() <= 128);
                        }
                        DecodedServerFrame::Ping => ws
                            .send(Message::Binary(
                                profile.encode_client_pong().to_vec().into(),
                            ))
                            .await
                            .unwrap(),
                        DecodedServerFrame::Pong | DecodedServerFrame::Unknown => {}
                        other => panic!("unexpected Private frame: {other:?}"),
                    }
                }
                Message::Ping(data) => ws.send(Message::Pong(data)).await.unwrap(),
                Message::Pong(_) => {}
                other => panic!("unexpected WS message: {other:?}"),
            }
        }
    })
}
async fn mqtt_peer(product: &Product, device: String, shared: Arc<Shared>) -> JoinHandle<()> {
    let mut mqtt =
        ProductMqttClient::connect(product.mqtt_port, &device, &product.synthetic_credential).await;
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), "MQTT peer");
        let mut last_ping = Instant::now();
        while !shared.stop.load(Ordering::Relaxed) {
            if last_ping.elapsed() >= Duration::from_secs(5) {
                mqtt.ping().await;
                last_ping = Instant::now();
            }
            let Some(packet) = mqtt.receive(Duration::from_millis(100)).await else {
                continue;
            };
            match packet {
                mqttbytes::v5::Packet::Publish(publish) => {
                    let envelope: Value = serde_json::from_slice(&publish.payload).unwrap();
                    let delivery = envelope["delivery_id"].as_str().unwrap();
                    let op = shared.verify("mqtt", &device, delivery, &envelope["data"]);
                    mqtt.acknowledge(publish.pkid).await;
                    shared.ack("mqtt", &op, &device, delivery);
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
    let raw = String::from_utf8(output.stdout).unwrap();
    let parts: Vec<_> = raw.split_whitespace().collect();
    assert_eq!(parts.len(), 2);
    let cpu = parts[0]
        .split(':')
        .rev()
        .enumerate()
        .map(|(i, v)| v.parse::<f64>().unwrap() * 60_f64.powi(i as i32))
        .sum::<f64>();
    json!({"pid":pid,"cpu_seconds":cpu,"rss_kib":parts[1].parse::<u64>().unwrap()})
}
fn database_observer(product: &Product, shared: Arc<Shared>) -> JoinHandle<()> {
    let database = product.directory.join("gateway.sqlite");
    let pid = product.child.id();
    tokio::spawn(async move {
        let _guard = BackgroundGuard(shared.clone(), "SQLite observer");
        let url = format!("sqlite://{}?mode=ro", database.display());
        let mut db = SqliteConnection::connect(&url).await.unwrap();
        let mut tick = 0_u64;
        while !shared.stop.load(Ordering::Relaxed) {
            let rows=sqlx::query("SELECT m.op_id,m.delivery_id,m.payload_bytes,t.device_key,t.delivery_mode,t.state,t.private_claim FROM ordinary_messages m LEFT JOIN ordinary_targets t ON t.delivery_id=m.delivery_id ORDER BY m.op_id,t.device_key").fetch_all(&mut db).await.unwrap();
            assert!(
                rows.len() <= INPUTS_LIMIT * 3,
                "observer cohort is fixed and bounded"
            );
            let mut seen = BTreeSet::new();
            let mut messages = BTreeMap::new();
            let mut states = BTreeMap::<String, usize>::new();
            let mut claims = 0;
            let mut waiting = 0;
            let mut running = 0;
            for row in rows {
                let op: String = row.get("op_id");
                let delivery: String = row.get("delivery_id");
                let bytes: i64 = row.get("payload_bytes");
                messages.insert(op.clone(), bytes);
                let Some(device) = row.get::<Option<String>, _>("device_key") else {
                    continue;
                };
                seen.insert((op.clone(), device.clone()));
                let state: String = row.get("state");
                *states.entry(state.clone()).or_default() += 1;
                if state == "running" {
                    running += 1;
                }
                if row.get::<String, _>("delivery_mode") == "private" {
                    if row.get::<Option<String>, _>("private_claim").is_some() {
                        claims += 1;
                    } else {
                        waiting += 1;
                    }
                } else if state == "provider_accepted"
                    && shared
                        .provider_visible
                        .lock()
                        .unwrap()
                        .insert(op.clone(), delivery.clone())
                        .is_none()
                {
                    shared.evidence.record("provider_receipt_commit_visible_upper_bound",json!({"op_id":op,"device_key":device,"delivery_id":delivery,"semantics":"independent committed read,100ms polling plus scheduler/query delay"}));
                }
            }
            for (op, device) in shared.ack_sent.lock().unwrap().iter() {
                if messages.contains_key(op)
                    && !seen.contains(&(op.clone(), device.clone()))
                    && shared
                        .ack_visible
                        .lock()
                        .unwrap()
                        .insert((op.clone(), device.clone()))
                {
                    shared.evidence.record("ack_commit_visible_upper_bound",json!({"op_id":op,"device_key":device,"semantics":"successful protocol ACK sent and frozen target absent; no route retirement/expiry in acknowledged cohort"}));
                }
            }
            for (op, bytes) in &messages {
                if *bytes == 0 && shared.released.lock().unwrap().insert(op.clone()) {
                    shared.evidence.record(
                        "body_release_commit_visible_upper_bound",
                        json!({"op_id":op}),
                    );
                }
            }
            let usage:(i64,i64,i64,i64)=sqlx::query_as("SELECT messages,targets,bytes,private_pending FROM ordinary_ledger_usage WHERE singleton=1").fetch_one(&mut db).await.unwrap();
            shared.evidence.record("database_sample",json!({"states":states,"running_targets":running,"private_issued_claims":claims,"private_unclaimed_waiting":waiting,"identity_count":messages.len(),"usage":{"messages":usage.0,"targets":usage.1,"bytes":usage.2,"private_pending":usage.3}}));
            if tick % 10 == 0 {
                let files:Vec<_>=std::fs::read_dir(database.parent().unwrap()).unwrap().map(|x|x.unwrap()).filter(|x|x.file_name().to_string_lossy().contains(".sqlite")).map(|x|json!({"name":x.file_name(),"logical_bytes":x.metadata().unwrap().len()})).collect();
                shared.evidence.record("resources",json!({"gateway":process_usage(pid),"harness_including_peers_observer":process_usage(std::process::id()),"database_process":"not separate: embedded SQLite","database_files":files}));
            }
            if tick % 100 == 0 {
                guard_disk(database.parent().unwrap());
            }
            tick += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        db.close().await.unwrap();
    })
}
async fn wait(product: &mut Product, shared: &Shared, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        shared.check();
        assert!(
            product.child.try_wait().unwrap().is_none(),
            "normal Gateway exited"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
fn request(product: &Product, channel: &str, op: &str, large: bool) -> Value {
    let mut input = json!({"channel_id":channel,"password":product.synthetic_credential,"op_id":op,"title":op,"body":format!("ordinary resource input {op}"),"metadata":{"unicode":"中文🙂","negative":-42,"fraction":0.125},"ttl":chrono::Utc::now().timestamp_millis()+3_600_000});
    if large {
        input["body"] = json!("中文🙂\\\"\n");
        let used = serde_json::to_vec(&input).unwrap().len();
        input["body"] = json!(format!(
            "{}{}",
            input["body"].as_str().unwrap(),
            "x".repeat(49152 - used)
        ));
        assert_eq!(serde_json::to_vec(&input).unwrap().len(), 49152);
    }
    input
}
async fn submit(product: &Product, shared: &Shared, input: Value) -> String {
    let op = input["op_id"].as_str().unwrap().to_owned();
    let body = input["body"].as_str().unwrap();
    let offer = shared.evidence.micros();
    {
        let mut expected = shared.expected.lock().unwrap();
        assert!(expected.len() < INPUTS_LIMIT);
        assert!(
            expected
                .insert(
                    op.clone(),
                    Expected {
                        body_hash: blake3::hash(body.as_bytes()).to_hex().to_string(),
                        body_bytes: body.len(),
                        metadata: input["metadata"].clone(),
                        message_id: None
                    }
                )
                .is_none()
        );
    }
    let bytes = serde_json::to_vec(&input).unwrap();
    shared.evidence.record(
        "offer",
        json!({"op_id":op,"request_bytes":bytes.len(),"offer_us":offer}),
    );
    shared.evidence.record("http_started", json!({"op_id":op}));
    let response = product
        .http
        .post(format!("{}/message", product.base))
        .bearer_auth(&product.synthetic_credential)
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let result: Value = response.json().await.unwrap();
    assert_eq!(status, 200, "ordinary admission: {result}");
    let message = result["data"]["message_id"].as_str().unwrap().to_owned();
    shared
        .expected
        .lock()
        .unwrap()
        .get_mut(&op)
        .unwrap()
        .message_id = Some(message.clone());
    shared.evidence.record("http_accepted",json!({"op_id":op,"message_id":message,"offer_to_response_us":shared.evidence.micros()-offer,"semantics":"normal successful response follows admission COMMIT; response-time upper bound"}));
    op
}
async fn paced(
    product: &Product,
    shared: &Shared,
    channel: &str,
    label: &str,
    count: usize,
    rate: u32,
) -> Vec<String> {
    let mut ops = Vec::new();
    let start = Instant::now();
    for index in 0..count {
        tokio::time::sleep_until(
            (start + Duration::from_secs_f64(index as f64 / rate as f64)).into(),
        )
        .await;
        shared.check();
        let op = format!("c11-{label}-{index:03}");
        ops.push(submit(product, shared, request(product, channel, &op, false)).await);
    }
    ops
}
async fn burst(
    product: &Product,
    shared: &Shared,
    channel: &str,
    label: &str,
    count: usize,
) -> Vec<String> {
    stream::iter(0..count)
        .map(|index| async move {
            shared.check();
            let op = format!("c11-{label}-{index:03}");
            submit(product, shared, request(product, channel, &op, false)).await
        })
        .buffer_unordered(8)
        .collect()
        .await
}
async fn drain(product: &mut Product, shared: &Shared, provider: &str, ops: &[String]) {
    let deadline = Instant::now() + SETTLE_LIMIT;
    loop {
        shared.check();
        if ops
            .iter()
            .all(|op| shared.provider_visible.lock().unwrap().contains_key(op))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixed Provider COMMIT visibility deadline exceeded"
        );
        wait(product, shared, Duration::from_millis(100)).await;
    }
    shared.evidence.record("all_provider_receipts_visible",json!({"count":ops.len(),"semantics":"sample committed Provider state before any Provider ACK in this cohort"}));
    for op in ops {
        let delivery = shared
            .provider_visible
            .lock()
            .unwrap()
            .get(op)
            .unwrap()
            .clone();
        let pulled = product
            .post(
                "/v2/messages/pull",
                json!({"device_key":provider,"delivery_id":delivery}),
            )
            .await;
        let items = pulled["data"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let payload = &items[0]["payload"];
        let expected = shared.expected.lock().unwrap().get(op).unwrap().clone();
        assert_eq!(
            payload["message_id"],
            expected.message_id.as_deref().unwrap()
        );
        assert_eq!(
            blake3::hash(payload["body"].as_str().unwrap().as_bytes())
                .to_hex()
                .to_string(),
            expected.body_hash
        );
        let result = product
            .post(
                "/v2/messages/ack",
                json!({"device_key":provider,"delivery_ids":[delivery]}),
            )
            .await;
        assert_eq!(result["data"]["removed_count"], 1);
        shared.ack("provider-explicit-http", op, provider, &delivery);
        shared.evidence.record(
            "provider_ack_commit_response",
            json!({"op_id":op,"delivery_id":delivery}),
        );
    }
    let deadline = Instant::now() + SETTLE_LIMIT;
    loop {
        shared.check();
        if ops
            .iter()
            .all(|op| shared.released.lock().unwrap().contains(op))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixed ACK/body convergence deadline exceeded"
        );
        wait(product, shared, Duration::from_millis(100)).await;
    }
    for op in ops {
        let expected = shared.expected.lock().unwrap().get(op).unwrap().clone();
        let ids = shared.peer_ids.lock().unwrap();
        let peers: Vec<_> = ids.iter().filter(|((seen, _), _)| seen == op).collect();
        assert_eq!(peers.len(), 2, "both protocol peers must receive {op}");
        assert!(
            peers
                .iter()
                .all(|(_, message)| Some(message.as_str()) == expected.message_id.as_deref())
        );
    }
    product.ledger.assert_capacity_released().await;
    product.ledger.assert_no_legacy_ordinary_writes().await;
    shared.evidence.record(
        "drained_and_ack_converged",
        json!({"messages":ops.len(),"expected_targets":ops.len()*3}),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit bounded long-running normal product resource evidence; fresh C11_EVIDENCE_DIR required"]
async fn normal_sqlite_product_two_load_cycles_reclaim_resources() {
    let directory = PathBuf::from(
        std::env::var_os("C11_EVIDENCE_DIR").expect("fresh evidence directory required"),
    );
    std::fs::create_dir(&directory).expect("refuse existing evidence directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let evidence = Arc::new(Evidence {
        started: Instant::now(),
        phase: Mutex::new("startup".into()),
        file: Mutex::new(private_file(&directory.join("journey.jsonl"))),
    });
    let shared = Arc::new(Shared {
        evidence: evidence.clone(),
        stop: AtomicBool::new(false),
        hold_ack: AtomicBool::new(false),
        failure: Mutex::new(None),
        expected: Mutex::new(BTreeMap::new()),
        peer_ids: Mutex::new(BTreeMap::new()),
        ack_sent: Mutex::new(BTreeSet::new()),
        provider_visible: Mutex::new(BTreeMap::new()),
        ack_visible: Mutex::new(BTreeSet::new()),
        released: Mutex::new(BTreeSet::new()),
    });
    let mut product = Product::spawn(directory.clone(), &evidence).await;
    let provider = product.device("android", Some("fcm")).await;
    let private = product.device("android", None).await;
    let mqtt = product.device("mqtt", None).await;
    let channel = product
        .subscribe(&provider, None, "c11-three-targets")
        .await;
    product.subscribe(&private, Some(&channel), "").await;
    product.subscribe(&mqtt, Some(&channel), "").await;
    let ws = private_peer(&product, private, shared.clone()).await;
    let mqtt = mqtt_peer(&product, mqtt, shared.clone()).await;
    let observer = database_observer(&product, shared.clone());
    evidence.phase("cold-idle35s-not-a-maintenance-window");
    wait(&mut product, &shared, Duration::from_secs(35)).await;
    for (cycle, ramp, burst_count) in [(1, 16, 112), (2, 8, 64)] {
        evidence.phase(&format!("cycle{cycle}-low"));
        let mut ops = paced(&product, &shared, &channel, &format!("c{cycle}-low"), 4, 1).await;
        evidence.phase(&format!("cycle{cycle}-ramp"));
        ops.extend(
            paced(
                &product,
                &shared,
                &channel,
                &format!("c{cycle}-ramp"),
                ramp,
                4,
            )
            .await,
        );
        evidence.phase(&format!("cycle{cycle}-burst-private-ACK-held"));
        shared.hold_ack.store(true, Ordering::Relaxed);
        let hold = Instant::now();
        ops.extend(
            burst(
                &product,
                &shared,
                &channel,
                &format!("c{cycle}-burst"),
                burst_count,
            )
            .await,
        );
        wait(
            &mut product,
            &shared,
            Duration::from_secs(15).saturating_sub(hold.elapsed()),
        )
        .await;
        shared.hold_ack.store(false, Ordering::Relaxed);
        evidence.phase(&format!("cycle{cycle}-drain"));
        drain(&mut product, &shared, &provider, &ops).await;
        if cycle == 1 {
            evidence.phase("cycle1-post-drain-idle330s");
            wait(&mut product, &shared, Duration::from_secs(330)).await;
        }
    }
    evidence.phase("four-complete-48KiB-requests");
    let mut large = Vec::new();
    for index in 0..4 {
        let op = format!("c11-large-{index}");
        large.push(submit(&product, &shared, request(&product, &channel, &op, true)).await);
    }
    drain(&mut product, &shared, &provider, &large).await;
    evidence.phase("unACKed-provider-expiry-sentinel");
    let sentinel_channel = product
        .subscribe(&provider, None, "c11-provider-expiry")
        .await;
    let sentinel_op = "c11-expiry-sentinel";
    let mut sentinel = request(&product, &sentinel_channel, sentinel_op, false);
    sentinel["ttl"] = json!(chrono::Utc::now().timestamp_millis() + 45_000);
    submit(&product, &shared, sentinel).await;
    let deadline = Instant::now() + SETTLE_LIMIT;
    while !shared
        .provider_visible
        .lock()
        .unwrap()
        .contains_key(sentinel_op)
    {
        assert!(Instant::now() < deadline, "sentinel COMMIT not observed");
        wait(&mut product, &shared, Duration::from_millis(100)).await;
    }
    evidence.phase("final-idle330s-expiry-and-maintenance");
    wait(&mut product, &shared, Duration::from_secs(330)).await;
    let snapshot = product.ledger.snapshot(sentinel_op).await;
    let cleaned = snapshot.payload_bytes == 0 && snapshot.body_length == 0 && snapshot.targets == 0;
    let strict =
        std::env::var("C11_EXPECT_ORDINARY_EXPIRY_CLEANUP").is_ok_and(|value| value == "1");
    evidence.record(if cleaned {"expiry_cleanup_pass"}else{"expected_failure"},json!({"op_id":sentinel_op,"payload_bytes":snapshot.payload_bytes,"body_length":snapshot.body_length,"targets":snapshot.targets,"strict_after_fix":strict,"semantics":"preserve baseline cleanup gap; no timeout extension or artificial ACK"}));
    if strict {
        assert!(
            cleaned,
            "runtime maintenance must release expired body and targets"
        );
    }
    assert_eq!(shared.expected.lock().unwrap().len(), 213);
    evidence.record("completed",json!({"offered_messages":213,"expected_targets":212*3+1,"provider_receipts_seen":shared.provider_visible.lock().unwrap().len(),"expiry_cleaned":cleaned,"scope":"finite same-process cycles, not capacity SLA, native-client, TLS, migration or power-loss acceptance"}));
    shared.stop.store(true, Ordering::Relaxed);
    ws.await.unwrap();
    mqtt.await.unwrap();
    observer.await.unwrap();
    product.shutdown().await;
    evidence.record("normal_shutdown", json!({"exit":0}));
    eprintln!("C11_PRODUCT_EVIDENCE={}", directory.display());
}
