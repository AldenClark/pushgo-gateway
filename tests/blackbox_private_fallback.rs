use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use pushgo_warp_profile::{PrivatePayloadEnvelope, PushgoWireProfile};
use reqwest::Client;
use serde_json::Value;
use tempfile::TempDir;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use warp_link::warp_link_core::{AckMsg, AckStatus, DecodedServerFrame, HelloCtx, WireProfile};

#[path = "support/product_ordinary_ledger.rs"]
mod product_ordinary_ledger;
use product_ordinary_ledger::{ProductLedger, guard_disk};

#[path = "support/product_mqtt.rs"]
mod product_mqtt;
use product_mqtt::ProductMqttClient;

struct GatewayProcess {
    child: Child,
    _dir: Option<TempDir>,
    _cert_dir: TempDir,
    log_path: PathBuf,
    ledger: ProductLedger,
    launch_args: Vec<String>,
    http_port: u16,
    mqtt_port: u16,
    token: String,
}

impl GatewayProcess {
    async fn spawn() -> Self {
        Self::spawn_with_ledger(None).await
    }

    async fn spawn_with_ledger(external: Option<ProductLedger>) -> Self {
        guard_disk(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let http_port = free_port();
        let private_tcp_port = free_port();
        let private_quic_port = free_port();
        let mqtt_port = free_port();
        let dir = if let Some(root) = std::env::var_os("C10_PRODUCT_EVIDENCE_DIR") {
            std::fs::create_dir_all(&root).expect("product evidence root should exist");
            tempfile::Builder::new()
                .prefix("normal-product-")
                .tempdir_in(root)
                .expect("fresh product evidence directory")
        } else {
            tempfile::tempdir().expect("tempdir should be created")
        };
        let cert_dir = tempfile::tempdir().expect("cert dir should be created");
        let db_path = dir.path().join("gateway-blackbox.sqlite");
        let ledger = external.unwrap_or_else(|| ProductLedger::sqlite(&db_path));
        let log_path = dir.path().join("gateway-blackbox.log");
        let cert_path = cert_dir.path().join("cert.pem");
        let key_path = cert_dir.path().join("key.pem");
        let token = "blackbox-private-token".to_string();
        write_self_signed_cert(&cert_path, &key_path);

        let log = std::fs::File::create(&log_path).expect("log file should open");
        let mut command = Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"));
        command
            .arg("--http-addr")
            .arg(format!("127.0.0.1:{http_port}"))
            .arg("--db-url")
            .arg(ledger.url())
            .arg("--token")
            .arg(&token)
            .arg("--token-service-url")
            .arg("http://127.0.0.1:1")
            .arg("--private-transports")
            .arg("quic,tcp,wss,mqtt")
            .arg("--mqtt-bind")
            .arg(format!("127.0.0.1:{mqtt_port}"))
            .arg("--mqtt-port")
            .arg(mqtt_port.to_string())
            .arg("--private-tcp-bind")
            .arg(format!("127.0.0.1:{private_tcp_port}"))
            .arg("--private-tcp-port")
            .arg(private_tcp_port.to_string())
            .arg("--private-quic-bind")
            .arg(format!("127.0.0.1:{private_quic_port}"))
            .arg("--private-quic-port")
            .arg(private_quic_port.to_string())
            .arg("--private-tls-cert")
            .arg(&cert_path)
            .arg("--private-tls-key")
            .arg(&key_path)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log));
        let launch_args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let child = command.spawn().expect("normal gateway should spawn");

        let gateway = Self {
            child,
            _dir: Some(dir),
            _cert_dir: cert_dir,
            log_path,
            ledger,
            launch_args,
            http_port,
            mqtt_port,
            token,
        };
        gateway.wait_until_ready().await;
        gateway
    }

    async fn crash_and_restart(&mut self) {
        guard_disk(
            self._dir
                .as_ref()
                .expect("product directory retained")
                .path(),
        );
        self.child.kill().expect("kill owned normal gateway");
        self.child.wait().expect("wait for killed normal gateway");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.log_path)
            .expect("existing product log should reopen");
        self.child = Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"))
            .args(&self.launch_args)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("normal gateway should restart");
        self.wait_until_ready().await;
    }

    async fn wait_until_ready(&self) {
        let client = Client::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let response = client
                .get(format!("http://127.0.0.1:{}/", self.http_port))
                .bearer_auth(&self.token)
                .send()
                .await;
            if response
                .as_ref()
                .is_ok_and(|value| value.status().is_success())
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "gateway did not become ready\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::env::var_os("C10_PRODUCT_EVIDENCE_DIR").is_some()
            && let Some(dir) = self._dir.take()
        {
            eprintln!("C10_PRODUCT_EVIDENCE={}", dir.keep().display());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_ack_timeout_redelivers_over_private_ws_without_provider() {
    let gateway = GatewayProcess::spawn().await;
    let client = Client::new();
    let device_key = register_private_device(&client, &gateway).await;
    let channel_id = subscribe_channel(&client, &gateway, &device_key).await;
    let profile: Arc<PushgoWireProfile> = Arc::new(PushgoWireProfile::new());
    reject_private_session_with_invalid_gateway_token(&gateway, &profile, &device_key).await;
    let mut ws = connect_private_ws(&gateway, &profile, &device_key).await;

    let submitted = send_message(&client, &gateway, &channel_id).await;
    let op_id = submitted["data"]["op_id"].as_str().expect("op id returned");
    let first = read_next_deliver(&mut ws, &profile).await;
    assert!(!first.0.is_empty());
    let payload = postcard::from_bytes::<PrivatePayloadEnvelope>(first.1.as_ref())
        .expect("private payload should decode");
    assert_eq!(
        payload.data.get("title").map(String::as_str),
        Some("wake-title")
    );

    let second = read_next_deliver(&mut ws, &profile).await;
    assert_eq!(second.0, first.0);
    assert_eq!(second.1, first.1);

    let ack = profile
        .encode_client_ack(&AckMsg {
            seq: second.2,
            id: second.0.clone(),
            status: AckStatus::Ok,
        })
        .expect("ack should encode");
    ws.send(Message::Binary(ack.to_vec().into()))
        .await
        .expect("ack should send");

    wait_until_ordinary_body_is_released(&gateway, op_id).await;
    gateway.ledger.assert_no_legacy_ordinary_writes().await;
    ws.close(None).await.expect("acked websocket should close");

    let mut reconnected = connect_private_ws(&gateway, &profile, &device_key).await;
    assert_no_deliver_for(&mut reconnected, &profile, Duration::from_secs(3), &gateway).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_product_sqlite_private_restart_releases_one_ledger() {
    ordinary_product_restart_contract(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires approved running isolated PG and a fresh C10_PRODUCT_PG_URL_FILE"]
async fn ordinary_product_postgres_private_restart_releases_one_ledger() {
    let ledger = ProductLedger::external_from_file("postgres", "C10_PRODUCT_PG_URL_FILE").await;
    ordinary_product_restart_contract(Some(ledger)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires approved running isolated MySQL and a fresh C10_PRODUCT_MYSQL_URL_FILE"]
async fn ordinary_product_mysql_private_restart_releases_one_ledger() {
    let ledger = ProductLedger::external_from_file("mysql", "C10_PRODUCT_MYSQL_URL_FILE").await;
    ordinary_product_restart_contract(Some(ledger)).await;
}

async fn ordinary_product_restart_contract(ledger: Option<ProductLedger>) {
    let mut gateway = GatewayProcess::spawn_with_ledger(ledger).await;
    let client = Client::new();
    let device_key = register_private_device(&client, &gateway).await;
    let channel_id = subscribe_channel(&client, &gateway, &device_key).await;
    let profile = Arc::new(PushgoWireProfile::new());
    let mut ws = connect_private_ws(&gateway, &profile, &device_key).await;
    let op_id = format!("c10-product-{:032x}", rand::random::<u128>());
    let occurred_at = chrono::Utc::now().timestamp_millis();
    let mut request = message_request(&channel_id);
    request["op_id"] = Value::String(op_id.clone());
    request["thing_id"] = Value::String("c10-associated-thing".into());
    request["occurred_at"] = occurred_at.into();
    request["metadata"] =
        serde_json::json!({"negative": -42, "fraction": 0.125, "plain": "中文🙂"});
    let prefix = "中文🙂\\\"\n";
    request["body"] = Value::String(prefix.into());
    let used = serde_json::to_vec(&request)
        .expect("request should encode")
        .len();
    request["body"] = Value::String(format!("{prefix}{}", "a".repeat(49152 - used)));
    let encoded = serde_json::to_vec(&request).expect("48KiB request should encode");
    assert_eq!(
        encoded.len(),
        49152,
        "test must exercise the whole JSON body boundary"
    );

    let accepted = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .header("Content-Type", "application/json")
        .body(encoded.clone())
        .send()
        .await
        .expect("normal message admission should respond");
    assert_eq!(accepted.status(), 200, "{}", gateway.logs());
    let accepted: Value = accepted
        .json()
        .await
        .expect("normal acceptance should decode");
    let message_id = accepted["data"]["message_id"]
        .as_str()
        .expect("stable message id");
    let first = read_next_deliver(&mut ws, &profile).await;
    let payload =
        postcard::from_bytes::<PrivatePayloadEnvelope>(&first.1).expect("full Private body");
    assert_eq!(
        payload.data.get("message_id").map(String::as_str),
        Some(message_id)
    );
    assert_eq!(
        payload.data.get("thing_id").map(String::as_str),
        Some("c10-associated-thing")
    );
    assert_eq!(
        payload.data.get("occurred_at").map(String::as_str),
        Some(occurred_at.to_string().as_str())
    );
    assert_eq!(
        payload.data.get("body").map(String::as_str),
        request["body"].as_str()
    );
    let metadata: Value =
        serde_json::from_str(payload.data.get("metadata").expect("metadata preserved"))
            .expect("metadata JSON should decode");
    assert_eq!(metadata, request["metadata"]);
    let before = gateway.ledger.snapshot(&op_id).await;
    assert_eq!(before.message_id, message_id);
    assert!(before.payload_bytes > 0 && before.body_length > 0);
    assert_eq!(before.targets, 1, "one frozen ordinary recipient");
    gateway.ledger.assert_no_legacy_ordinary_writes().await;

    // A client error is not durable success and must preserve the accepted body.
    let negative = profile
        .encode_client_ack(&AckMsg {
            seq: first.2,
            id: first.0.clone(),
            status: AckStatus::Error,
        })
        .expect("negative ACK should encode");
    ws.send(Message::Binary(negative.to_vec().into()))
        .await
        .expect("negative ACK should send");
    let retried = read_next_deliver(&mut ws, &profile).await;
    assert_eq!(
        (retried.0.as_str(), retried.1.as_slice()),
        (first.0.as_str(), first.1.as_slice())
    );
    assert_eq!(
        gateway.ledger.snapshot(&op_id).await,
        before,
        "negative ACK cannot release or replace identity/body"
    );

    // Strong termination occurs after client receive and before a successful ACK.
    // Recovery must use the normal binary and the same one durable identity.
    gateway.crash_and_restart().await;
    drop(ws);
    let mut recovered = connect_private_ws(&gateway, &profile, &device_key).await;
    let replay = read_next_deliver(&mut recovered, &profile).await;
    assert_eq!(
        (replay.0.as_str(), replay.1.as_slice()),
        (first.0.as_str(), first.1.as_slice())
    );
    assert_eq!(gateway.ledger.snapshot(&op_id).await, before);
    let ack = profile
        .encode_client_ack(&AckMsg {
            seq: replay.2,
            id: replay.0.clone(),
            status: AckStatus::Ok,
        })
        .expect("successful ACK should encode");
    recovered
        .send(Message::Binary(ack.to_vec().into()))
        .await
        .expect("ACK should send");
    recovered
        .send(Message::Binary(ack.to_vec().into()))
        .await
        .expect("duplicate ACK should send");
    wait_until_ordinary_body_is_released(&gateway, &op_id).await;
    let after = gateway.ledger.snapshot(&op_id).await;
    assert_eq!(
        (
            after.message_id.as_str(),
            after.accepted_at,
            after.expires_at,
            after.dedupe_until
        ),
        (
            before.message_id.as_str(),
            before.accepted_at,
            before.expires_at,
            before.dedupe_until
        )
    );
    gateway.ledger.assert_no_legacy_ordinary_writes().await;

    let replay_response = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&request)
        .send()
        .await
        .expect("idempotent replay should respond");
    assert_eq!(replay_response.status(), 200);
    let replay_response: Value = replay_response.json().await.expect("replay should decode");
    assert_eq!(
        replay_response["data"]["message_id"],
        accepted["data"]["message_id"]
    );
    assert_eq!(
        gateway.ledger.snapshot(&op_id).await,
        after,
        "replay after ACK cannot recreate body/queue"
    );
    let mut conflict = request.clone();
    conflict["title"] = Value::String("other-head".into());
    assert_eq!(
        serde_json::to_vec(&conflict).unwrap().len(),
        49152,
        "conflict input must remain within the legal whole-JSON body boundary"
    );
    let conflict = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&conflict)
        .send()
        .await
        .expect("conflict should respond");
    assert_eq!(conflict.status(), 409);
    let mut oversized = encoded;
    oversized.push(b' ');
    let oversized = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .header("Content-Type", "application/json")
        .body(oversized)
        .send()
        .await
        .expect("oversized request should respond");
    assert_eq!(
        oversized.status(),
        400,
        "normal ApiJson retains its existing over-body-limit rejection status"
    );
    let status = client
        .get(format!("{}/send_status/{op_id}", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .send()
        .await
        .expect("product send status should respond");
    assert_eq!(status.status(), 200);
    let status: Value = status.json().await.expect("status JSON should decode");
    assert_eq!(status["data"]["entity_id"].as_str(), Some(message_id));

    recovered.close(None).await.expect("close ACKed connection");
    gateway.crash_and_restart().await;
    let mut reconnected = connect_private_ws(&gateway, &profile, &device_key).await;
    assert_no_deliver_for(&mut reconnected, &profile, Duration::from_secs(3), &gateway).await;
    assert_eq!(gateway.ledger.snapshot(&op_id).await, after);
    gateway.ledger.assert_no_legacy_ordinary_writes().await;
    drop(reconnected);
    ordinary_product_mqtt_expiry_contract(&mut gateway).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_product_sqlite_expired_mqtt_queue_and_reconnect_never_publish() {
    let mut gateway = GatewayProcess::spawn().await;
    ordinary_product_mqtt_expiry_contract(&mut gateway).await;
}

async fn ordinary_product_mqtt_expiry_contract(gateway: &mut GatewayProcess) {
    let http = Client::new();
    let device_key = register_private_device_with_platform(&http, gateway, "mqtt").await;
    let channel = subscribe_channel(&http, gateway, &device_key).await;
    let mut mqtt = ProductMqttClient::connect(gateway.mqtt_port, &device_key, &gateway.token).await;
    let past_millis = chrono::Utc::now().timestamp_millis() - 1;
    for (ttl, canonical_millis) in [(0, 0), (-1, -1000), (past_millis, past_millis)] {
        let mut request = message_request(&channel);
        let op_id = format!("c10-expired-{:032x}", rand::random::<u128>());
        request["op_id"] = Value::String(op_id.clone());
        request["ttl"] = ttl.into();
        let accepted = post_product_message(&http, gateway, &request).await;
        let snapshot = gateway.ledger.snapshot(&op_id).await;
        assert_eq!(
            snapshot.message_id,
            accepted["data"]["message_id"].as_str().unwrap()
        );
        assert_eq!(
            snapshot.expires_at, canonical_millis,
            "HTTP lenient seconds normalization must preserve an elapsed absolute deadline"
        );
        assert_eq!(
            (
                snapshot.payload_bytes,
                snapshot.body_length,
                snapshot.targets
            ),
            (0, 0, 0),
            "already-expired acceptance retains identity without creating delivery work"
        );
        let replay = post_product_message(&http, gateway, &request).await;
        assert_eq!(replay["data"]["message_id"], accepted["data"]["message_id"]);
        assert_eq!(gateway.ledger.snapshot(&op_id).await, snapshot);
    }
    mqtt.assert_no_delivery(Duration::from_millis(200)).await;

    // The first PUBLISH starts while valid. Its unacknowledged Hub resume copy
    // reaches the 3s Small-profile retry boundary only after its 2s TTL elapsed.
    let mut retry = message_request(&channel);
    let retry_op = format!("c10-expiring-retry-{:032x}", rand::random::<u128>());
    let deadline = chrono::Utc::now().timestamp_millis() + 2000;
    retry["op_id"] = Value::String(retry_op.clone());
    retry["ttl"] = deadline.into();
    let accepted = post_product_message(&http, gateway, &retry).await;
    let first = mqtt
        .receive(Duration::from_secs(2))
        .await
        .expect("valid first MQTT PUBLISH should arrive");
    let mqttbytes::v5::Packet::Publish(first) = first else {
        panic!("expected live ordinary MQTT PUBLISH")
    };
    let data: Value =
        serde_json::from_slice(&first.payload).expect("actual MQTT envelope should decode");
    assert_eq!(data["data"]["message_id"], accepted["data"]["message_id"]);
    assert!(
        chrono::Utc::now().timestamp_millis() < deadline,
        "first PUBLISH must be observed before expiry for this retry test to be valid"
    );
    let retained = gateway.ledger.snapshot(&retry_op).await;
    assert!(retained.payload_bytes > 0 && retained.targets > 0);
    mqtt.assert_no_delivery(Duration::from_secs(4)).await;
    // No successful PUBACK was sent; reconnect/startup expiry must preserve the
    // accepted identity while retiring expired work, without inventing an ACK.
    gateway.crash_and_restart().await;
    drop(mqtt);
    let expired = gateway.ledger.snapshot(&retry_op).await;
    assert_eq!(
        (
            expired.message_id.as_str(),
            expired.accepted_at,
            expired.expires_at,
            expired.dedupe_until
        ),
        (
            retained.message_id.as_str(),
            retained.accepted_at,
            retained.expires_at,
            retained.dedupe_until
        )
    );
    assert_eq!(
        (expired.payload_bytes, expired.body_length, expired.targets),
        (0, 0, 0)
    );
    let mut reconnected =
        ProductMqttClient::connect(gateway.mqtt_port, &device_key, &gateway.token).await;
    reconnected
        .assert_no_delivery(Duration::from_millis(200))
        .await;
    drop(reconnected);

    // Accepted while offline, then expired before a new session claims it.
    let mut queued = message_request(&channel);
    let queued_op = format!("c10-expiring-offline-{:032x}", rand::random::<u128>());
    let queued_deadline = chrono::Utc::now().timestamp_millis() + 1000;
    queued["op_id"] = Value::String(queued_op.clone());
    queued["ttl"] = queued_deadline.into();
    post_product_message(&http, gateway, &queued).await;
    let queued_before = gateway.ledger.snapshot(&queued_op).await;
    assert!(queued_before.payload_bytes > 0 && queued_before.targets > 0);
    let remaining = queued_deadline
        .saturating_sub(chrono::Utc::now().timestamp_millis())
        .max(0) as u64;
    tokio::time::sleep(Duration::from_millis(remaining + 50)).await;
    let mut late = ProductMqttClient::connect(gateway.mqtt_port, &device_key, &gateway.token).await;
    late.assert_no_delivery(Duration::from_millis(200)).await;
    gateway.crash_and_restart().await;
    drop(late);
    let queued_after = gateway.ledger.snapshot(&queued_op).await;
    assert_eq!(
        (
            queued_after.message_id.as_str(),
            queued_after.accepted_at,
            queued_after.expires_at,
            queued_after.dedupe_until
        ),
        (
            queued_before.message_id.as_str(),
            queued_before.accepted_at,
            queued_before.expires_at,
            queued_before.dedupe_until
        )
    );
    assert_eq!(
        (
            queued_after.payload_bytes,
            queued_after.body_length,
            queued_after.targets
        ),
        (0, 0, 0)
    );
    let mut final_client =
        ProductMqttClient::connect(gateway.mqtt_port, &device_key, &gateway.token).await;
    final_client
        .assert_no_delivery(Duration::from_millis(200))
        .await;
    gateway.ledger.assert_capacity_released().await;
    gateway.ledger.assert_no_legacy_ordinary_writes().await;
}

async fn post_product_message(http: &Client, gateway: &GatewayProcess, request: &Value) -> Value {
    let response = http
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(request)
        .send()
        .await
        .expect("normal product admission should respond");
    assert_eq!(response.status(), 200, "{}", gateway.logs());
    response
        .json()
        .await
        .expect("normal product acceptance should decode")
}

async fn reject_private_session_with_invalid_gateway_token(
    gateway: &GatewayProcess,
    profile: &Arc<PushgoWireProfile>,
    device_key: &str,
) {
    let mut request = format!("ws://127.0.0.1:{}/private/ws", gateway.http_port)
        .into_client_request()
        .expect("ws request should build");
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "pushgo-private.v1".parse().expect("subprotocol header"),
    );
    // Pass HTTP middleware so this specifically checks the private protocol's
    // device-session authentication with the Hello token.
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", gateway.token)
            .parse()
            .expect("auth header"),
    );
    let (mut ws, _) = connect_async(request)
        .await
        .expect("websocket transport should connect before Hello auth");
    let hello = profile
        .encode_client_hello(&HelloCtx {
            identity: device_key.to_string(),
            auth_token: Some("invalid-private-session-token".to_string()),
            resume_token: None,
            last_acked_seq: None,
            supported_wire_versions: Vec::new(),
            supported_payload_versions: Vec::new(),
            perf_tier: None,
            app_state: None,
            metadata: Default::default(),
        })
        .expect("hello should encode");
    ws.send(Message::Binary(hello.to_vec().into()))
        .await
        .expect("hello should send");

    let next = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("authentication response should arrive")
        .expect("private auth should respond before closing")
        .expect("authentication frame should decode");
    let Message::Binary(frame) = next else {
        panic!("invalid private token should receive a protocol error frame: {next:?}");
    };
    match profile
        .decode_server_frame(&frame)
        .expect("private auth frame should decode")
    {
        DecodedServerFrame::Error { code, .. } => {
            assert!(
                !code.is_empty(),
                "auth rejection should include an error code"
            );
        }
        other => panic!("invalid private token was not rejected: {other:?}"),
    }
    let _ = ws.close(None).await;
}

async fn wait_until_ordinary_body_is_released(gateway: &GatewayProcess, op_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let snapshot = gateway.ledger.snapshot(op_id).await;
        if snapshot.payload_bytes == 0 && snapshot.body_length == 0 && snapshot.targets == 0 {
            gateway.ledger.assert_capacity_released().await;
            assert!(
                snapshot.dedupe_until - snapshot.accepted_at >= 30 * 24 * 60 * 60 * 1000,
                "ACK must preserve full 30 day identity history"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "ACK did not commit ordinary body/target release: {snapshot:?}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn assert_no_deliver_for(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    profile: &Arc<PushgoWireProfile>,
    duration: Duration,
    gateway: &GatewayProcess,
) {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
            return;
        };
        let next = match tokio::time::timeout(remaining, ws.next()).await {
            Err(_) => return,
            Ok(next) => next
                .expect("reconnected websocket should stay open")
                .expect("reconnected websocket frame should decode"),
        };
        match next {
            Message::Binary(frame) => match profile
                .decode_server_frame(&frame)
                .expect("server frame should decode")
            {
                DecodedServerFrame::Deliver(msg) => panic!(
                    "ACKed delivery was replayed after reconnect: id={}\n{}",
                    msg.id,
                    gateway.logs()
                ),
                DecodedServerFrame::Ping => {
                    let pong = profile.encode_client_pong();
                    ws.send(Message::Binary(pong.to_vec().into()))
                        .await
                        .expect("pong should send");
                }
                DecodedServerFrame::Pong
                | DecodedServerFrame::Welcome(_)
                | DecodedServerFrame::Unknown => {}
                DecodedServerFrame::Error { code, message } => {
                    panic!("gateway returned error code={code} message={message}");
                }
                DecodedServerFrame::GoAway(reason) => {
                    panic!("gateway closed reconnected session: {reason:?}");
                }
            },
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload))
                    .await
                    .expect("pong should send");
            }
            Message::Pong(_) => {}
            other => panic!("unexpected websocket frame after reconnect: {other:?}"),
        }
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("port bind should succeed");
    listener
        .local_addr()
        .expect("local addr should exist")
        .port()
}

fn write_self_signed_cert(cert_path: &std::path::Path, key_path: &std::path::Path) {
    let status = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-sha256")
        .arg("-days")
        .arg("1")
        .arg("-nodes")
        .arg("-keyout")
        .arg(key_path)
        .arg("-out")
        .arg(cert_path)
        .arg("-subj")
        .arg("/CN=127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl should start");
    assert!(
        status.success(),
        "openssl failed to generate self-signed cert"
    );
}

async fn register_private_device(client: &Client, gateway: &GatewayProcess) -> String {
    register_private_device_with_platform(client, gateway, "android").await
}

async fn register_private_device_with_platform(
    client: &Client,
    gateway: &GatewayProcess,
    platform: &str,
) -> String {
    let response = client
        .post(format!("{}/device/register", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "platform": platform
        }))
        .send()
        .await
        .expect("device register should succeed");
    assert_eq!(response.status(), 200, "{}", gateway.logs());
    let body: Value = response.json().await.expect("response json should parse");
    body["data"]["device_key"]
        .as_str()
        .expect("device key should exist")
        .to_string()
}

async fn subscribe_channel(client: &Client, gateway: &GatewayProcess, device_key: &str) -> String {
    let response = client
        .post(format!("{}/channel/subscribe", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "device_key": device_key,
            "channel_name": "blackbox-private-fallback",
            "password": "benchmark-123"
        }))
        .send()
        .await
        .expect("channel subscribe should succeed");
    assert_eq!(response.status(), 200, "{}", gateway.logs());
    let body: Value = response.json().await.expect("response json should parse");
    body["data"]["channel_id"]
        .as_str()
        .expect("channel id should exist")
        .to_string()
}

async fn send_message(client: &Client, gateway: &GatewayProcess, channel_id: &str) -> Value {
    let response = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&message_request(channel_id))
        .send()
        .await
        .expect("message request should succeed");
    assert_eq!(response.status(), 200, "{}", gateway.logs());
    response.json().await.expect("response json should parse")
}

fn message_request(channel_id: &str) -> Value {
    serde_json::json!({
        "channel_id": channel_id,
        "password": "benchmark-123",
        "title": "wake-title",
        "body": "fallback body"
    })
}

async fn connect_private_ws(
    gateway: &GatewayProcess,
    profile: &Arc<PushgoWireProfile>,
    device_key: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut request = format!("ws://127.0.0.1:{}/private/ws", gateway.http_port)
        .into_client_request()
        .expect("ws request should build");
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "pushgo-private.v1".parse().expect("subprotocol header"),
    );
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", gateway.token)
            .parse()
            .expect("auth header"),
    );
    let (mut ws, _) = connect_async(request)
        .await
        .expect("private websocket should connect");

    let hello = profile
        .encode_client_hello(&HelloCtx {
            identity: device_key.to_string(),
            auth_token: Some(gateway.token.clone()),
            resume_token: None,
            last_acked_seq: None,
            supported_wire_versions: Vec::new(),
            supported_payload_versions: Vec::new(),
            perf_tier: None,
            app_state: None,
            metadata: Default::default(),
        })
        .expect("hello should encode");
    ws.send(Message::Binary(hello.to_vec().into()))
        .await
        .expect("hello should send");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let next = tokio::time::timeout(Duration::from_secs(1), ws.next())
            .await
            .expect("welcome timeout")
            .expect("websocket should stay open")
            .expect("frame should decode");
        match next {
            Message::Binary(frame) => match profile
                .decode_server_frame(&frame)
                .expect("server frame should decode")
            {
                DecodedServerFrame::Welcome(welcome) => {
                    assert_eq!(
                        welcome.max_frame_bytes, 131072,
                        "normal product WELCOME must use the coordinated 128KiB full-frame limit"
                    );
                    return ws;
                }
                DecodedServerFrame::Ping => {
                    let pong = profile.encode_client_pong();
                    ws.send(Message::Binary(pong.to_vec().into()))
                        .await
                        .expect("pong should send");
                }
                DecodedServerFrame::Error { code, message } => {
                    panic!("gateway returned error code={code} message={message}");
                }
                other => panic!("unexpected pre-welcome frame: {other:?}"),
            },
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload))
                    .await
                    .expect("pong should send");
            }
            other => panic!("unexpected websocket frame before welcome: {other:?}"),
        }
        assert!(Instant::now() < deadline, "welcome frame never arrived");
    }
}

async fn read_next_deliver(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    profile: &Arc<PushgoWireProfile>,
) -> (String, Vec<u8>, Option<u64>) {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("deliver timeout")
            .expect("websocket should stay open")
            .expect("frame should decode");
        match next {
            Message::Binary(frame) => match profile
                .decode_server_frame(&frame)
                .expect("server frame should decode")
            {
                DecodedServerFrame::Deliver(msg) => {
                    assert!(
                        frame.len() <= 131072,
                        "full WSS frame includes the type/flags header"
                    );
                    return (msg.id, msg.payload.to_vec(), msg.seq);
                }
                DecodedServerFrame::Ping => {
                    let pong = profile.encode_client_pong();
                    ws.send(Message::Binary(pong.to_vec().into()))
                        .await
                        .expect("pong should send");
                }
                DecodedServerFrame::Pong => {}
                DecodedServerFrame::Error { code, message } => {
                    panic!("gateway returned error code={code} message={message}");
                }
                DecodedServerFrame::GoAway(reason) => {
                    panic!("gateway closed session: {reason:?}");
                }
                DecodedServerFrame::Welcome(_) | DecodedServerFrame::Unknown => {}
            },
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload))
                    .await
                    .expect("pong should send");
            }
            Message::Pong(_) => {}
            other => panic!("unexpected websocket frame: {other:?}"),
        }
        assert!(Instant::now() < deadline, "deliver frame never arrived");
    }
}
