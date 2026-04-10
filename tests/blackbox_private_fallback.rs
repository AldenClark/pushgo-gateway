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

struct GatewayProcess {
    child: Child,
    _dir: TempDir,
    _cert_dir: TempDir,
    log_path: PathBuf,
    http_port: u16,
    token: String,
}

impl GatewayProcess {
    async fn spawn() -> Self {
        let http_port = free_port();
        let private_tcp_port = free_port();
        let private_quic_port = free_port();
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let cert_dir = tempfile::tempdir().expect("cert dir should be created");
        let db_path = dir.path().join("gateway-blackbox.sqlite");
        let log_path = dir.path().join("gateway-blackbox.log");
        let cert_path = cert_dir.path().join("cert.pem");
        let key_path = cert_dir.path().join("key.pem");
        let token = "blackbox-private-token".to_string();
        write_self_signed_cert(&cert_path, &key_path);

        let log = std::fs::File::create(&log_path).expect("log file should open");
        let child = Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"))
            .arg("--http-addr")
            .arg(format!("127.0.0.1:{http_port}"))
            .arg("--db-url")
            .arg(format!("sqlite://{}?mode=rwc", db_path.to_string_lossy()))
            .arg("--token")
            .arg(&token)
            .arg("--private-channel-enabled")
            .arg("--private-ack-timeout")
            .arg("1")
            .arg("--private-fallback-max-attempts")
            .arg("3")
            .arg("--private-fallback-max-backoff")
            .arg("4")
            .arg("--private-tcp-bind")
            .arg(format!("127.0.0.1:{private_tcp_port}"))
            .arg("--private-tcp-port")
            .arg(private_tcp_port.to_string())
            .arg("--private-tcp-tls-offload")
            .arg("--private-quic-bind")
            .arg(format!("127.0.0.1:{private_quic_port}"))
            .arg("--private-quic-port")
            .arg(private_quic_port.to_string())
            .arg("--private-tls-cert")
            .arg(&cert_path)
            .arg("--private-tls-key")
            .arg(&key_path)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("gateway should spawn");

        let gateway = Self {
            child,
            _dir: dir,
            _cert_dir: cert_dir,
            log_path,
            http_port,
            token,
        };
        gateway.wait_until_ready().await;
        gateway
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
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_ack_timeout_redelivers_over_private_ws_without_provider() {
    let gateway = GatewayProcess::spawn().await;
    let client = Client::new();
    let device_key = register_private_device(&client, &gateway).await;
    let channel_id = subscribe_channel(&client, &gateway, &device_key).await;
    let profile: Arc<PushgoWireProfile> = Arc::new(PushgoWireProfile::new());
    let mut ws = connect_private_ws(&gateway, &profile, &device_key).await;

    send_message(&client, &gateway, &channel_id).await;
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
    let response = client
        .post(format!("{}/device/register", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "platform": "android",
            "channel_type": "private"
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

async fn send_message(client: &Client, gateway: &GatewayProcess, channel_id: &str) {
    let response = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "channel_id": channel_id,
            "password": "benchmark-123",
            "title": "wake-title",
            "body": "fallback body"
        }))
        .send()
        .await
        .expect("message request should succeed");
    assert_eq!(response.status(), 200, "{}", gateway.logs());
    let _body: Value = response.json().await.expect("response json should parse");
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
                DecodedServerFrame::Welcome(_) => return ws,
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
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let next = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("deliver timeout")
            .expect("websocket should stay open")
            .expect("frame should decode");
        match next {
            Message::Binary(frame) => match profile
                .decode_server_frame(&frame)
                .expect("server frame should decode")
            {
                DecodedServerFrame::Deliver(msg) => return (msg.id, msg.payload.to_vec(), msg.seq),
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
