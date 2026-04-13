use std::{
    collections::HashSet,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use reqwest::Client;
use serde_json::Value;
use tempfile::TempDir;

struct GatewayProcess {
    child: Child,
    _dir: TempDir,
    log_path: PathBuf,
    http_port: u16,
    token: String,
}

impl GatewayProcess {
    async fn spawn() -> Self {
        let http_port = free_port();
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("gateway-provider-ingress.sqlite");
        let log_path = dir.path().join("gateway-provider-ingress.log");
        let token = "blackbox-provider-token".to_string();

        let log = std::fs::File::create(&log_path).expect("log file should open");
        let child = Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"))
            .arg("--http-addr")
            .arg(format!("127.0.0.1:{http_port}"))
            .arg("--db-url")
            .arg(format!("sqlite://{}?mode=rwc", db_path.to_string_lossy()))
            .arg("--token")
            .arg(&token)
            .arg("--diagnostics-api-enabled")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("gateway should spawn");

        let gateway = Self {
            child,
            _dir: dir,
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
async fn provider_ingress_pull_and_ack_work_end_to_end() {
    let gateway = GatewayProcess::spawn().await;
    let client = Client::new();

    let device_key = register_provider_device(&client, &gateway).await;
    let channel_id = subscribe_channel(&client, &gateway, &device_key).await;

    let _ = pull_messages(&client, &gateway, &device_key, None).await;

    send_message(&client, &gateway, &channel_id, "op-provider-ack-001").await;
    let mut known_delivery_ids = HashSet::new();
    let first_delivery_id =
        wait_for_delivery_id(&client, &gateway, &channel_id, &known_delivery_ids).await;
    known_delivery_ids.insert(first_delivery_id.clone());

    assert!(ack_message_with_retry(&client, &gateway, &device_key, &first_delivery_id).await);
    let ack_again = ack_message(&client, &gateway, &device_key, &first_delivery_id).await;
    assert_eq!(ack_again, Some(false), "ack should be idempotent");

    let single_after_ack = pull_messages(
        &client,
        &gateway,
        &device_key,
        Some(first_delivery_id.as_str()),
    )
    .await;
    assert!(
        single_after_ack.is_empty(),
        "acked delivery should not be pullable"
    );

    send_message(&client, &gateway, &channel_id, "op-provider-pull-all-001").await;
    send_message(&client, &gateway, &channel_id, "op-provider-pull-all-002").await;
    let second_delivery_id =
        wait_for_delivery_id(&client, &gateway, &channel_id, &known_delivery_ids).await;
    known_delivery_ids.insert(second_delivery_id.clone());
    let third_delivery_id =
        wait_for_delivery_id(&client, &gateway, &channel_id, &known_delivery_ids).await;
    known_delivery_ids.insert(third_delivery_id.clone());

    let single_pull = pull_messages(
        &client,
        &gateway,
        &device_key,
        Some(second_delivery_id.as_str()),
    )
    .await;
    assert_eq!(single_pull.len(), 1);
    assert_eq!(single_pull[0], second_delivery_id);

    let all_pull = pull_messages(&client, &gateway, &device_key, None).await;
    assert!(
        all_pull.contains(&third_delivery_id),
        "pull all should include remaining delivery"
    );
    assert!(
        !all_pull.contains(&second_delivery_id),
        "single pulled delivery must not reappear in pull all"
    );

    let drain_pull = pull_messages(&client, &gateway, &device_key, None).await;
    assert!(drain_pull.is_empty(), "queue should be drained");
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("port bind should succeed");
    listener
        .local_addr()
        .expect("local addr should exist")
        .port()
}

async fn register_provider_device(client: &Client, gateway: &GatewayProcess) -> String {
    let token = format!("fcm-blackbox-token-{}", std::process::id());
    let response = client
        .post(format!("{}/device/register", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "platform": "android",
            "channel_type": "fcm",
            "provider_token": token
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
            "channel_name": "blackbox-provider-ingress",
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

async fn send_message(client: &Client, gateway: &GatewayProcess, channel_id: &str, op_id: &str) {
    let response = client
        .post(format!("{}/message", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "channel_id": channel_id,
            "password": "benchmark-123",
            "op_id": op_id,
            "title": format!("title-{op_id}"),
            "body": "provider ingress blackbox"
        }))
        .send()
        .await
        .expect("message request should succeed");
    assert!(
        response.status().as_u16() == 200 || response.status().as_u16() == 503,
        "unexpected message status: {}\n{}",
        response.status(),
        gateway.logs()
    );
    let _: Value = response.json().await.expect("response json should parse");
}

async fn wait_for_delivery_id(
    client: &Client,
    gateway: &GatewayProcess,
    channel_id: &str,
    excluded: &HashSet<String>,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let diagnostics_url = format!(
            "{}/diagnostics/dispatch?limit=200&channel_id={channel_id}",
            gateway.base_url()
        );
        let response = client
            .get(diagnostics_url)
            .bearer_auth(&gateway.token)
            .send()
            .await
            .expect("diagnostics request should succeed");
        if response.status().is_success() {
            let body: Value = response
                .json()
                .await
                .expect("diagnostics response should parse");
            if let Some(entries) = body["data"]["entries"].as_array() {
                for entry in entries {
                    let delivery_id = entry["delivery_id"].as_str().unwrap_or("").trim();
                    if !delivery_id.is_empty() && !excluded.contains(delivery_id) {
                        return delivery_id.to_string();
                    }
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "delivery id not found in diagnostics\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn ack_message_with_retry(
    client: &Client,
    gateway: &GatewayProcess,
    device_key: &str,
    delivery_id: &str,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(true) = ack_message(client, gateway, device_key, delivery_id).await {
            return true;
        }
        assert!(
            Instant::now() < deadline,
            "ack did not remove delivery_id={delivery_id}\n{}",
            gateway.logs()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn ack_message(
    client: &Client,
    gateway: &GatewayProcess,
    device_key: &str,
    delivery_id: &str,
) -> Option<bool> {
    let response = client
        .post(format!("{}/messages/ack", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&serde_json::json!({
            "device_key": device_key,
            "delivery_id": delivery_id
        }))
        .send()
        .await
        .expect("ack request should succeed");
    if !response.status().is_success() {
        return None;
    }
    let body: Value = response.json().await.expect("ack response should parse");
    body["data"]["removed"].as_bool()
}

async fn pull_messages(
    client: &Client,
    gateway: &GatewayProcess,
    device_key: &str,
    delivery_id: Option<&str>,
) -> Vec<String> {
    let mut payload = serde_json::json!({
        "device_key": device_key
    });
    if let Some(delivery_id) = delivery_id {
        payload["delivery_id"] = serde_json::json!(delivery_id);
    }
    let response = client
        .post(format!("{}/messages/pull", gateway.base_url()))
        .bearer_auth(&gateway.token)
        .json(&payload)
        .send()
        .await
        .expect("pull request should succeed");
    assert!(response.status().is_success(), "{}", gateway.logs());
    let body: Value = response.json().await.expect("pull response should parse");
    body["data"]["items"]
        .as_array()
        .expect("items should be array")
        .iter()
        .filter_map(|item| item["delivery_id"].as_str().map(ToString::to_string))
        .collect()
}
