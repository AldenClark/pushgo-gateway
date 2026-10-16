#![cfg(feature = "qa")]
//! Real product executable/router/Storage/ledger with only Provider IO replaced.
//! This does not claim real APNs, Windows OS or native-client persistence QA.
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[path = "support/product_ordinary_ledger.rs"]
mod product_ordinary_ledger;
use product_ordinary_ledger::{ProductLedger, guard_disk};

const PASSWORD: &str = "qa-channel-password";
const AUTH: &str = "qa-gateway-local-synthetic";

struct ProductProcess {
    child: Child,
    directory: PathBuf,
    scenario: PathBuf,
    log: PathBuf,
    args: Vec<String>,
    base: String,
    ledger: ProductLedger,
    client: Client,
}

impl ProductProcess {
    async fn spawn(external: Option<ProductLedger>) -> Self {
        guard_disk(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
        let directory = if let Some(root) = std::env::var_os("C10_PRODUCT_EVIDENCE_DIR") {
            std::fs::create_dir_all(&root).unwrap();
            tempfile::Builder::new()
                .prefix("c10-synthetic-provider-")
                .tempdir_in(root)
                .unwrap()
        } else {
            tempfile::Builder::new()
                .prefix("c10-synthetic-provider-")
                .tempdir()
                .unwrap()
        }
        .keep();
        let scenario = directory.join("providers");
        std::fs::create_dir(&scenario).unwrap();
        std::fs::write(
            scenario.join("scenario.json"),
            br#"{"synthetic_only":true,"status":202,"delay_ms":1000}"#,
        )
        .unwrap();
        let ledger =
            external.unwrap_or_else(|| ProductLedger::sqlite(&directory.join("gateway.sqlite")));
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let base = format!("http://127.0.0.1:{port}");
        let args = vec![
            "--http-addr".into(),
            format!("127.0.0.1:{port}"),
            "--db-url".into(),
            ledger.url().into(),
            "--token".into(),
            AUTH.into(),
            "--token-service-url".into(),
            "http://127.0.0.1:1".into(),
            "--public-base-url".into(),
            format!("{base}/qa/prefix"),
            "--private-transports".into(),
            "false".into(),
            "--qa-provider-fixture-dir".into(),
            scenario.to_string_lossy().into_owned(),
        ];
        let log = directory.join("normal-gateway.log");
        let child = launch(&args, &log);
        let mut process = Self {
            child,
            directory,
            scenario,
            log,
            args,
            base,
            ledger,
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        };
        process.ready().await;
        process
    }
    async fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "normal product exited before ready: {}",
                self.logs()
            );
            if self
                .client
                .get(&self.base)
                .bearer_auth(AUTH)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "normal product ready timeout: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn restart(&mut self) {
        guard_disk(&self.directory);
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.child = launch(&self.args, &self.log);
        self.ready().await;
    }
    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    async fn post(&self, path: &str, input: &Value) -> (u16, Value) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(AUTH)
            .json(input)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.json().await.unwrap();
        (status, body)
    }
    async fn post_ok(&self, path: &str, input: &Value) -> Value {
        let (status, body) = self.post(path, input).await;
        assert_eq!(status, 200, "{path}: {body}; {}", self.logs());
        body
    }
    async fn register(&self, platform: &str, provider: &str, raw: &str) -> String {
        let result = self
            .post_ok("/device/register", &json!({"platform":platform}))
            .await;
        let key = result["data"]["device_key"].as_str().unwrap().to_owned();
        self.post_ok("/channel/device",&json!({"platform":platform,"device_key":key,"channel_type":provider,"provider_token":raw})).await;
        key
    }
    async fn subscribe(&self, key: &str, channel: Option<&str>) -> String {
        let input = if let Some(channel) = channel {
            json!({"device_key":key,"channel_id":channel,"password":PASSWORD})
        } else {
            json!({"device_key":key,"channel_name":"qa-normal-ordinary","password":PASSWORD})
        };
        self.post_ok("/channel/subscribe", &input).await["data"]["channel_id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn records(&self) -> Vec<Value> {
        let raw = std::fs::read_to_string(self.scenario.join("records.jsonl")).unwrap_or_default();
        // The controlled writer flushes complete lines. Ignore a concurrent
        // incomplete last line until the next observation, never a final result.
        raw.split_inclusive('\n')
            .filter(|line| line.ends_with('\n'))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    async fn records_for(&self, delivery: &str, minimum: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let records: Vec<_> = self
                .records()
                .into_iter()
                .filter(|record| record["data"]["delivery_id"] == delivery)
                .collect();
            if records.len() >= minimum {
                return records;
            }
            assert!(
                Instant::now() < deadline,
                "missing {minimum} calls for {delivery}: {}; {}",
                self.records().len(),
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn settled(&self, op: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let response = self
                .client
                .get(format!("{}/send_status/{op}", self.base))
                .bearer_auth(AUTH)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{}", self.logs());
            let result: Value = response.json().await.unwrap();
            if result["data"]["status"] == "sent" {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "provider receipt COMMIT did not converge: {result}; {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    async fn pull(&self, key: &str, delivery: Option<&str>) -> Vec<Value> {
        let mut input = json!({"device_key":key});
        if let Some(delivery) = delivery {
            input["delivery_id"] = json!(delivery);
        }
        self.post_ok("/v2/messages/pull", &input).await["data"]["items"]
            .as_array()
            .unwrap()
            .clone()
    }
    async fn delivery_for(&self, key: &str, message: &str) -> String {
        self.pull(key, None)
            .await
            .into_iter()
            .find(|item| item["payload"]["message_id"] == message)
            .unwrap()["delivery_id"]
            .as_str()
            .unwrap()
            .into()
    }
    async fn ack_all(&self, keys: &[String], delivery: &str) {
        for key in keys {
            let request = json!({"device_key":key,"delivery_ids":[delivery]});
            let result = self.post_ok("/v2/messages/ack", &request).await;
            assert_eq!(result["data"]["removed_count"], 1);
            let replay = self.post_ok("/v2/messages/ack", &request).await;
            assert_eq!(
                replay["data"]["removed_count"], 0,
                "duplicate ACK must remain terminal"
            );
            assert!(self.pull(key, Some(delivery)).await.is_empty());
        }
    }
}
fn launch(args: &[String], log: &std::path::Path) -> Child {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_pushgo-gateway"))
        .args(args)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap()
}
impl Drop for ProductProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_sqlite_provider_ordinary_chain() {
    journey(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an explicitly provisioned new isolated PostgreSQL database URL file"]
async fn normal_postgres_provider_ordinary_chain() {
    journey(Some(
        ProductLedger::external_from_file("postgres", "C10_PROVIDER_PG_URL_FILE").await,
    ))
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an explicitly provisioned new isolated MySQL database URL file"]
async fn normal_mysql_provider_ordinary_chain() {
    journey(Some(
        ProductLedger::external_from_file("mysql", "C10_PROVIDER_MYSQL_URL_FILE").await,
    ))
    .await;
}

async fn journey(external: Option<ProductLedger>) {
    let mut product = ProductProcess::spawn(external).await;
    let keys = vec![
        product
            .register("android", "fcm", "qa-fcm-synthetic-ordinary-0123456789")
            .await,
        product.register("ios", "apns", &"11".repeat(32)).await,
        product.register("watchos", "apns", &"22".repeat(32)).await,
        product
            .register(
                "windows",
                "wns",
                "https://qa-synthetic.notify.windows.com/ordinary",
            )
            .await,
    ];
    let channel = product.subscribe(&keys[0], None).await;
    for key in &keys[1..] {
        assert_eq!(product.subscribe(key, Some(&channel)).await, channel);
    }
    let expires = chrono::Utc::now().timestamp_millis() + 300_000;
    let direct = json!({
        "channel_id":channel,"password":PASSWORD,"op_id":"qa-product-direct",
        "thing_id":"00112233445566778899aabbccddeeff","occurred_at":1700000000123_i64,
        "title":"ordinary linked text 中文","body":"complete ordinary body","ttl":expires,
        "metadata":{"negative":-7,"float":3.125,"string":"preserved"},
    });
    let first = product.post_ok("/message", &direct).await;
    let message = first["data"]["message_id"].as_str().unwrap().to_owned();
    let delivery = product.delivery_for(&keys[0], &message).await;
    let calls = product.records_for(&delivery, 4).await;
    product.settled("qa-product-direct").await;
    let classes: BTreeSet<_> = calls
        .iter()
        .map(|record| {
            (
                record["provider"].as_str().unwrap(),
                record["platform"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        classes,
        BTreeSet::from([
            ("FCM", "android"),
            ("APNS", "ios"),
            ("APNS", "watchos"),
            ("WNS", "windows")
        ])
    );
    for record in &calls {
        assert_eq!(record["data"]["message_id"], message);
        assert_eq!(
            record["data"]["base_url"],
            format!("{}/qa/prefix", product.base)
        );
        assert_ne!(record["data"]["provider_mode"], "wakeup");
    }
    let snapshot = product.ledger.snapshot("qa-product-direct").await;
    assert_eq!(
        snapshot.targets, 4,
        "one accepted message freezes every Provider target in the same ledger"
    );
    assert_eq!(snapshot.message_id, message);
    assert_eq!(snapshot.expires_at, expires);
    assert_eq!(
        snapshot.dedupe_until - snapshot.accepted_at,
        30_i64 * 86_400_000
    );
    assert_eq!(
        product.post_ok("/message", &direct).await["data"]["message_id"],
        message
    );
    let mut conflict = direct.clone();
    conflict["body"] = json!("conflicting content");
    assert_eq!(product.post("/message", &conflict).await.0, 409);

    // A later subscriber cannot join an already accepted message's target set.
    let late = product
        .register("android", "fcm", "qa-fcm-synthetic-late-0123456789")
        .await;
    product.subscribe(&late, Some(&channel)).await;
    assert_eq!(
        product.ledger.snapshot("qa-product-direct").await.targets,
        4
    );
    assert!(product.pull(&late, Some(&delivery)).await.is_empty());
    product
        .post_ok(
            "/channel/unsubscribe",
            &json!({"device_key":late,"channel_id":channel}),
        )
        .await;
    product.restart().await;
    assert_eq!(product.ledger.snapshot("qa-product-direct").await, snapshot);
    for key in &keys {
        let items = product.pull(key, Some(&delivery)).await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["payload"]["body"], direct["body"]);
        assert_eq!(items[0]["payload"]["thing_id"], direct["thing_id"]);
        assert_eq!(items[0]["payload"]["occurred_at"], "1700000000123");
        let metadata: Value =
            serde_json::from_str(items[0]["payload"]["metadata"].as_str().unwrap()).unwrap();
        assert_eq!(metadata, direct["metadata"]);
    }
    let denied = product
        .client
        .post(format!("{}/v2/messages/ack", product.base))
        .json(&json!({"device_key":keys[0],"delivery_ids":[delivery]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        401,
        "failed unauthenticated ACK must not release durable body"
    );
    assert_eq!(product.ledger.snapshot("qa-product-direct").await, snapshot);
    product.ack_all(&keys, &delivery).await;
    assert_eq!(
        product
            .ledger
            .snapshot("qa-product-direct")
            .await
            .body_length,
        0
    );
    product.ledger.assert_capacity_released().await;

    // Exactly 48KiB is the complete JSON body, not a standalone text allowance.
    let mut large = json!({"channel_id":channel,"password":PASSWORD,"op_id":"qa-product-large","title":"large ordinary","body":"","ttl":expires});
    let overhead = serde_json::to_vec(&large).unwrap().len();
    large["body"] = json!("x".repeat(49152 - overhead));
    let encoded = serde_json::to_vec(&large).unwrap();
    assert_eq!(encoded.len(), 49152);
    let response = product
        .client
        .post(format!("{}/message", product.base))
        .bearer_auth(AUTH)
        .header("content-type", "application/json")
        .body(encoded)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let accepted: Value = response.json().await.unwrap();
    let large_message = accepted["data"]["message_id"].as_str().unwrap().to_owned();
    let large_delivery = product.delivery_for(&keys[0], &large_message).await;
    let large_calls = product.records_for(&large_delivery, 4).await;
    product.settled("qa-product-large").await;
    for record in large_calls
        .iter()
        .filter(|record| record["platform"] != "watchos")
    {
        assert_eq!(record["data"]["provider_mode"], "wakeup");
    }
    for key in &keys {
        let items = product.pull(key, Some(&large_delivery)).await;
        assert_eq!(
            items[0]["payload"]["body"], large["body"],
            "Pull preserves canonical body independently of Provider payload limits"
        );
        assert_eq!(items[0]["payload"]["message_id"], large_message);
    }
    let mut oversized = serde_json::to_vec(&large).unwrap();
    oversized.push(b' ');
    let rejected = product
        .client
        .post(format!("{}/message", product.base))
        .bearer_auth(AUTH)
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .unwrap();
    // The normal ApiJson contract maps BytesRejection to its existing 400
    // invalid_request_body response; the independent prototype used 413.
    assert_eq!(rejected.status(), 400);
    let rejection: Value = rejected.json().await.unwrap();
    assert!(rejection.to_string().contains("invalid_request_body"));
    product.ack_all(&keys, &large_delivery).await;
    product.ledger.assert_capacity_released().await;

    // Kill after an observed send begins, before its configured local reply.
    // Recovery may repeat the external request but must retain durable identity.
    let unknown = json!({"channel_id":channel,"password":PASSWORD,"op_id":"qa-product-unknown","title":"unknown external result","body":"same identity after crash","ttl":expires});
    let accepted = product.post_ok("/message", &unknown).await;
    let unknown_message = accepted["data"]["message_id"].as_str().unwrap().to_owned();
    let unknown_delivery = product.delivery_for(&keys[0], &unknown_message).await;
    product.records_for(&unknown_delivery, 4).await;
    let before = product.ledger.snapshot("qa-product-unknown").await;
    let pending: Value = product
        .client
        .get(format!("{}/send_status/qa-product-unknown", product.base))
        .bearer_auth(AUTH)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        pending["data"]["status"], "provider_queued",
        "fault injection must observe work before terminal receipt COMMIT"
    );
    product.restart().await;
    product.records_for(&unknown_delivery, 4).await;
    product.settled("qa-product-unknown").await;
    assert_eq!(product.ledger.snapshot("qa-product-unknown").await, before);
    assert_eq!(
        product.post_ok("/message", &unknown).await["data"]["message_id"],
        unknown_message
    );
    product.ack_all(&keys, &unknown_delivery).await;
    product.ledger.assert_capacity_released().await;
    product.ledger.assert_no_legacy_ordinary_writes().await;
    assert!(product.records().len() <= 256);
    std::fs::write(product.directory.join("qa-provider-result.json"),serde_json::to_vec_pretty(&json!({
        "normal_binary":env!("CARGO_BIN_EXE_pushgo-gateway"),"qa_feature":true,
        "messages":3,"targets_per_message":4,"provider_calls_observed":product.records().len(),
        "ordinary_legacy_writes":0,"final_capacity_released":true,
        "real_provider_network":false,"client_storage":false,
        "ack_failure_coverage":"unauthenticated HTTP ACK; database-write faults are separate tests",
    })).unwrap()).unwrap();
    eprintln!(
        "normal Provider product evidence: {}",
        product.directory.display()
    );
}
