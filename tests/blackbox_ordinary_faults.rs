#![cfg(feature = "qa")]
//! Normal Gateway executable fault recovery with fresh synthetic databases.
//! Provider handoff is observed separately from receipt COMMIT. These cases
//! exercise real SQL locks; an unauthenticated ACK is not their failure oracle.
use serde_json::json;

#[path = "support/ordinary_faults.rs"]
mod ordinary_faults;
#[path = "support/product_ordinary_ledger.rs"]
mod product_ordinary_ledger;

use ordinary_faults::{AUTH, PASSWORD, ProductProcess, WriteBlock, target_state};
use product_ordinary_ledger::ProductLedger;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_sqlite_receipt_and_ack_sql_lock_recovery() {
    sql_lock_recovery(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a newly provisioned isolated PostgreSQL URL file; does not create or reset a database"]
async fn normal_postgres_receipt_and_ack_sql_lock_recovery() {
    sql_lock_recovery(Some(
        ProductLedger::external_from_file("postgres", "C10_FAULTS_PG_URL_FILE").await,
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a newly provisioned isolated MySQL URL file; does not create or reset a database"]
async fn normal_mysql_receipt_and_ack_sql_lock_recovery() {
    sql_lock_recovery(Some(
        ProductLedger::external_from_file("mysql", "C10_FAULTS_MYSQL_URL_FILE").await,
    ))
    .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a newly provisioned isolated PG URL file and permission to terminate that role's own test session"]
async fn normal_postgres_fixed_owner_loss_rejects_live_old_process_takeover() {
    owner_session_loss(
        ProductLedger::external_from_file("postgres", "C10_FAULTS_OWNER_PG_URL_FILE").await,
    )
    .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a newly provisioned isolated MySQL URL file and permission to terminate that role's own test session"]
async fn normal_mysql_fixed_owner_loss_rejects_live_old_process_takeover() {
    owner_session_loss(
        ProductLedger::external_from_file("mysql", "C10_FAULTS_OWNER_MYSQL_URL_FILE").await,
    )
    .await;
}

#[cfg(unix)]
async fn owner_session_loss(ledger: ProductLedger) {
    let mut product = ProductProcess::spawn(Some(ledger)).await;
    let (key, channel) = product.register_channel().await;
    let input = json!({
        "channel_id":channel,"password":PASSWORD,"op_id":"qa-owner-session-loss",
        "title":"fixed owner loss","body":"survive owner failure",
        "ttl":chrono::Utc::now().timestamp_millis()+300_000,
    });
    let accepted = product.post_ok("/message", &input).await;
    let message = accepted["data"]["message_id"].as_str().unwrap().to_owned();
    let delivery = product.network_started(&message, 1).await;
    product.settled("qa-owner-session-loss").await;
    let before = product.ledger.snapshot("qa-owner-session-loss").await;
    let suspended = ordinary_faults::SuspendedProcess::new(&product).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ordinary_faults::terminate_fixed_owner_session(&product.ledger),
    )
    .await
    .expect("fixed owner session fault injection exceeded its bounded window");
    // The DB lock is gone while the old OS process still owns its descriptor.
    // A successful second process here would be a genuine dual-owner defect.
    product.assert_second_owner_rejected(false).await;
    drop(suspended);
    let exit = product.failed_exit().await;
    assert!(
        product
            .logs()
            .contains("fixed product database owner session lost")
    );
    assert_eq!(
        product.ledger.snapshot("qa-owner-session-loss").await,
        before
    );
    product.restart().await;
    assert_eq!(
        product.post_ok("/message", &input).await["data"]["message_id"],
        message
    );
    assert_eq!(
        product.ledger.snapshot("qa-owner-session-loss").await,
        before
    );
    let pulled = product
        .post_ok(
            "/v2/messages/pull",
            &json!({"device_key":key,"delivery_id":delivery}),
        )
        .await;
    assert_eq!(pulled["data"]["items"][0]["payload"]["body"], input["body"]);
    assert_eq!(
        product
            .post_ok(
                "/v2/messages/ack",
                &json!({"device_key":key,"delivery_ids":[delivery]})
            )
            .await["data"]["removed_count"],
        1
    );
    product.ledger.assert_capacity_released().await;
    product.ledger.assert_no_legacy_ordinary_writes().await;
    product.evidence(&json!({
        "normal_binary":env!("CARGO_BIN_EXE_pushgo-gateway"),"qa_feature":true,
        "injected_fault":"terminate fixed native owner session while this test's Gateway child is SIGSTOP paused",
        "live_old_process_takeover_rejected":true,"owner_failure_exit_code":exit.code(),
        "restart_identity_and_body_preserved":true,"final_ack_capacity_released":true,
        "real_provider_network":false,"client_storage":false,
    }));
}

async fn sql_lock_recovery(external: Option<ProductLedger>) {
    let mut product = ProductProcess::spawn(external).await;
    product.assert_second_owner_rejected(true).await;
    let (key, channel) = product.register_channel().await;
    let input = json!({
        "channel_id":channel,"password":PASSWORD,"op_id":"qa-locked-receipt",
        "title":"real database receipt failure","body":"body must survive failed COMMIT",
        "ttl":chrono::Utc::now().timestamp_millis()+300_000,
    });
    let accepted = product.post_ok("/message", &input).await;
    let message = accepted["data"]["message_id"].as_str().unwrap().to_owned();
    let delivery = product.network_started(&message, 1).await;
    assert_eq!(
        target_state(&product.ledger, &delivery).await,
        ("running".into(), None, None)
    );
    let before = product.ledger.snapshot("qa-locked-receipt").await;
    assert!(before.body_length > 0);

    // The external substitute already owns the request. Block the actual SQL
    // receipt write until its native three-second timeout, without killing the
    // Gateway or cancelling the network attempt from the test harness.
    let block = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        WriteBlock::acquire(&product.ledger),
    )
    .await
    .expect("receipt SQL lock acquisition exceeded its bounded window");
    assert_eq!(
        target_state(&product.ledger, &delivery).await,
        ("running".into(), None, None),
        "fault injection missed receipt window before the SQL lock became held",
    );
    let exit = product.failed_exit().await;
    assert_eq!(
        target_state(&product.ledger, &delivery).await,
        ("running".into(), None, None)
    );
    assert_eq!(product.ledger.snapshot("qa-locked-receipt").await, before);
    let unavailable = product
        .client
        .post(format!("{}/message", product.base))
        .bearer_auth(AUTH)
        .json(&input)
        .send()
        .await;
    assert!(
        unavailable.is_err(),
        "failed normal process continued accepting HTTP"
    );
    let stopped_calls = product.records().len();
    assert_eq!(
        stopped_calls, 1,
        "no new claim may send after receipt failure"
    );
    block.release().await;

    product.restart().await;
    assert_eq!(
        product.post_ok("/message", &input).await["data"]["message_id"],
        message
    );
    assert_eq!(product.network_started(&message, 2).await, delivery);
    product.settled("qa-locked-receipt").await;
    assert_eq!(product.ledger.snapshot("qa-locked-receipt").await, before);
    // Let the post-receipt empty claim finish before selecting the ACK path's
    // failure window. A 503 health fence is deliberately not accepted below.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Authenticated ACK really reaches SQL and fails on the same native lock.
    // It cannot release capacity or turn into a successful client receipt.
    let block = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        WriteBlock::acquire(&product.ledger),
    )
    .await
    .expect("ACK SQL lock acquisition exceeded its bounded window");
    let ack = json!({"device_key":key,"delivery_ids":[delivery]});
    let failed_ack = product.post("/v2/messages/ack", &ack).await;
    let ack_status = failed_ack.status().as_u16();
    assert_eq!(
        ack_status, 500,
        "authenticated ACK must reach the blocked SQL write, observed {ack_status}"
    );
    assert_eq!(product.ledger.snapshot("qa-locked-receipt").await, before);
    let (_, receipt, acknowledged) = target_state(&product.ledger, &delivery).await;
    assert!(
        receipt.is_some(),
        "successful Provider receipt must remain durable"
    );
    assert!(
        acknowledged.is_none(),
        "failed ACK prematurely changed terminal state"
    );
    block.release().await;
    // An implementation may fail-stop on a database failure; recovery still
    // retains the same identity and permits exactly one durable ACK removal.
    if product.child.try_wait().unwrap().is_some() {
        product.restart().await;
    }
    let success = product.post_ok("/v2/messages/ack", &ack).await;
    assert_eq!(success["data"]["removed_count"], 1);
    assert_eq!(
        product.post_ok("/v2/messages/ack", &ack).await["data"]["removed_count"],
        0
    );
    assert_eq!(
        product
            .ledger
            .snapshot("qa-locked-receipt")
            .await
            .body_length,
        0
    );
    product.ledger.assert_capacity_released().await;
    product.restart().await;
    assert_eq!(
        product.post_ok("/message", &input).await["data"]["message_id"],
        message
    );
    assert!(
        product
            .post_ok(
                "/v2/messages/pull",
                &json!({"device_key":key,"delivery_id":delivery})
            )
            .await["data"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        product
            .ledger
            .snapshot("qa-locked-receipt")
            .await
            .body_length,
        0
    );
    product.ledger.assert_capacity_released().await;
    product.ledger.assert_no_legacy_ordinary_writes().await;
    product.evidence(&json!({
        "normal_binary":env!("CARGO_BIN_EXE_pushgo-gateway"),"qa_feature":true,
        "injected_fault":"real SQL write lock: SQLite BEGIN IMMEDIATE, PostgreSQL/MySQL ledger_usage FOR UPDATE",
        "receipt_failure_exit_code":exit.code(),"authenticated_sql_ack_failure_http":ack_status,
        "identity_survived":true,"body_survived_failed_receipt_and_ack":true,
        "second_owner_connection_alias_rejected":true,"final_body_bytes":0,
        "external_calls_before_failstop":stopped_calls,"external_calls_final":product.records().len(),
        "real_provider_network":false,"client_storage":false,"power_loss":false,
    }));
}
