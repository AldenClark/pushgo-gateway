use super::*;

#[test]
fn decode_private_payload_context_extracts_structured_fields() {
    let mut data = hashbrown::HashMap::new();
    data.insert("channel_id", "06J0FZG1Y8XGG14VTQ4Y3G10MR");
    data.insert("entity_type", "event");
    data.insert("entity_id", "evt-1");
    data.insert("op_id", "op-1");
    let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("payload encode should succeed");

    let context = PrivatePayloadContext::decode(&payload).expect("context decode should succeed");
    assert!(context.channel_id.is_some());
    assert_eq!(context.entity_type.as_deref(), Some("event"));
    assert_eq!(context.entity_id.as_deref(), Some("evt-1"));
    assert_eq!(context.op_id.as_deref(), Some("op-1"));
}

#[test]
fn decode_private_payload_context_rejects_unknown_payload_version() {
    let mut data = hashbrown::HashMap::new();
    data.insert("channel_id", "06J0FZG1Y8XGG14VTQ4Y3G10MR");
    let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 9,
        data,
    })
    .expect("payload encode should succeed");
    assert!(PrivatePayloadContext::decode(&payload).is_none());
}

#[test]
fn normalize_delivery_audit_path_and_status_defaults() {
    assert_eq!(
        DeliveryAuditPath::parse_lossy("provider"),
        DeliveryAuditPath::Provider
    );
    assert_eq!(
        DeliveryAuditPath::parse_lossy("DIRECT"),
        DeliveryAuditPath::Direct
    );
    assert_eq!(
        DeliveryAuditPath::parse_lossy("invalid-path"),
        DeliveryAuditPath::Provider
    );

    assert_eq!(
        DeliveryAuditStatus::parse_lossy("enqueued"),
        DeliveryAuditStatus::Enqueued
    );
    assert_eq!(
        DeliveryAuditStatus::parse_lossy("SKIPPED_PRIVATE_REALTIME"),
        DeliveryAuditStatus::SkippedPrivateRealtime
    );
    assert_eq!(
        DeliveryAuditStatus::parse_lossy("unknown-status"),
        DeliveryAuditStatus::EnqueueFailed
    );
}

#[test]
fn normalize_delivery_audit_error_code_truncates_and_trims() {
    let blank = DeliveryAuditWrite {
        delivery_id: "delivery-blank".to_string(),
        channel_id: [0; 16],
        device_key: "device-blank".to_string(),
        entity_type: None,
        entity_id: None,
        op_id: None,
        path: DeliveryAuditPath::Provider,
        status: DeliveryAuditStatus::Enqueued,
        error_code: Some("  ".to_string()),
        created_at: 0,
    };
    assert_eq!(blank.normalized().error_code, None);
    let queue_full = DeliveryAuditWrite {
        error_code: Some(" queue_full ".to_string()),
        ..blank.clone()
    };
    assert_eq!(
        queue_full.normalized().error_code.as_deref(),
        Some("queue_full")
    );
    let long = DeliveryAuditWrite {
        error_code: Some("x".repeat(128)),
        ..blank
    };
    let normalized = long
        .normalized()
        .error_code
        .expect("normalized error code should be present");
    assert_eq!(normalized.len(), 64);
}
