use hashbrown::HashMap;
use serde_json::Map as JsonMap;

use crate::{dispatch::ProviderDeliveryPath, storage::Platform};

use super::{
    MessageIntent,
    ids::{OpId, wakeup_data_with_delivery_id},
    payload::{
        CustomPayloadData, EntityKind, OptionalText, PayloadSeverity, ProviderDeliverySelection,
        StandardFields,
    },
};

#[test]
fn wakeup_pull_requires_available_wakeup_path() {
    let selection = ProviderDeliverySelection::resolve(Platform::ANDROID, 5_000, 1_000, false);
    assert!(selection.is_err());
}

#[test]
fn wakeup_pull_selected_when_direct_too_large_and_available() {
    let selection = ProviderDeliverySelection::resolve(Platform::ANDROID, 5_000, 1_000, true)
        .expect("wakeup pull should be selected");
    assert_eq!(selection.initial_path, ProviderDeliveryPath::WakeupPull);
    assert!(selection.wakeup_payload_within_limit);
}

#[test]
fn message_intent_accepts_markdown_link_body() {
    let body = "[https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV](https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV)\n\n无论可以玩玩。有上千个，\n\n\n\n[原文链接](https://www.v2ex.com/t/1200790)";
    let intent = MessageIntent {
        channel_id: "06J0FZG1Y8XGG14VTQ4Y3G10MR".to_string(),
        password: "pass-123".to_string(),
        op_id: Some("op-123".to_string()),
        thing_id: None,
        occurred_at: Some(1_710_000_000),
        title: "sample".to_string(),
        body: Some(body.to_string()),
        severity: None,
        ttl: None,
        url: None,
        images: Vec::new(),
        ciphertext: None,
        tags: Vec::new(),
        metadata: JsonMap::new(),
    };
    intent
        .validate_payload()
        .expect("markdown body should pass validation");
}

#[test]
fn add_standard_fields_keeps_markdown_link_body() {
    let body = "[https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV](https://sway.cloud.microsoft/lNjlqkdUA7wtAxfV)\n\n无论可以玩玩。有上千个，\n\n\n\n[原文链接](https://www.v2ex.com/t/1200790)";
    let mut data = HashMap::new();
    StandardFields {
        channel_id: "06J0FZG1Y8XGG14VTQ4Y3G10MR",
        title: Some("sample"),
        body: Some(body),
        severity: None,
        schema_version: "1",
        payload_version: "1",
        op_id: "op-123",
        delivery_id: "d-123",
        ingested_at: 1_710_000_001,
        occurred_at: 1_710_000_000,
        sent_at: 1_710_000_000,
        ttl: None,
        entity_type: "message",
        entity_id: "m-123",
    }
    .apply_to(&mut data);
    assert_eq!(data.get("body"), Some(&body.to_string()));
}

#[test]
fn resolve_op_id_uses_provided_value() {
    let resolved = OpId::resolve(Some("provided-op-id")).expect("op_id should be accepted");
    assert_eq!(resolved.into_inner(), "provided-op-id");
}

#[test]
fn resolve_op_id_generates_when_absent() {
    let resolved = OpId::resolve(None).expect("op_id should be generated");
    let resolved = resolved.into_inner();
    assert_eq!(resolved.len(), 32);
    assert!(resolved.chars().all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn provider_payload_limit_boundary_matches_platform_rules() {
    assert!(ProviderDeliverySelection::within_platform_limit(
        Platform::ANDROID,
        4096
    ));
    assert!(!ProviderDeliverySelection::within_platform_limit(
        Platform::ANDROID,
        4097
    ));
    assert!(ProviderDeliverySelection::within_platform_limit(
        Platform::IOS,
        4096
    ));
    assert!(!ProviderDeliverySelection::within_platform_limit(
        Platform::IOS,
        4097
    ));

    assert!(ProviderDeliverySelection::within_platform_limit(
        Platform::WINDOWS,
        5119
    ));
    assert!(!ProviderDeliverySelection::within_platform_limit(
        Platform::WINDOWS,
        5120
    ));
}

#[test]
fn payload_severity_normalizes_to_known_levels() {
    assert_eq!(
        PayloadSeverity::normalize(Some("HIGH".to_string())),
        PayloadSeverity::High
    );
    assert_eq!(
        PayloadSeverity::normalize(Some(" critical ".to_string())),
        PayloadSeverity::Critical
    );
    assert_eq!(
        PayloadSeverity::normalize(Some("unknown".to_string())),
        PayloadSeverity::Normal
    );
    assert_eq!(PayloadSeverity::Normal.fcm_priority(), "HIGH");
    assert_eq!(PayloadSeverity::Low.fcm_priority(), "NORMAL");
    assert_eq!(PayloadSeverity::Critical.fcm_priority(), "HIGH");
}

#[test]
fn optional_text_trims_and_drops_blank_values() {
    assert_eq!(
        OptionalText::normalize_owned(Some("  body  ".to_string())),
        Some("body".to_string())
    );
    assert_eq!(OptionalText::normalize_owned(Some("   ".to_string())), None);
    assert_eq!(OptionalText::normalize_owned(None), None);
}

#[test]
fn custom_payload_data_sanitizes_reserved_fields() {
    let mut raw = HashMap::new();
    raw.insert("title".to_string(), "shadow".to_string());
    raw.insert("body".to_string(), "shadow".to_string());
    raw.insert("custom".to_string(), "value".to_string());

    let payload = CustomPayloadData::new(raw).into_shared();
    assert_eq!(payload.get("custom"), Some(&"value".to_string()));
    assert!(!payload.contains_key("title"));
    assert!(!payload.contains_key("body"));
}

#[test]
fn custom_payload_prepare_dispatch_builds_thread_id_and_wakeup_data() {
    let mut raw = HashMap::new();
    raw.insert("custom".to_string(), "value".to_string());

    let mut payload = CustomPayloadData::new(raw);
    payload.insert_extra_fields(HashMap::from([
        ("event_id".to_string(), "event-1".to_string()),
        ("thing_id".to_string(), "thing-1".to_string()),
    ]));
    let prepared = payload
        .prepare_dispatch("channel-1", EntityKind::new("thing"))
        .expect("payload should encode");

    assert_eq!(
        prepared.apple_thread_id.into_inner(),
        "thing|channel=channel-1|event=event-1|thing=thing-1"
    );
    assert_eq!(
        prepared
            .wakeup_data
            .into_inner()
            .get("provider_mode")
            .map(String::as_str),
        Some("wakeup")
    );
    assert!(prepared.private_payload.into_inner().len() > 1);
    assert_eq!(
        prepared.custom_data.get("custom").map(String::as_str),
        Some("value")
    );
}

#[test]
fn custom_payload_prepare_dispatch_includes_gateway_base_url_in_wakeup_data() {
    let mut payload = CustomPayloadData::new(HashMap::new());
    payload.apply_gateway_base_url(Some(" https://sandbox.pushgo.dev/ "));
    let prepared = payload
        .prepare_dispatch("channel-1", EntityKind::new("message"))
        .expect("payload should encode");

    assert_eq!(
        prepared
            .wakeup_data
            .into_inner()
            .get("base_url")
            .map(String::as_str),
        Some("https://sandbox.pushgo.dev")
    );
}

#[test]
fn provider_pull_delivery_id_reuses_dispatch_delivery_id() {
    let wakeup = wakeup_data_with_delivery_id(&HashMap::new(), "base-delivery");
    assert_eq!(
        wakeup.get("delivery_id").map(String::as_str),
        Some("base-delivery")
    );
}

#[test]
fn provider_pull_delivery_id_is_not_device_derived() {
    let first = wakeup_data_with_delivery_id(&HashMap::new(), "delivery-fixed");
    let second = wakeup_data_with_delivery_id(&HashMap::new(), "delivery-fixed");
    assert_eq!(first, second);
}

#[test]
fn message_intent_normalizes_occurred_at_to_millis() {
    let raw = r#"{
        "channel_id":"06J0FZG1Y8XGG14VTQ4Y3G10MR",
        "password":"pass-123",
        "title":"sample",
        "occurred_at":"1710000000123"
    }"#;
    let parsed = serde_json::from_str::<MessageIntent>(raw).expect("message intent should parse");
    assert_eq!(parsed.occurred_at, Some(1_710_000_000_123));
}
