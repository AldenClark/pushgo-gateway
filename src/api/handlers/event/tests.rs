use super::{EventCreateRequest, EventUpdateRequest};

#[test]
fn event_create_rejects_event_id_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "event_id":"should-not-exist",
        "title":"t",
        "status":"open",
        "message":"m",
        "severity":"normal"
    }"#;
    let parsed = serde_json::from_str::<EventCreateRequest>(raw);
    assert!(
        parsed.is_err(),
        "event create should reject event_id in payload"
    );
}

#[test]
fn event_create_accepts_optional_thing_id() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "thing_id":"thing-in-body",
        "title":"t",
        "status":"open",
        "message":"m",
        "severity":"normal"
    }"#;
    let parsed = serde_json::from_str::<EventCreateRequest>(raw);
    assert!(
        parsed.is_ok(),
        "event create should accept optional thing_id in body"
    );
}

#[test]
fn event_update_accepts_expected_fields() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "event_id":"evt-1",
        "status":"open",
        "message":"m",
        "severity":"normal"
    }"#;
    let parsed = serde_json::from_str::<EventUpdateRequest>(raw);
    assert!(parsed.is_ok(), "event update should parse valid payload");
}

#[test]
fn event_create_accepts_missing_op_id() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "title":"t",
        "status":"open",
        "message":"m",
        "severity":"normal"
    }"#;
    let parsed = serde_json::from_str::<EventCreateRequest>(raw);
    assert!(parsed.is_ok(), "event create should accept missing op_id");
}

#[test]
fn event_create_normalizes_timestamps_to_millis() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "title":"t",
        "status":"open",
        "message":"m",
        "severity":"normal",
        "event_time":1710000000123,
        "started_at":"1710000000456",
        "ended_at":1710000000789
    }"#;
    let parsed =
        serde_json::from_str::<EventCreateRequest>(raw).expect("event create should parse payload");
    assert_eq!(parsed.payload.event_time, Some(1_710_000_000_123));
    assert_eq!(parsed.payload.started_at, Some(1_710_000_000_456));
    assert_eq!(parsed.payload.ended_at, Some(1_710_000_000_789));
}
