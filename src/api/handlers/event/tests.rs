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
