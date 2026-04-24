use super::{ThingArchiveRequest, ThingCreateRequest, ThingDeleteRequest, ThingUpdateRequest};

#[test]
fn thing_create_rejects_thing_id_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "thing_id":"should-not-exist",
        "title":"name"
    }"#;
    let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
    assert!(
        parsed.is_err(),
        "thing create should reject thing_id in payload"
    );
}

#[test]
fn thing_archive_rejects_state_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "thing_id":"thing-1",
        "state":"deleted"
    }"#;
    let parsed = serde_json::from_str::<ThingArchiveRequest>(raw);
    assert!(parsed.is_err(), "thing archive should reject state field");
}

#[test]
fn thing_create_rejects_state_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "state":"deleted"
    }"#;
    let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
    assert!(parsed.is_err(), "thing create should reject state field");
}

#[test]
fn thing_update_rejects_state_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "thing_id":"thing-1",
        "state":"archived"
    }"#;
    let parsed = serde_json::from_str::<ThingUpdateRequest>(raw);
    assert!(parsed.is_err(), "thing update should reject state field");
}

#[test]
fn thing_create_rejects_deleted_at_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "deleted_at":123
    }"#;
    let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
    assert!(
        parsed.is_err(),
        "thing create should reject deleted_at field"
    );
}

#[test]
fn thing_update_rejects_deleted_at_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "thing_id":"thing-1",
        "deleted_at":123
    }"#;
    let parsed = serde_json::from_str::<ThingUpdateRequest>(raw);
    assert!(
        parsed.is_err(),
        "thing update should reject deleted_at field"
    );
}

#[test]
fn thing_delete_accepts_deleted_at_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "op_id":"op-1",
        "thing_id":"thing-1",
        "deleted_at":123
    }"#;
    let parsed = serde_json::from_str::<ThingDeleteRequest>(raw);
    assert!(parsed.is_ok(), "thing delete should accept deleted_at");
}

#[test]
fn thing_create_accepts_missing_op_id() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "title":"name"
    }"#;
    let parsed = serde_json::from_str::<ThingCreateRequest>(raw);
    assert!(parsed.is_ok(), "thing create should accept missing op_id");
}

#[test]
fn thing_create_normalizes_timestamps_to_millis() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "title":"name",
        "created_at":"1710000000123",
        "observed_at":1710000000456
    }"#;
    let parsed =
        serde_json::from_str::<ThingCreateRequest>(raw).expect("thing create should parse payload");
    assert_eq!(parsed.created_at, Some(1_710_000_000_123));
    assert_eq!(parsed.payload.observed_at, Some(1_710_000_000_456));
}

#[test]
fn thing_delete_normalizes_deleted_at_to_millis() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "thing_id":"thing-1",
        "deleted_at":1710000000789,
        "observed_at":"1710000000999"
    }"#;
    let parsed =
        serde_json::from_str::<ThingDeleteRequest>(raw).expect("thing delete should parse payload");
    assert_eq!(parsed.deleted_at, Some(1_710_000_000_789));
    assert_eq!(parsed.payload.observed_at, Some(1_710_000_000_999));
}

#[test]
fn thing_create_accepts_ciphertext_field() {
    let raw = r#"{
        "channel_id":"AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "password":"12345678",
        "observed_at":1710000000999,
        "ciphertext":"encrypted-payload"
    }"#;
    let parsed =
        serde_json::from_str::<ThingCreateRequest>(raw).expect("thing create should parse payload");
    assert_eq!(
        parsed.payload.ciphertext.as_deref(),
        Some("encrypted-payload")
    );
}
