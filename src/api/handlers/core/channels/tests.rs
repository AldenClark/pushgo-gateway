#[test]
fn channel_sync_item_rejects_unknown_fields() {
    let raw = r#"{
        "device_key":"dev-1",
        "channels":[{"channel_id":"abc","password":"12345678","extra":"x"}]
    }"#;
    let parsed = serde_json::from_str::<super::types::ChannelSyncRequest>(raw);
    assert!(
        parsed.is_err(),
        "channel sync item should reject unknown fields"
    );
}
