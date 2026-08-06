#[test]
fn channel_sync_item_ignores_unknown_fields_for_forward_compatibility() {
    let raw = r#"{
        "device_key":"dev-1",
        "channels":[{"channel_id":"abc","password":"12345678","extra":"x"}]
    }"#;
    let parsed = serde_json::from_str::<super::types::ChannelSyncRequest>(raw);
    assert!(
        parsed.is_ok(),
        "channel sync should ignore extension fields"
    );
}
