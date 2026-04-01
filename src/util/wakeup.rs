use hashbrown::HashMap;

pub fn build_wakeup_data(base: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in [
        "delivery_id",
        "channel_id",
        "entity_type",
        "entity_id",
        "message_id",
        "event_id",
        "thing_id",
        "op_id",
        "sent_at",
        "ttl",
        "schema_version",
        "payload_version",
    ] {
        if let Some(value) = base.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    out.insert("private_mode".to_string(), "wakeup".to_string());
    out.insert("private_wakeup".to_string(), "1".to_string());
    out.insert("_skip_persist".to_string(), "1".to_string());
    out
}
