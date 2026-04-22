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
