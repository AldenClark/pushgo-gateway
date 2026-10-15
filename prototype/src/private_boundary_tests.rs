//! Actual serialized ordinary HTTP/canonical/Private frame size oracles.
//! The shared fixed transport frame budget includes type/flags, excluding the stream prefix.
use crate::{Config, MESSAGE_SUBMISSION_BODY_BYTES, OrdinaryStore};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use pushgo_warp_profile::PushgoWireProfile;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use warp_link::warp_link_core::{DeliverMsg, MAX_FRAME_BYTES, WireProfile};

/// Exactly the locked public DeliverV2Frame schema. This test-only serialization
/// measures actual Rust bytes even when the production codec rejects an oversize
/// frame. Small/in-range frames are compared byte-for-byte against that codec.
pub(super) fn actual_deliver_frame(id: &str, payload: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    struct Deliver<'a> {
        seq: u64,
        delivery_id: &'a str,
        payload: &'a [u8],
    }
    let profile = PushgoWireProfile::new();
    let header = profile
        .encode_server_deliver(&DeliverMsg {
            seq: Some(1),
            id: id.into(),
            payload: bytes::Bytes::new(),
        })
        .unwrap();
    let mut frame = header[..2].to_vec();
    frame.extend(
        postcard::to_allocvec(&Deliver {
            seq: 1,
            delivery_id: id,
            payload,
        })
        .unwrap(),
    );
    if frame.len() <= MAX_FRAME_BYTES {
        assert_eq!(
            profile
                .encode_server_deliver(&DeliverMsg {
                    seq: Some(1),
                    id: id.into(),
                    payload: bytes::Bytes::copy_from_slice(payload)
                })
                .unwrap(),
            frame
        );
    }
    frame
}

/// Serialize the actual legal request instead of deriving per-field wire limits.
pub(super) fn legal_http_input(channel: &str, password: &str, kind: &str) -> Vec<u8> {
    legal_http_input_at_size(channel, password, kind, MESSAGE_SUBMISSION_BODY_BYTES)
}

pub(super) fn legal_http_input_at_size(
    channel: &str,
    password: &str,
    kind: &str,
    input_bytes: usize,
) -> Vec<u8> {
    let mut request = json!({"channel_id":channel,"password":password,"title":"x","body":"","op_id":"private-wire-boundary"});
    if matches!(
        kind,
        "numeric-metadata" | "negative-metadata" | "float-metadata"
    ) {
        request["metadata"] = json!(null);
        let base = serde_json::to_string(&request).unwrap();
        let mut entries = Vec::new();
        loop {
            let literal = match kind {
                "negative-metadata" => "-1e15",
                "float-metadata" => {
                    ["1e15", "-1e15", "1e-6", "-0.0", "1.2345678901234567e12"][entries.len() % 5]
                }
                _ => "1e15",
            };
            let entry = format!("\"{:x}\":{literal}", entries.len());
            entries.push(entry);
            let candidate = base.replace(
                "\"metadata\":null",
                &format!("\"metadata\":{{{}}}", entries.join(",")),
            );
            if candidate.len() > input_bytes {
                entries.pop();
                break;
            }
        }
        let raw = base.replace(
            "\"metadata\":null",
            &format!("\"metadata\":{{{}}}", entries.join(",")),
        );
        let padding = "x".repeat(input_bytes - raw.len());
        let raw = raw.replace("\"body\":\"\"", &format!("\"body\":\"{padding}\""));
        assert_eq!(raw.len(), input_bytes);
        return raw.into_bytes();
    }
    let pattern = match kind {
        "text" => "x",
        "chinese" => "中文",
        "unicode" => "🙂𝄞é中",
        "escape" => "\"\\\n\t",
        _ => panic!("unknown boundary fixture"),
    };
    let mut repeats = 0;
    loop {
        request["body"] = json!(pattern.repeat(repeats + 128));
        if serde_json::to_vec(&request).unwrap().len() > input_bytes {
            break;
        }
        repeats += 128;
    }
    request["body"] = json!(pattern.repeat(repeats));
    let remainder = input_bytes - serde_json::to_vec(&request).unwrap().len();
    request["body"] = json!(format!(
        "{}{}",
        pattern.repeat(repeats),
        "x".repeat(remainder)
    ));
    let raw = serde_json::to_vec(&request).unwrap();
    assert_eq!(raw.len(), input_bytes);
    raw
}

async fn admitted_size(kind: &str) {
    admitted_size_at(kind, MESSAGE_SUBMISSION_BODY_BYTES).await;
}

async fn admitted_size_at(kind: &str, input_bytes: usize) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.private.enabled = true;
    let (store, owner) = OrdinaryStore::open(
        &format!("sqlite://{}", dir.path().join("size.sqlite").display()),
        config,
    )
    .await
    .unwrap();
    let device = store.register("android").await.unwrap();
    let password = crate::types::generate_hex_id_128();
    let channel = store
        .subscribe(&device, None, Some("wire boundary"), &password)
        .await
        .unwrap()["channel_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let input = legal_http_input_at_size(&channel, &password, kind, input_bytes);
    let input_hash = blake3::hash(&input).to_hex().to_string();
    let expected: serde_json::Value = serde_json::from_slice(&input).unwrap();
    let app = crate::router(store.clone(), Arc::new(|| json!({})));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/message")
                .header("content-type", "application/json")
                .body(Body::from(input))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "legal {kind} HTTP input must stay accepted"
    );
    let accepted: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let route = store.private_route(&device).await.unwrap();
    let ticket = store
        .private_claim(&route, "boundary", 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        ticket.delivery_id,
        accepted["data"]["delivery_id"].as_str().unwrap()
    );
    let payload = crate::private_runtime::encode_payload(&ticket.payload).unwrap();
    let frame = actual_deliver_frame(&ticket.delivery_id, &payload);
    let decoded: pushgo_warp_profile::PrivatePayloadEnvelope =
        postcard::from_bytes(&payload).unwrap();
    assert_eq!(
        decoded.data["body"],
        expected["body"].as_str().unwrap().trim()
    );
    if let Some(metadata) = expected.get("metadata") {
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&decoded.data["metadata"]).unwrap(),
            *metadata
        );
    }
    println!(
        "C8_LEGAL_HTTP_FRAME {}",
        json!({"case":kind,"input_blake3":input_hash,"http_bytes":input_bytes,"canonical_bytes":ticket.payload.len(),"complete_frame_bytes":frame.len(),"fixed_frame_limit":MAX_FRAME_BYTES,"accepted_delivery_id":ticket.delivery_id,"canonical_message_id":decoded.data["message_id"]})
    );
    let mqtt_packet =
        crate::private_mqtt::encoded_delivery_packet_for_test(&ticket.delivery_id, &payload).await;
    println!(
        "C8_LEGAL_HTTP_MQTT {}",
        json!({"case":kind,"input_blake3":input_hash,"http_bytes":input_bytes,"complete_mqtt_packet_bytes":mqtt_packet.len(),"shared_frame_limit":MAX_FRAME_BYTES})
    );
    assert!(
        mqtt_packet.len() <= MAX_FRAME_BYTES,
        "actual production MQTT packet exceeds shared fixed frame limit"
    );
    // No rejection or payload rewrite is introduced. If a real legal sample
    // exceeds the shared fixed budget this preserves its exact generator/hash/bytes.
    store
        .private_release(&ticket.group_id, std::slice::from_ref(&ticket.claim_token))
        .await
        .unwrap();
    store.close().await;
    owner.release();
    assert!(
        frame.len() <= MAX_FRAME_BYTES,
        "legal {kind} sample {input_hash}: actual complete frame {} exceeds shared fixed limit {}",
        frame.len(),
        MAX_FRAME_BYTES
    );
}
#[tokio::test]
async fn legal_http_text_fits_complete_private_frame() {
    admitted_size("text").await;
}
#[tokio::test]
async fn legal_http_chinese_fits_complete_private_frame() {
    admitted_size("chinese").await;
}
#[tokio::test]
async fn legal_http_escape_fits_complete_private_frame() {
    admitted_size("escape").await;
}
#[tokio::test]
async fn legal_http_numeric_metadata_measures_complete_private_frame() {
    admitted_size("numeric-metadata").await;
}

#[tokio::test]
async fn legal_http_unicode_fits_complete_private_frame() {
    admitted_size("unicode").await;
}

#[tokio::test]
async fn legal_http_negative_metadata_fits_complete_private_frame() {
    admitted_size("negative-metadata").await;
}

#[tokio::test]
async fn legal_http_float_metadata_fits_complete_private_frame() {
    admitted_size("float-metadata").await;
}

#[tokio::test]
async fn former_32k_legal_http_request_remains_deliverable() {
    admitted_size_at("text", 32 * 1024).await;
}

#[test]
fn ordinary_text_chinese_escape_complete_frame_at_and_above_shared_fixed_limit() {
    for pattern in ["x", "中文", "🙂𝄞é中", "\"\\\n\t"] {
        let frame_for = |body: &str| {
            let canonical = serde_json::to_vec(
                &json!({"entity_type":"message","title":"boundary","body":body}),
            )
            .unwrap();
            let payload = crate::private_runtime::encode_payload(&canonical).unwrap();
            (
                actual_deliver_frame("0123456789abcdef0123456789abcdef", &payload),
                payload,
            )
        };
        let mut low = 0;
        let mut high = MAX_FRAME_BYTES;
        while low < high {
            let middle = (low + high + 1) / 2;
            if frame_for(&pattern.repeat(middle)).0.len() <= MAX_FRAME_BYTES {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let mut body = pattern.repeat(low);
        // Fill only the final few bytes after actual serialized-size search.
        let remaining = MAX_FRAME_BYTES - frame_for(&body).0.len();
        body.push_str(&"x".repeat(remaining));
        let (frame, payload) = frame_for(&body);
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
        let decoded: pushgo_warp_profile::PrivatePayloadEnvelope =
            postcard::from_bytes(&payload).unwrap();
        assert_eq!(decoded.data["body"], body);
        let mut oversized = body.clone();
        oversized.push('x');
        let (over, payload) = frame_for(&oversized);
        assert_eq!(over.len(), MAX_FRAME_BYTES + 1);
        assert!(
            PushgoWireProfile::new()
                .encode_server_deliver(&DeliverMsg {
                    seq: Some(1),
                    id: "0123456789abcdef0123456789abcdef".into(),
                    payload: bytes::Bytes::from(payload)
                })
                .is_err(),
            "transport rejects full frame one byte above shared fixed limit {}, not legal HTTP admission",
            MAX_FRAME_BYTES
        );
    }
}
