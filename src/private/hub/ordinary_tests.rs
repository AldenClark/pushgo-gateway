#[cfg(test)]
mod ordinary_private_tests {
    use super::*;

    fn envelope() -> protocol::DeliverEnvelope {
        protocol::DeliverEnvelope {
            delivery_id: "00000000000000000000000000000001".to_owned(),
            payload: Arc::from([1_u8]),
            ordinary: true,
            ordinary_expires_at: Some(i64::MAX),
        }
    }

    #[test]
    fn resume_watermark_keeps_issued_delivery_until_durable_settle() {
        let now = Instant::now();
        let mut state = ResumeState::fresh(now);
        let (seq, envelope) = state.track_outbound(envelope(), now);
        assert_eq!(
            state.ack_up_to(seq, now),
            vec![envelope.delivery_id.clone()]
        );
        assert_eq!(
            state.inflight_snapshot().len(),
            1,
            "client watermark cannot erase an uncommitted ACK capability"
        );
        assert_eq!(
            state.ack_up_to(seq, now),
            vec![envelope.delivery_id.clone()],
            "a failed durable settle must remain retryable"
        );
        assert_eq!(
            state.ack_by_seq(seq, Some(&envelope.delivery_id), now),
            Some(envelope.delivery_id)
        );
        assert!(state.inflight_snapshot().is_empty());
    }

    #[test]
    fn ordinary_retransmission_reuses_issued_sequence_and_shared_body() {
        let now = Instant::now();
        let mut state = ResumeState::fresh(now);
        let first = envelope();
        let body = first.payload.clone();
        let (original, _) = state.track_outbound(first.clone(), now);
        let (replayed, replay) = state.track_outbound(first, now);
        assert_eq!(original, replayed);
        assert_eq!(state.inflight.len(), 1);
        assert!(Arc::ptr_eq(&body, &replay.payload));
    }

    #[test]
    fn ordinary_encoding_preserves_text_and_structured_values() {
        let raw = serde_json::json!({
            "message_id": "stable-id",
            "body": "中文🙂\\\"\n".repeat(1024),
            "metadata": {"negative": -42, "fraction": 1.25, "items": [1, 2, 3]},
            "timestamp": 1792123456789_i64
        });
        let encoded = encode_ordinary_private_payload(&serde_json::to_vec(&raw).unwrap()).unwrap();
        let decoded = protocol::PrivatePayloadEnvelope::decode_postcard(&encoded).unwrap();
        assert_eq!(
            decoded.data.get("message_id").map(String::as_str),
            Some("stable-id")
        );
        assert_eq!(
            decoded.data.get("body"),
            raw.get("body")
                .and_then(|value| value.as_str())
                .map(|value| value.to_owned())
                .as_ref()
        );
        let metadata: serde_json::Value =
            serde_json::from_str(decoded.data.get("metadata").unwrap()).unwrap();
        assert_eq!(metadata, raw["metadata"]);
        assert_eq!(
            decoded.data.get("timestamp").map(String::as_str),
            Some("1792123456789")
        );
    }
}
