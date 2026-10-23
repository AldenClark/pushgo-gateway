//! Fixed legacy-envelope inspection used only by the forward-cutover guard.
//! Callers page database rows; this function never retains a history window.
pub(crate) fn payload_is_ordinary(bytes: &[u8]) -> Result<bool, serde_json::Error> {
    if bytes.is_empty() {
        return Ok(false);
    }
    if let Some(context) = crate::storage::decode_private_payload_context(bytes) {
        return Ok(context.entity_type.as_deref() == Some("message"));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    Ok(
        value.get("entity_type").and_then(|v| v.as_str()) == Some("message")
            || value
                .pointer("/direct_payload/data/entity_type")
                .and_then(|v| v.as_str())
                == Some("message")
            || value
                .pointer("/wakeup_payload/data/entity_type")
                .and_then(|v| v.as_str())
                == Some("message")
            || value.pointer("/data/entity_type").and_then(|v| v.as_str()) == Some("message")
            || value.pointer("/request/payload/Message").is_some()
            || value.pointer("/payload/Message").is_some(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspects_known_envelopes_without_classifying_user_metadata() {
        for bytes in [
            br#"{"entity_type":"message"}"#.as_slice(),
            br#"{"direct_payload":{"data":{"entity_type":"message"}}}"#.as_slice(),
            br#"{"request":{"payload":{"Message":{"message_id":"stable"}}}}"#.as_slice(),
        ] {
            assert!(payload_is_ordinary(bytes).unwrap());
        }
        assert!(
            !payload_is_ordinary(br#"{"entity_type":"event","metadata":{"Message":{}}}"#).unwrap()
        );
        assert!(!payload_is_ordinary(&[]).unwrap());
        assert!(payload_is_ordinary(b"corrupt").is_err());
    }

    #[test]
    fn classifies_the_normal_postcard_private_envelope() {
        #[derive(serde::Serialize)]
        struct Envelope {
            payload_version: u8,
            data: hashbrown::HashMap<String, String>,
        }
        for kind in ["message", "event", "thing"] {
            let mut data = hashbrown::HashMap::new();
            data.insert("entity_type".to_string(), kind.to_string());
            data.insert("body".to_string(), "保留正文".to_string());
            let bytes = postcard::to_allocvec(&Envelope {
                payload_version: 1,
                data,
            })
            .unwrap();
            assert_eq!(payload_is_ordinary(&bytes).unwrap(), kind == "message");
        }
    }
}
