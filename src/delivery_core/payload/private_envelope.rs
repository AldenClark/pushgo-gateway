use hashbrown::HashMap;
use serde::Serialize;
use std::collections::BTreeMap;

pub(crate) const PAYLOAD_VERSION_NUMERIC: u8 = 1;

pub(crate) struct PrivateEnvelopeEncoder;

pub(crate) struct EncodedPrivatePayload(pub(crate) Vec<u8>);

impl PrivateEnvelopeEncoder {
    pub(crate) fn encode(data: HashMap<String, String>) -> Result<Vec<u8>, postcard::Error> {
        Self::encode_ref(&data).map(EncodedPrivatePayload::into_inner)
    }

    pub(crate) fn encode_ref(
        data: &HashMap<String, String>,
    ) -> Result<EncodedPrivatePayload, postcard::Error> {
        #[derive(Serialize)]
        struct BorrowedPayloadEnvelope<'a> {
            payload_version: u8,
            data: BTreeMap<&'a str, &'a str>,
        }

        let data = data
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();

        postcard::to_allocvec(&BorrowedPayloadEnvelope {
            payload_version: PAYLOAD_VERSION_NUMERIC,
            data,
        })
        .map(EncodedPrivatePayload)
    }
}

impl EncodedPrivatePayload {
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct DecodedEnvelope {
        payload_version: u8,
        data: HashMap<String, String>,
    }

    #[test]
    fn private_envelope_encoding_is_independent_of_hash_map_insertion_order() {
        let first = HashMap::from([
            ("z-last".to_string(), "three".to_string()),
            ("a-first".to_string(), "one".to_string()),
            ("m-middle".to_string(), "two".to_string()),
        ]);
        let mut second = HashMap::new();
        second.insert("m-middle".to_string(), "two".to_string());
        second.insert("z-last".to_string(), "three".to_string());
        second.insert("a-first".to_string(), "one".to_string());

        let first = PrivateEnvelopeEncoder::encode(first).expect("first payload should encode");
        let second = PrivateEnvelopeEncoder::encode(second).expect("second payload should encode");

        assert_eq!(first, second);
        let decoded: DecodedEnvelope = postcard::from_bytes(&first)
            .expect("sorted map encoding must keep the existing postcard wire shape");
        assert_eq!(decoded.payload_version, PAYLOAD_VERSION_NUMERIC);
        assert_eq!(decoded.data.len(), 3);
    }
}
