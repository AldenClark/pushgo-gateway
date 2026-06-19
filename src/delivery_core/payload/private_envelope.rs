use hashbrown::HashMap;
use serde::Serialize;

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
            data: &'a HashMap<String, String>,
        }

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
