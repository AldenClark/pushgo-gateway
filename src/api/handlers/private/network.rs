use axum::http::{HeaderMap, header::SEC_WEBSOCKET_PROTOCOL};

pub(super) struct PrivateRequestHeaders<'a> {
    headers: &'a HeaderMap,
}

impl<'a> PrivateRequestHeaders<'a> {
    pub(super) fn new(headers: &'a HeaderMap) -> Self {
        Self { headers }
    }

    pub(super) fn offers_ws_subprotocol(&self, expected: &str) -> bool {
        self.headers
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|raw| raw.to_str().ok())
            .map(|raw| raw.split(',').map(str::trim).any(|value| value == expected))
            .unwrap_or(false)
    }
}
