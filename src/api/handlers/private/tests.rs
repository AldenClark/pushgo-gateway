use std::sync::Arc;

use axum::http::HeaderMap;

use super::{
    PRIVATE_WS_SUBPROTOCOL, network::PrivateRequestHeaders, runtime::GatewayProfileResponse,
};
use crate::app::PrivateTransportProfile;

#[test]
fn transport_hints_returns_profile_capabilities() {
    let profile = PrivateTransportProfile {
        quic_enabled: true,
        quic_port: Some(8443),
        tcp_enabled: true,
        tcp_port: 5223,
        wss_enabled: true,
        wss_port: 443,
        wss_path: Arc::from("/private/ws"),
        ws_subprotocol: Arc::from(PRIVATE_WS_SUBPROTOCOL),
        mqtt_enabled: true,
        mqtt_port: Some(1883),
        mqtt_tls_required: true,
    };

    let hints = profile.hints(Some("https://sandbox.pushgo.dev"));
    assert!(hints.quic_enabled);
    assert_eq!(hints.quic_port, Some(8443));
    assert!(hints.tcp_enabled);
    assert_eq!(hints.tcp_port, 5223);
    assert!(hints.wss_enabled);
    assert_eq!(hints.wss_port, 443);
    assert_eq!(hints.wss_path, "/private/ws");
    assert_eq!(
        hints.wss_url.as_deref(),
        Some("wss://sandbox.pushgo.dev/private/ws")
    );
    assert_eq!(hints.ws_subprotocol, PRIVATE_WS_SUBPROTOCOL);
    assert!(hints.mqtt_enabled);
    assert_eq!(hints.mqtt_port, Some(1883));
    assert!(hints.mqtt_tls_required);
    assert_eq!(hints.mqtt_protocol, "mqtt5");
    assert_eq!(hints.mqtt_qos, 1);
    assert_eq!(hints.mqtt_topic_template, "{channel_id}");
}

#[test]
fn gateway_profile_disabled_omits_transport() {
    let response = GatewayProfileResponse::private_disabled();
    assert!(!response.private_channel_enabled);
    assert!(!response.private_enabled);
    assert!(response.transport.is_none());
}

#[test]
fn offers_ws_subprotocol_matches_csv_entries() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "sec-websocket-protocol",
        "other-proto, pushgo-private.v1, final-proto"
            .parse()
            .unwrap(),
    );
    let request = PrivateRequestHeaders::new(&headers);
    assert!(request.offers_ws_subprotocol(PRIVATE_WS_SUBPROTOCOL));
    assert!(!request.offers_ws_subprotocol("missing-proto"));
}
