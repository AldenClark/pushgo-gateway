use std::sync::Arc;

use axum::http::{HeaderMap, header::HOST};

use super::{
    PRIVATE_WS_SUBPROTOCOL,
    network::{
        ObservedIpScope, PrivateDiagnosticsRequest, PrivateRequestHeaders, ResolvedIpSource,
    },
    runtime::GatewayProfileResponse,
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
}

#[test]
fn gateway_profile_disabled_omits_transport() {
    let response = GatewayProfileResponse::private_disabled();
    assert!(!response.private_channel_enabled);
    assert!(!response.private_enabled);
    assert!(response.transport.is_none());
}

#[test]
fn classify_ip_scope_detects_cgnat() {
    assert_eq!(
        ObservedIpScope::classify("100.64.1.2"),
        ObservedIpScope::CarrierGradeNat
    );
    assert_eq!(
        ObservedIpScope::classify("100.127.255.254"),
        ObservedIpScope::CarrierGradeNat
    );
}

#[test]
fn request_headers_resolve_forwarded_proto() {
    let mut headers = HeaderMap::new();
    headers.insert("forwarded", "for=1.2.3.4;proto=https".parse().unwrap());
    let request = PrivateRequestHeaders::new(&headers);
    assert_eq!(request.forwarded_pair("proto").as_deref(), Some("https"));
    assert_eq!(request.resolved_ip_source(), ResolvedIpSource::Forwarded);
}

#[test]
fn network_observation_collects_proxy_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, "example.com".parse().unwrap());
    headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
    headers.insert("x-forwarded-proto", "https".parse().unwrap());
    let request = PrivateDiagnosticsRequest::new("198.51.100.9:443".parse().unwrap(), &headers);
    let observation = request.observe_network();

    assert_eq!(observation.host.as_deref(), Some("example.com"));
    assert_eq!(observation.x_forwarded_for.as_deref(), Some("203.0.113.8"));
    assert_eq!(observation.forwarded_proto.as_deref(), Some("https"));
    assert!(observation.proxy_detected());
    assert_eq!(
        observation.resolved_ip_source,
        ResolvedIpSource::XForwardedFor
    );
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

#[test]
fn resolved_ip_source_prefers_x_forwarded_for_over_other_headers() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "198.51.100.42".parse().unwrap());
    headers.insert(
        "forwarded",
        "for=198.51.100.43;proto=https".parse().unwrap(),
    );
    headers.insert("x-forwarded-for", "198.51.100.44".parse().unwrap());
    let request = PrivateRequestHeaders::new(&headers);
    assert_eq!(
        request.resolved_ip_source(),
        ResolvedIpSource::XForwardedFor
    );
}
