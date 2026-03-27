use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{State, connect_info::ConnectInfo, ws::WebSocketUpgrade},
    http::{
        HeaderMap, StatusCode,
        header::{HOST, HeaderName, SEC_WEBSOCKET_PROTOCOL},
    },
    response::IntoResponse,
};
use serde::Serialize;

use crate::{
    api::HttpResult,
    app::{AppState, PrivateTransportProfile},
};

const PRIVATE_WS_SUBPROTOCOL: &str = "pushgo-private.v1";
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

#[derive(Debug, Serialize)]
struct PrivateMetricsResponse {
    private_enabled: bool,
    metrics: crate::private::metrics::PrivateMetricsSnapshot,
}

#[derive(Debug, Serialize)]
struct PrivateNetworkDiagnosticsResponse {
    private_enabled: bool,
    observed_client_ip: Option<String>,
    peer_ip: String,
    resolved_ip_source: &'static str,
    proxy_detected: bool,
    observed_ip_scope: &'static str,
    nat_hint: &'static str,
    host: Option<String>,
    forwarded_proto: Option<String>,
    x_forwarded_for: Option<String>,
    x_real_ip: Option<String>,
    forwarded: Option<String>,
    transport_hints: PrivateTransportHints,
}

#[derive(Debug, Serialize)]
struct PrivateTransportHints {
    quic_enabled: bool,
    quic_port: Option<u16>,
    tcp_enabled: bool,
    tcp_port: u16,
    wss_enabled: bool,
    wss_port: u16,
    wss_path: String,
    ws_subprotocol: String,
}

#[derive(Debug, Serialize)]
struct PrivateProfileResponse {
    private_enabled: bool,
    transport: PrivateTransportHints,
}

#[derive(Debug, Serialize)]
struct GatewayProfileResponse {
    private_channel_enabled: bool,
    private_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<PrivateTransportHints>,
}

pub(crate) async fn private_metrics(State(state): State<AppState>) -> HttpResult {
    let metrics = state
        .private
        .as_ref()
        .map(|private| private.metrics.snapshot())
        .unwrap_or_else(|| crate::private::metrics::PrivateMetrics::default().snapshot());
    Ok(crate::api::ok(PrivateMetricsResponse {
        private_enabled: state.private_channel_enabled,
        metrics,
    }))
}

pub(crate) async fn private_health(State(state): State<AppState>) -> HttpResult {
    let snapshot = state
        .private
        .as_ref()
        .map(|private| {
            private
                .metrics
                .health_snapshot(state.private_channel_enabled)
        })
        .unwrap_or_else(|| {
            crate::private::metrics::PrivateMetrics::default()
                .health_snapshot(state.private_channel_enabled)
        });
    Ok(crate::api::ok(snapshot))
}

pub(crate) async fn gateway_profile(State(state): State<AppState>) -> HttpResult {
    if !state.private_channel_enabled {
        return Ok(crate::api::ok(GatewayProfileResponse {
            private_channel_enabled: false,
            private_enabled: false,
            transport: None,
        }));
    }
    let private_profile = private_profile_payload(&state);
    Ok(crate::api::ok(GatewayProfileResponse {
        private_channel_enabled: true,
        private_enabled: true,
        transport: Some(private_profile.transport),
    }))
}

fn private_profile_payload(state: &AppState) -> PrivateProfileResponse {
    PrivateProfileResponse {
        private_enabled: true,
        transport: transport_hints(&state.private_transport_profile),
    }
}

pub(crate) async fn private_network_diagnostics(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> HttpResult {
    if !state.private_channel_enabled {
        return Ok(crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
        ));
    }

    let observed_client_ip = Some(peer.ip().to_string());
    let peer_ip = peer.ip().to_string();
    let resolved_ip_source = resolve_ip_source(&headers);
    let observed_ip_scope = observed_client_ip
        .as_deref()
        .map(classify_ip_scope)
        .unwrap_or("unknown");
    let proxy_detected = has_proxy_headers(&headers);

    Ok(crate::api::ok(PrivateNetworkDiagnosticsResponse {
        private_enabled: true,
        observed_client_ip,
        peer_ip,
        resolved_ip_source,
        proxy_detected,
        observed_ip_scope,
        nat_hint: nat_hint_for_scope(observed_ip_scope),
        host: header_value(&headers, HOST),
        forwarded_proto: header_value(&headers, X_FORWARDED_PROTO)
            .or_else(|| forwarded_pair(&headers, "proto")),
        x_forwarded_for: header_value(&headers, X_FORWARDED_FOR),
        x_real_ip: header_value(&headers, X_REAL_IP),
        forwarded: header_value(&headers, FORWARDED),
        transport_hints: transport_hints(&state.private_transport_profile),
    }))
}

pub(crate) async fn private_ws(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !state.private_channel_enabled {
        return crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
        );
    }
    if !client_offers_ws_subprotocol(&headers, PRIVATE_WS_SUBPROTOCOL) {
        return crate::api::err(
            StatusCode::BAD_REQUEST,
            format!("missing websocket subprotocol `{PRIVATE_WS_SUBPROTOCOL}`"),
        );
    }
    let Some(private_state) = state.private.as_ref() else {
        return crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel runtime is unavailable",
        );
    };
    let private_state = Arc::clone(private_state);
    ws.protocols([PRIVATE_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            crate::private::ws::serve_ws_socket(socket, private_state).await;
        })
        .into_response()
}

fn transport_hints(profile: &PrivateTransportProfile) -> PrivateTransportHints {
    PrivateTransportHints {
        quic_enabled: profile.quic_enabled,
        quic_port: profile.quic_port,
        tcp_enabled: profile.tcp_enabled,
        tcp_port: profile.tcp_port,
        wss_enabled: profile.wss_enabled,
        wss_port: profile.wss_port,
        wss_path: profile.wss_path.to_string(),
        ws_subprotocol: profile.ws_subprotocol.to_string(),
    }
}

fn client_offers_ws_subprotocol(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|raw| raw.to_str().ok())
        .map(|raw| raw.split(',').map(str::trim).any(|value| value == expected))
        .unwrap_or(false)
}

fn header_value(headers: &HeaderMap, name: axum::http::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|raw| raw.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn resolve_ip_source(headers: &HeaderMap) -> &'static str {
    if headers.contains_key(X_FORWARDED_FOR) {
        "x-forwarded-for"
    } else if headers.contains_key(X_REAL_IP) {
        "x-real-ip"
    } else if headers.contains_key(FORWARDED) {
        "forwarded"
    } else {
        "peer"
    }
}

fn has_proxy_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(X_FORWARDED_FOR)
        || headers.contains_key(X_REAL_IP)
        || headers.contains_key(FORWARDED)
        || headers.contains_key(X_FORWARDED_PROTO)
}

fn forwarded_pair(headers: &HeaderMap, key: &str) -> Option<String> {
    let raw = header_value(headers, FORWARDED)?;
    raw.split(',')
        .flat_map(|segment| segment.split(';'))
        .find_map(|pair| {
            let (candidate_key, candidate_value) = pair.split_once('=')?;
            if !candidate_key.trim().eq_ignore_ascii_case(key) {
                return None;
            }
            let value = candidate_value.trim().trim_matches('"').trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        })
}

fn classify_ip_scope(raw: &str) -> &'static str {
    let Ok(ip) = raw.parse::<std::net::IpAddr>() else {
        return "unknown";
    };
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            if is_cgnat_ipv4(ipv4) {
                "carrier-grade-nat"
            } else if ipv4.is_private() {
                "private-ipv4"
            } else if ipv4.is_loopback() {
                "loopback"
            } else if ipv4.is_link_local() {
                "link-local"
            } else {
                "public-ipv4"
            }
        }
        std::net::IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                "loopback"
            } else if ipv6.is_unicast_link_local() {
                "link-local"
            } else if ipv6.is_unique_local() {
                "unique-local-ipv6"
            } else {
                "public-ipv6"
            }
        }
    }
}

fn nat_hint_for_scope(scope: &str) -> &'static str {
    match scope {
        "carrier-grade-nat" => "carrier-grade-nat-likely",
        "private-ipv4" | "unique-local-ipv6" => "private-proxy-or-misconfigured-forwarding",
        "public-ipv4" => "public-ipv4-observed-or-port-preserving-nat",
        "public-ipv6" => "native-ipv6-or-prefix-delegation",
        "link-local" | "loopback" => "gateway-observation-is-not-routable",
        _ => "unknown",
    }
}

fn is_cgnat_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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

        let hints = transport_hints(&profile);
        assert!(hints.quic_enabled);
        assert_eq!(hints.quic_port, Some(8443));
        assert!(hints.tcp_enabled);
        assert_eq!(hints.tcp_port, 5223);
        assert!(hints.wss_enabled);
        assert_eq!(hints.wss_port, 443);
        assert_eq!(hints.wss_path, "/private/ws");
        assert_eq!(hints.ws_subprotocol, PRIVATE_WS_SUBPROTOCOL);
    }

    #[test]
    fn classify_ip_scope_detects_cgnat() {
        assert_eq!(classify_ip_scope("100.64.1.2"), "carrier-grade-nat");
        assert_eq!(classify_ip_scope("100.127.255.254"), "carrier-grade-nat");
    }
}
