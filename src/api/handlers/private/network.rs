use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::http::{
    HeaderMap,
    header::{HOST, HeaderName, SEC_WEBSOCKET_PROTOCOL},
};
use serde::Serialize;

use crate::app::PrivateTransportProfile;

use super::runtime::{PrivateRuntimeView, PrivateTransportHints};

const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");
const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

#[derive(Debug, Serialize)]
pub(super) struct PrivateNetworkDiagnosticsResponse {
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

#[derive(Debug)]
pub(super) struct PrivateNetworkObservation {
    pub(super) observed_client_ip: Option<String>,
    pub(super) peer_ip: String,
    pub(super) resolved_ip_source: ResolvedIpSource,
    pub(super) observed_ip_scope: ObservedIpScope,
    pub(super) host: Option<String>,
    pub(super) forwarded_proto: Option<String>,
    pub(super) x_forwarded_for: Option<String>,
    pub(super) x_real_ip: Option<String>,
    pub(super) forwarded: Option<String>,
}

pub(super) struct PrivateDiagnosticsRequest<'a> {
    peer: SocketAddr,
    headers: PrivateRequestHeaders<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolvedIpSource {
    Peer,
    XForwardedFor,
    XRealIp,
    Forwarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ObservedIpScope {
    CarrierGradeNat,
    PrivateIpv4,
    Loopback,
    LinkLocal,
    PublicIpv4,
    UniqueLocalIpv6,
    PublicIpv6,
    Unknown,
}

pub(super) struct PrivateRequestHeaders<'a> {
    headers: &'a HeaderMap,
}

impl ResolvedIpSource {
    fn detect(headers: &HeaderMap) -> Self {
        if headers.contains_key(X_FORWARDED_FOR) {
            Self::XForwardedFor
        } else if headers.contains_key(X_REAL_IP) {
            Self::XRealIp
        } else if headers.contains_key(FORWARDED) {
            Self::Forwarded
        } else {
            Self::Peer
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::XForwardedFor => "x-forwarded-for",
            Self::XRealIp => "x-real-ip",
            Self::Forwarded => "forwarded",
        }
    }
}

impl ObservedIpScope {
    pub(super) fn classify(raw: &str) -> Self {
        let Ok(ip) = raw.parse::<IpAddr>() else {
            return Self::Unknown;
        };
        match ip {
            IpAddr::V4(ipv4) => {
                if Self::is_cgnat_ipv4(ipv4) {
                    Self::CarrierGradeNat
                } else if ipv4.is_private() {
                    Self::PrivateIpv4
                } else if ipv4.is_loopback() {
                    Self::Loopback
                } else if ipv4.is_link_local() {
                    Self::LinkLocal
                } else {
                    Self::PublicIpv4
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() {
                    Self::Loopback
                } else if ipv6.is_unicast_link_local() {
                    Self::LinkLocal
                } else if ipv6.is_unique_local() {
                    Self::UniqueLocalIpv6
                } else {
                    Self::PublicIpv6
                }
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::CarrierGradeNat => "carrier-grade-nat",
            Self::PrivateIpv4 => "private-ipv4",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::PublicIpv4 => "public-ipv4",
            Self::UniqueLocalIpv6 => "unique-local-ipv6",
            Self::PublicIpv6 => "public-ipv6",
            Self::Unknown => "unknown",
        }
    }

    fn nat_hint(self) -> &'static str {
        match self {
            Self::CarrierGradeNat => "carrier-grade-nat-likely",
            Self::PrivateIpv4 | Self::UniqueLocalIpv6 => {
                "private-proxy-or-misconfigured-forwarding"
            }
            Self::PublicIpv4 => "public-ipv4-observed-or-port-preserving-nat",
            Self::PublicIpv6 => "native-ipv6-or-prefix-delegation",
            Self::LinkLocal | Self::Loopback => "gateway-observation-is-not-routable",
            Self::Unknown => "unknown",
        }
    }

    fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 100 && (64..=127).contains(&octets[1])
    }
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

    fn value(&self, name: HeaderName) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|raw| raw.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }

    pub(super) fn resolved_ip_source(&self) -> ResolvedIpSource {
        ResolvedIpSource::detect(self.headers)
    }

    pub(super) fn forwarded_pair(&self, key: &str) -> Option<String> {
        let raw = self.value(FORWARDED)?;
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

    fn observe_network(&self, peer: SocketAddr) -> PrivateNetworkObservation {
        let observed_client_ip = Some(peer.ip().to_string());
        let observed_ip_scope = observed_client_ip
            .as_deref()
            .map(ObservedIpScope::classify)
            .unwrap_or(ObservedIpScope::Unknown);
        PrivateNetworkObservation {
            observed_client_ip,
            peer_ip: peer.ip().to_string(),
            resolved_ip_source: self.resolved_ip_source(),
            observed_ip_scope,
            host: self.value(HOST),
            forwarded_proto: self
                .value(X_FORWARDED_PROTO)
                .or_else(|| self.forwarded_pair("proto")),
            x_forwarded_for: self.value(X_FORWARDED_FOR),
            x_real_ip: self.value(X_REAL_IP),
            forwarded: self.value(FORWARDED),
        }
    }
}

impl PrivateNetworkObservation {
    pub(super) fn proxy_detected(&self) -> bool {
        self.x_forwarded_for.is_some()
            || self.x_real_ip.is_some()
            || self.forwarded.is_some()
            || self.forwarded_proto.is_some()
    }

    fn into_response(
        self,
        view: &PrivateRuntimeView<'_>,
        transport_profile: &PrivateTransportProfile,
    ) -> PrivateNetworkDiagnosticsResponse {
        let proxy_detected = self.proxy_detected();
        PrivateNetworkDiagnosticsResponse {
            private_enabled: view.gateway_profile_response().private_enabled,
            observed_client_ip: self.observed_client_ip,
            peer_ip: self.peer_ip,
            resolved_ip_source: self.resolved_ip_source.as_str(),
            proxy_detected,
            observed_ip_scope: self.observed_ip_scope.as_str(),
            nat_hint: self.observed_ip_scope.nat_hint(),
            host: self.host,
            forwarded_proto: self.forwarded_proto,
            x_forwarded_for: self.x_forwarded_for,
            x_real_ip: self.x_real_ip,
            forwarded: self.forwarded,
            transport_hints: transport_profile.hints(view.public_base_url()),
        }
    }
}

impl<'a> PrivateDiagnosticsRequest<'a> {
    pub(super) fn new(peer: SocketAddr, headers: &'a HeaderMap) -> Self {
        Self {
            peer,
            headers: PrivateRequestHeaders::new(headers),
        }
    }

    pub(super) fn observe_network(&self) -> PrivateNetworkObservation {
        self.headers.observe_network(self.peer)
    }

    pub(super) fn diagnostics_response(
        &self,
        view: &PrivateRuntimeView<'_>,
    ) -> PrivateNetworkDiagnosticsResponse {
        self.observe_network()
            .into_response(view, view.transport_profile())
    }
}
