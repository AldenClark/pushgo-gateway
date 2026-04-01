use serde::Serialize;

use crate::{
    app::{AppState, PrivateTransportProfile},
    private::metrics::{PrivateHealthMode, PrivateHealthSnapshot, PrivateMetricsSnapshot},
};

#[derive(Debug, Serialize)]
pub(super) struct PrivateMetricsResponse {
    pub(super) private_enabled: bool,
    pub(super) metrics: PrivateMetricsSnapshot,
}

#[derive(Debug, Serialize)]
pub(super) struct PrivateTransportHints {
    pub(super) quic_enabled: bool,
    pub(super) quic_port: Option<u16>,
    pub(super) tcp_enabled: bool,
    pub(super) tcp_port: u16,
    pub(super) wss_enabled: bool,
    pub(super) wss_port: u16,
    pub(super) wss_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) wss_url: Option<String>,
    pub(super) ws_subprotocol: String,
}

#[derive(Debug, Serialize)]
pub(super) struct GatewayProfileResponse {
    pub(super) private_channel_enabled: bool,
    pub(super) private_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) transport: Option<PrivateTransportHints>,
}

pub(super) struct PrivateRuntimeView<'a> {
    state: &'a AppState,
}

impl PrivateTransportProfile {
    pub(super) fn hints(&self, public_base_url: Option<&str>) -> PrivateTransportHints {
        PrivateTransportHints {
            quic_enabled: self.quic_enabled,
            quic_port: self.quic_port,
            tcp_enabled: self.tcp_enabled,
            tcp_port: self.tcp_port,
            wss_enabled: self.wss_enabled,
            wss_port: self.wss_port,
            wss_path: self.wss_path.to_string(),
            wss_url: build_wss_url(public_base_url, self.wss_enabled, self.wss_path.as_ref()),
            ws_subprotocol: self.ws_subprotocol.to_string(),
        }
    }
}

impl PrivateMetricsResponse {
    fn from_view(view: &PrivateRuntimeView<'_>) -> Self {
        let metrics = view
            .state
            .private
            .as_ref()
            .map(|private| private.metrics.snapshot())
            .unwrap_or_else(|| crate::private::metrics::PrivateMetrics::default().snapshot());
        Self {
            private_enabled: view.state.private_channel_enabled,
            metrics,
        }
    }
}

impl GatewayProfileResponse {
    pub(super) fn private_disabled() -> Self {
        Self {
            private_channel_enabled: false,
            private_enabled: false,
            transport: None,
        }
    }

    fn private_enabled(profile: &PrivateTransportProfile, public_base_url: Option<&str>) -> Self {
        Self {
            private_channel_enabled: true,
            private_enabled: true,
            transport: Some(profile.hints(public_base_url)),
        }
    }
}

impl<'a> PrivateRuntimeView<'a> {
    pub(super) fn new(state: &'a AppState) -> Self {
        Self { state }
    }

    fn health_mode(&self) -> PrivateHealthMode {
        if self.state.private_channel_enabled {
            PrivateHealthMode::Enabled
        } else {
            PrivateHealthMode::Disabled
        }
    }

    pub(super) fn transport_profile(&self) -> &'a PrivateTransportProfile {
        &self.state.private_transport_profile
    }

    pub(super) fn public_base_url(&self) -> Option<&str> {
        self.state.public_base_url.as_deref()
    }

    pub(super) fn metrics_response(&self) -> PrivateMetricsResponse {
        PrivateMetricsResponse::from_view(self)
    }

    pub(super) fn health_snapshot(&self) -> PrivateHealthSnapshot {
        self.state
            .private
            .as_ref()
            .map(|private| private.metrics.health_snapshot(self.health_mode()))
            .unwrap_or_else(|| {
                crate::private::metrics::PrivateMetrics::default()
                    .health_snapshot(self.health_mode())
            })
    }

    pub(super) fn gateway_profile_response(&self) -> GatewayProfileResponse {
        if !self.state.private_channel_enabled {
            GatewayProfileResponse::private_disabled()
        } else {
            GatewayProfileResponse::private_enabled(
                self.transport_profile(),
                self.public_base_url(),
            )
        }
    }
}

fn build_wss_url(
    public_base_url: Option<&str>,
    wss_enabled: bool,
    wss_path: &str,
) -> Option<String> {
    if !wss_enabled {
        return None;
    }
    let base_url = public_base_url?.trim_end_matches('/');
    let scheme_adjusted = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return None;
    };
    Some(format!("{scheme_adjusted}{wss_path}"))
}
