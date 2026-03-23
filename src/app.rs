use crate::{
    api::router::build_router,
    args::Args,
    device_registry::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord},
    dispatch::{
        DispatchChannels, DispatchWorkerDeps, create_dispatch_channels, spawn_dispatch_workers,
    },
    private::{
        PrivateConfig, PrivateState, spawn_persistent_fallback_worker, spawn_quic_if_configured,
        spawn_tcp_if_configured,
    },
    providers::{ApnsClient, FcmClient, WnsClient},
    rate_limit::{ApiRateLimiter, ClientIpResolver},
    storage::{DeviceRegistryRoute, Store, new_store},
};
use axum::Router;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub(crate) struct PrivateTransportProfile {
    pub quic_enabled: bool,
    pub quic_port: Option<u16>,
    pub tcp_enabled: bool,
    pub tcp_port: u16,
    pub wss_enabled: bool,
    pub wss_port: u16,
    pub wss_path: Arc<str>,
    pub ws_subprotocol: Arc<str>,
}

#[derive(Clone)]
pub(crate) enum AuthMode {
    Disabled,
    SharedToken(Arc<str>),
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub dispatch: DispatchChannels,
    pub auth: AuthMode,
    pub private_channel_enabled: bool,
    pub ip_rate_limit_enabled: bool,
    pub ingress_processing_limiter: Arc<Semaphore>,
    pub ingress_wait_limiter: Arc<Semaphore>,
    pub api_rate_limiter: Arc<ApiRateLimiter>,
    pub client_ip_resolver: Arc<ClientIpResolver>,
    pub device_registry: Arc<DeviceRegistry>,
    pub private_transport_profile: PrivateTransportProfile,
    pub private: Option<Arc<PrivateState>>,
    pub store: Store,
}

pub struct AppRuntime {
    pub router: Router,
    pub private: Option<Arc<PrivateState>>,
}

pub async fn build_app(
    args: &Args,
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
    docs_html: &'static str,
) -> Result<AppRuntime, Box<dyn std::error::Error>> {
    let store = new_store(args.db_url.as_deref()).await?;
    let ingress_permits = auto_ingress_permits();
    let client_ip_resolver = Arc::new(ClientIpResolver);
    let device_registry = Arc::new(DeviceRegistry::new());
    restore_device_registry(&store, &device_registry).await?;

    let (dispatch, apns_rx, fcm_rx, wns_rx) = create_dispatch_channels();

    let auth = match args.token.as_deref() {
        None => AuthMode::Disabled,
        Some(token) => AuthMode::SharedToken(Arc::from(token)),
    };

    let private_config = PrivateConfig::new(
        Some(args.private_quic_bind.clone()),
        Some(args.private_tcp_bind.clone()),
        args.private_tcp_tls_offload,
        args.private_tls_cert_path.clone(),
        args.private_tls_key_path.clone(),
        args.private_session_ttl_secs,
        args.private_grace_window_secs,
        args.private_max_pending_per_device,
        args.private_global_max_pending,
        args.private_pull_limit,
        args.private_ack_timeout_secs,
        args.private_fallback_max_attempts,
        args.private_fallback_max_backoff_secs,
        args.private_retx_window_secs,
        args.private_retx_max_per_window,
        args.private_retx_max_per_tick,
        args.private_retx_max_retries,
        args.private_hot_cache_capacity,
        args.private_default_ttl_secs,
        args.token.clone(),
        args.enable_ip_rate_limit,
    );
    let private = if args.private_channel_enabled {
        let state = Arc::new(PrivateState::new(
            Arc::clone(&store),
            private_config,
            Arc::clone(&device_registry),
        ));
        spawn_quic_if_configured(Arc::clone(&state))
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        spawn_tcp_if_configured(Arc::clone(&state))
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        spawn_persistent_fallback_worker(Arc::clone(&state), dispatch.clone());
        Some(state)
    } else {
        None
    };

    spawn_dispatch_workers(
        apns_rx,
        fcm_rx,
        wns_rx,
        DispatchWorkerDeps {
            apns: Arc::clone(&apns),
            fcm: Arc::clone(&fcm),
            wns: Arc::clone(&wns),
            store: Arc::clone(&store),
            private: private.clone(),
        },
    );

    let private_transport_profile = PrivateTransportProfile {
        quic_enabled: true,
        quic_port: Some(args.private_quic_port),
        tcp_enabled: true,
        tcp_port: args.private_tcp_port,
        wss_enabled: true,
        wss_port: 443,
        wss_path: Arc::from("/private/ws"),
        ws_subprotocol: Arc::from("pushgo-private.v1"),
    };

    let state = AppState {
        dispatch,
        auth,
        private_channel_enabled: args.private_channel_enabled,
        ip_rate_limit_enabled: args.enable_ip_rate_limit,
        ingress_processing_limiter: Arc::new(Semaphore::new(ingress_permits)),
        ingress_wait_limiter: Arc::new(Semaphore::new(ingress_permits)),
        api_rate_limiter: Arc::new(ApiRateLimiter::default()),
        client_ip_resolver,
        device_registry,
        private_transport_profile,
        private: private.clone(),
        store,
    };

    let router = build_router(state.clone(), docs_html);

    Ok(AppRuntime { router, private })
}

fn auto_ingress_permits() -> usize {
    let cpu = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1);
    cpu.saturating_mul(200)
}

async fn restore_device_registry(
    store: &Store,
    registry: &Arc<DeviceRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let routes = store.load_device_registry_routes_async().await?;

    for route in routes {
        let Some(record) = parse_route_record(&route) else {
            continue;
        };
        if registry.restore_route(&route.device_key, record).is_err() {
            continue;
        }
    }
    Ok(())
}

fn parse_route_record(route: &DeviceRegistryRoute) -> Option<DeviceRouteRecord> {
    let channel_type = DeviceChannelType::parse(&route.channel_type)?;
    Some(DeviceRouteRecord {
        platform: route.platform.trim().to_ascii_lowercase(),
        channel_type,
        provider_token: route.provider_token.clone(),
        updated_at: route.updated_at,
    })
}
