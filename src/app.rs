use crate::{
    api::router::build_router,
    args::Args,
    delivery_audit::DeliveryAuditCollector,
    device_registry::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord},
    dispatch::{
        DispatchChannels, DispatchWorkerDeps,
        audit::{DEFAULT_DISPATCH_AUDIT_CAPACITY, DispatchAuditLog},
        create_dispatch_channels, spawn_dispatch_workers, spawn_provider_pull_retry_worker,
    },
    private::{
        PrivateConfig, PrivateState, spawn_persistent_fallback_worker, spawn_quic_if_configured,
        spawn_tcp_if_configured,
    },
    providers::{ApnsClient, FcmClient, WnsClient},
    stats::StatsCollector,
    storage::{DeviceRouteRecordRow, Platform, Store, new_store},
};
use axum::Router;
use std::sync::Arc;

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
    pub dispatch_audit: Arc<DispatchAuditLog>,
    pub delivery_audit: Arc<DeliveryAuditCollector>,
    pub auth: AuthMode,
    pub private_channel_enabled: bool,
    pub diagnostics_api_enabled: bool,
    pub device_registry: Arc<DeviceRegistry>,
    pub stats: Arc<StatsCollector>,
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
    let stats = StatsCollector::spawn(Arc::clone(&store));
    let device_registry = Arc::new(DeviceRegistry::new());
    restore_device_registry(&store, &device_registry).await?;

    let (dispatch, apns_rx, fcm_rx, wns_rx) = create_dispatch_channels();
    let dispatch_audit = Arc::new(DispatchAuditLog::new(
        DEFAULT_DISPATCH_AUDIT_CAPACITY,
        args.diagnostics_api_enabled,
    ));
    let delivery_audit = DeliveryAuditCollector::spawn(
        args.diagnostics_api_enabled,
        Arc::clone(&store),
        Arc::clone(&dispatch_audit),
    );

    let auth = match args.token.as_deref() {
        None => AuthMode::Disabled,
        Some(token) => AuthMode::SharedToken(Arc::from(token)),
    };

    let private_config = PrivateConfig::new(
        Some(args.private_quic_bind.clone()),
        Some(args.private_tcp_bind.clone()),
        args.private_tcp_tls_offload,
        args.private_tcp_proxy_protocol,
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
    );
    let private = if args.private_channel_enabled {
        let state = Arc::new(PrivateState::new(
            Arc::clone(&store),
            private_config,
            Arc::clone(&device_registry),
            Arc::clone(&stats),
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
            audit: dispatch_audit.clone(),
        },
    );
    spawn_provider_pull_retry_worker(
        Arc::clone(&store),
        Arc::clone(&apns),
        Arc::clone(&fcm),
        Arc::clone(&wns),
        dispatch_audit.clone(),
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
        dispatch_audit,
        delivery_audit,
        auth,
        private_channel_enabled: args.private_channel_enabled,
        diagnostics_api_enabled: args.diagnostics_api_enabled,
        device_registry,
        stats,
        private_transport_profile,
        private: private.clone(),
        store,
    };

    let router = build_router(state.clone(), docs_html);

    Ok(AppRuntime { router, private })
}

async fn restore_device_registry(
    store: &Store,
    registry: &Arc<DeviceRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let routes = store.load_device_routes_async().await?;

    for route in routes {
        let Some(record) = parse_device_route_record(&route) else {
            continue;
        };
        if registry
            .restore_route(&route.device_key, record.clone())
            .is_err()
        {
            continue;
        }
        if let Err(err) =
            backfill_private_binding_for_route(store, &route.device_key, &record).await
        {
            crate::util::diagnostics_log(format_args!(
                "restore private binding failed device_key={} error={}",
                route.device_key, err
            ));
        }
    }
    Ok(())
}

fn parse_device_route_record(route: &DeviceRouteRecordRow) -> Option<DeviceRouteRecord> {
    let channel_type = DeviceChannelType::parse(&route.channel_type)?;
    Some(DeviceRouteRecord {
        platform: route.platform.trim().to_ascii_lowercase(),
        channel_type,
        provider_token: route.provider_token.clone(),
        updated_at: route.updated_at,
    })
}

async fn backfill_private_binding_for_route(
    store: &Store,
    device_key: &str,
    route: &DeviceRouteRecord,
) -> Result<(), String> {
    if route.channel_type == DeviceChannelType::Private {
        return Ok(());
    }
    let Some(token) = route
        .provider_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let platform: Platform = route
        .platform
        .parse()
        .map_err(|_| "invalid route platform".to_string())?;
    let device_id = DeviceRegistry::derive_private_device_id(device_key);
    store
        .bind_private_token_async(device_id, platform, token)
        .await
        .map_err(|err| err.to_string())
}
