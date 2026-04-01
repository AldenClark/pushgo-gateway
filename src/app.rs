use crate::{
    api::router::build_router,
    args::Args,
    dispatch::{
        DeliveryAuditCollector, DeliveryAuditMode, DispatchChannels, DispatchWorkerDeps,
        ProviderPullRetryWorkerDeps,
        audit::{DEFAULT_DISPATCH_AUDIT_CAPACITY, DispatchAuditLog, DispatchAuditMode},
    },
    mcp::{McpConfig, McpPredefinedClientConfig, McpState},
    private::{PrivateConfig, PrivateState},
    providers::{ApnsClient, FcmClient, WnsClient},
    routing::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord, derive_private_device_id},
    stats::StatsCollector,
    storage::{DeviceRouteRecordRow, Storage},
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
    pub public_base_url: Option<Arc<str>>,
    pub device_registry: Arc<DeviceRegistry>,
    pub stats: Arc<StatsCollector>,
    pub private_transport_profile: PrivateTransportProfile,
    pub private: Option<Arc<PrivateState>>,
    pub store: Storage,
    pub mcp: Option<Arc<McpState>>,
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
    let store = Storage::new(args.db_url.as_deref()).await?;
    let stats = StatsCollector::spawn(store.clone());
    let device_registry = Arc::new(DeviceRegistry::new());
    restore_device_registry(&store, &device_registry).await?;

    let (dispatch, receivers) = DispatchChannels::new();
    let dispatch_audit = Arc::new(DispatchAuditLog::new(
        DEFAULT_DISPATCH_AUDIT_CAPACITY,
        if args.diagnostics_api_enabled {
            DispatchAuditMode::Enabled
        } else {
            DispatchAuditMode::Disabled
        },
    ));
    let delivery_audit = DeliveryAuditCollector::spawn(
        if args.diagnostics_api_enabled {
            DeliveryAuditMode::Enabled
        } else {
            DeliveryAuditMode::Disabled
        },
        store.clone(),
        Arc::clone(&dispatch_audit),
    );

    let auth = match args.token.as_deref() {
        None => AuthMode::Disabled,
        Some(token) => AuthMode::SharedToken(Arc::from(token)),
    };

    let private_config = PrivateConfig {
        private_quic_bind: Some(args.private_quic_bind.clone()),
        private_tcp_bind: Some(args.private_tcp_bind.clone()),
        tcp_tls_offload: args.private_tcp_tls_offload,
        tcp_proxy_protocol: args.private_tcp_proxy_protocol,
        private_tls_cert_path: args.private_tls_cert_path.clone(),
        private_tls_key_path: args.private_tls_key_path.clone(),
        session_ttl_secs: args.private_session_ttl_secs,
        grace_window_secs: args.private_grace_window_secs,
        max_pending_per_device: args.private_max_pending_per_device,
        global_max_pending: args.private_global_max_pending,
        pull_limit: args.private_pull_limit,
        ack_timeout_secs: args.private_ack_timeout_secs,
        fallback_max_attempts: args.private_fallback_max_attempts,
        fallback_max_backoff_secs: args.private_fallback_max_backoff_secs,
        retransmit_window_secs: args.private_retx_window_secs,
        retransmit_max_per_window: args.private_retx_max_per_window,
        retransmit_max_per_tick: args.private_retx_max_per_tick,
        retransmit_max_retries: args.private_retx_max_retries,
        hot_cache_capacity: args.private_hot_cache_capacity,
        default_ttl_secs: args.private_default_ttl_secs,
        gateway_token: args.token.clone(),
    }
    .normalized();
    let private = if args.private_channel_enabled {
        let state = Arc::new(PrivateState::new(
            store.clone(),
            private_config,
            Arc::clone(&device_registry),
            Arc::clone(&stats),
        ));
        state
            .spawn_configured_transports()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        state.spawn_persistent_fallback_worker(dispatch.clone());
        Some(state)
    } else {
        None
    };

    DispatchWorkerDeps {
        apns: Arc::clone(&apns),
        fcm: Arc::clone(&fcm),
        wns: Arc::clone(&wns),
        store: store.clone(),
        private: private.clone(),
        audit: dispatch_audit.clone(),
    }
    .spawn(receivers);
    ProviderPullRetryWorkerDeps {
        store: store.clone(),
        apns: Arc::clone(&apns),
        fcm: Arc::clone(&fcm),
        wns: Arc::clone(&wns),
        audit: dispatch_audit.clone(),
    }
    .spawn();

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

    let public_base_url = normalize_mcp_public_base_url(args.public_base_url.as_deref())?
        .map(|value| Arc::<str>::from(value.into_boxed_str()));

    let mcp_state = if args.mcp_enabled {
        let predefined_clients =
            parse_mcp_predefined_clients(args.mcp_predefined_clients.as_deref())?;
        let config = McpConfig {
            bootstrap_http_addr: Arc::from(args.http_addr.clone().into_boxed_str()),
            public_base_url: public_base_url.clone(),
            access_token_ttl_secs: args.mcp_access_token_ttl_secs,
            refresh_token_absolute_ttl_secs: args.mcp_refresh_token_absolute_ttl_secs,
            refresh_token_idle_ttl_secs: args.mcp_refresh_token_idle_ttl_secs,
            bind_session_ttl_secs: args.mcp_bind_session_ttl_secs,
            dcr_enabled: args.mcp_dcr_enabled,
            predefined_clients,
        };
        Some(Arc::new(McpState::new(config, &auth, store.clone()).await))
    } else {
        None
    };

    let state = AppState {
        dispatch,
        dispatch_audit,
        delivery_audit,
        auth: auth.clone(),
        private_channel_enabled: args.private_channel_enabled,
        diagnostics_api_enabled: args.diagnostics_api_enabled,
        public_base_url,
        device_registry,
        stats,
        private_transport_profile,
        private: private.clone(),
        store,
        mcp: mcp_state,
    };

    let router = build_router(state.clone(), docs_html);

    Ok(AppRuntime { router, private })
}

fn normalize_mcp_public_base_url(
    raw: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if !value.starts_with("https://") && !value.starts_with("http://") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PUSHGO_PUBLIC_BASE_URL must start with https:// or http://",
        )
        .into());
    }
    Ok(Some(value.trim_end_matches('/').to_string()))
}

fn parse_mcp_predefined_clients(
    raw: Option<&str>,
) -> Result<Vec<McpPredefinedClientConfig>, Box<dyn std::error::Error>> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut clients = Vec::new();
    for entry in value
        .split(['\n', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((client_id, client_secret)) = entry.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid predefined MCP client entry: {entry}"),
            )
            .into());
        };
        let client_id = client_id.trim();
        let client_secret = client_secret.trim();
        if client_id.is_empty() || client_secret.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid predefined MCP client entry: {entry}"),
            )
            .into());
        }
        clients.push(McpPredefinedClientConfig {
            client_id: Arc::from(client_id.to_string().into_boxed_str()),
            client_secret: Arc::from(client_secret.to_string().into_boxed_str()),
        });
    }
    Ok(clients)
}

async fn restore_device_registry(
    store: &Storage,
    registry: &Arc<DeviceRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let routes = store.load_device_routes().await?;

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
    let platform = route.platform.parse().ok()?;
    Some(DeviceRouteRecord {
        platform,
        channel_type,
        provider_token: route.provider_token.clone(),
        updated_at: route.updated_at,
    })
}

async fn backfill_private_binding_for_route(
    store: &Storage,
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
    let device_id = derive_private_device_id(device_key);
    store
        .bind_private_token(device_id, route.platform, token)
        .await
        .map_err(|err| err.to_string())
}
