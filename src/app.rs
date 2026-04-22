use crate::{
    api::router::build_router,
    args::Args,
    dispatch::{DispatchChannels, DispatchWorkerDeps},
    mcp::{McpConfig, McpPredefinedClientConfig, McpState},
    private::{PrivateConfig, PrivateState},
    providers::{ApnsClient, FcmClient, WnsClient},
    routing::{DeviceChannelType, DeviceRegistry, DeviceRouteRecord, derive_private_device_id},
    stats::StatsCollector,
    storage::{DeviceRouteRecordRow, Storage},
};
use axum::Router;
use scc::HashMap as ConcurrentHashMap;
use std::sync::{
    Arc, OnceLock, Weak,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::Instant;
use tokio::sync::Mutex;

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
    pub diagnostics_api_enabled: bool,
    pub trace_logs_enabled: bool,
    pub public_base_url: Option<Arc<str>>,
    pub device_registry: Arc<DeviceRegistry>,
    pub device_operation_guards: Arc<DeviceOperationGuards>,
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

pub(crate) struct DeviceOperationGuards {
    by_key: ConcurrentHashMap<Arc<str>, DeviceOperationGuardSlot>,
    access_count: AtomicUsize,
}

struct DeviceOperationGuardSlot {
    guard: Weak<Mutex<()>>,
    last_seen_ms: AtomicU64,
}

impl DeviceOperationGuards {
    const CLEANUP_INTERVAL: usize = 256;
    const STALE_IDLE_TTL_MS: u64 = 5 * 60 * 1000;

    fn monotonic_now_ms() -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as u64
    }

    pub fn guard_for(&self, device_key: &str) -> Option<Arc<Mutex<()>>> {
        let normalized = device_key.trim();
        if normalized.is_empty() {
            return None;
        }

        let now_ms = Self::monotonic_now_ms();
        if let Some(Some(guard)) = self.by_key.read_sync(normalized, |_, slot| {
            slot.last_seen_ms.store(now_ms, Ordering::Relaxed);
            slot.guard.upgrade()
        }) {
            self.maybe_cleanup(now_ms);
            return Some(guard);
        }

        let normalized: Arc<str> = Arc::from(normalized);
        let guard = match self.by_key.entry_sync(Arc::clone(&normalized)) {
            scc::hash_map::Entry::Occupied(mut entry) => {
                let slot = entry.get_mut();
                slot.last_seen_ms.store(now_ms, Ordering::Relaxed);
                if let Some(existing) = slot.guard.upgrade() {
                    existing
                } else {
                    let replacement = Arc::new(Mutex::new(()));
                    slot.guard = Arc::downgrade(&replacement);
                    replacement
                }
            }
            scc::hash_map::Entry::Vacant(entry) => {
                let guard = Arc::new(Mutex::new(()));
                entry.insert_entry(DeviceOperationGuardSlot {
                    guard: Arc::downgrade(&guard),
                    last_seen_ms: AtomicU64::new(now_ms),
                });
                guard
            }
        };

        self.maybe_cleanup(now_ms);
        Some(guard)
    }

    fn maybe_cleanup(&self, now_ms: u64) {
        let access = self.access_count.fetch_add(1, Ordering::Relaxed) + 1;
        if !access.is_multiple_of(Self::CLEANUP_INTERVAL) {
            return;
        }
        self.sweep_stale_entries(now_ms);
    }

    fn sweep_stale_entries(&self, now_ms: u64) {
        self.by_key.retain_sync(|_, slot| {
            let idle_for_ms = now_ms.saturating_sub(slot.last_seen_ms.load(Ordering::Relaxed));
            let is_stale = slot.guard.strong_count() == 0 && idle_for_ms >= Self::STALE_IDLE_TTL_MS;
            !is_stale
        });
    }
}

impl Default for DeviceOperationGuards {
    fn default() -> Self {
        Self {
            by_key: ConcurrentHashMap::default(),
            access_count: AtomicUsize::new(0),
        }
    }
}

pub async fn build_app(
    args: &Args,
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
    docs_html: &'static str,
) -> Result<AppRuntime, Box<dyn std::error::Error>> {
    let store = Storage::new(args.db_url.as_deref()).await?;
    let observability = args.observability_config();
    let stats = StatsCollector::spawn_with_mode(store.clone(), observability.stats_enabled);
    let device_registry = Arc::new(DeviceRegistry::new());
    let device_operation_guards = Arc::new(DeviceOperationGuards::default());
    restore_device_registry(&store, &device_registry).await?;

    let (dispatch, receivers) = DispatchChannels::new();

    let auth = match args.token.as_deref() {
        None => AuthMode::Disabled,
        Some(token) => AuthMode::SharedToken(Arc::from(token)),
    };
    let private_transports = args.private_transports()?;
    let private_channel_enabled = private_transports.any_enabled();

    let private_config = PrivateConfig {
        private_quic_bind: private_transports
            .quic
            .then(|| args.private_quic_bind.clone()),
        private_tcp_bind: private_transports
            .tcp
            .then(|| args.private_tcp_bind.clone()),
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
    let private = if private_channel_enabled {
        let state = Arc::new(PrivateState::new(
            store.clone(),
            private_config,
            Arc::clone(&device_registry),
            Arc::clone(&stats),
        ));
        state
            .spawn_configured_transports()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        state.spawn_persistent_fallback_worker();
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
        stats: Arc::clone(&stats),
    }
    .spawn(receivers);

    let private_transport_profile = PrivateTransportProfile {
        quic_enabled: private_transports.quic,
        quic_port: private_transports.quic.then_some(args.private_quic_port),
        tcp_enabled: private_transports.tcp,
        tcp_port: args.private_tcp_port,
        wss_enabled: private_transports.wss,
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
        auth: auth.clone(),
        private_channel_enabled,
        diagnostics_api_enabled: observability.diagnostics_api_enabled,
        trace_logs_enabled: observability.trace_logs_enabled,
        public_base_url,
        device_registry,
        device_operation_guards,
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
            crate::util::TraceEvent::new("gateway.restore_private_binding_failed")
                .field_redacted("device_key", route.device_key.as_str())
                .field_str("error", &err)
                .emit();
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

#[cfg(test)]
mod tests {
    use super::DeviceOperationGuards;
    use std::sync::Arc;

    #[test]
    fn device_operation_guards_reuse_live_lock_and_reap_stale_slots() {
        let guards = DeviceOperationGuards::default();

        let first = guards.guard_for(" device-a ").expect("guard should exist");
        let second = guards
            .guard_for("device-a")
            .expect("guard should be reused");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(guards.by_key.len(), 1);

        guards.sweep_stale_entries(u64::MAX);
        assert_eq!(guards.by_key.len(), 1, "live guard must not be reaped");

        drop(first);
        drop(second);

        guards.sweep_stale_entries(u64::MAX);
        assert!(guards.by_key.is_empty(), "stale slot should be reaped");
    }
}
