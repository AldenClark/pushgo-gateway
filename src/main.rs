use std::{error::Error, future::Future, net::SocketAddr, sync::Arc};

use clap::Parser;
use tokio::{
    net::TcpListener,
    signal,
    sync::watch,
    time::{Instant as TokioInstant, timeout_at},
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use pushgo_gateway::{
    app::{AppRuntime, build_app},
    args::{Args, ObservabilityConfig, ObservabilityLogLevel, PrivateTransports},
    providers::{ApnsService, FcmService, WnsService},
    runtime_config::RuntimeTuning,
    storage::{
        StorageInitConfig,
        database::upgrade::{UpgradeManager, UpgradeMode},
    },
};

const APNS_PRODUCTION_ENDPOINT: &str = "https://api.push.apple.com";
const APNS_SANDBOX_ENDPOINT: &str = "https://api.sandbox.push.apple.com";
const FCM_SEND_BASE_URL: &str = "https://fcm.googleapis.com";
const APP_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(20);

// Measurement-only ABI from the frozen C9 observer, kept out of the product
// library (which continues to forbid unsafe code) and every non-QA build.
#[cfg(all(feature = "qa", target_os = "macos"))]
fn qa_allocator_snapshot() -> serde_json::Value {
    #[repr(C)]
    #[derive(Default)]
    struct Statistics {
        blocks_in_use: u32,
        size_in_use: usize,
        max_size_in_use: usize,
        size_allocated: usize,
    }
    unsafe extern "C" {
        fn malloc_zone_statistics(zone: *mut std::ffi::c_void, statistics: *mut Statistics);
    }
    let mut value = Statistics::default();
    // SAFETY: the synchronous system API writes this repr(C) output with the
    // SDK malloc_statistics_t layout; a null zone sums all process malloc zones.
    unsafe {
        malloc_zone_statistics(std::ptr::null_mut(), &mut value);
    }
    serde_json::json!({
        "blocks_in_use": value.blocks_in_use,
        "bytes_in_use": value.size_in_use,
        "max_bytes_touched": value.max_size_in_use,
        "bytes_reserved": value.size_allocated,
        "scope": "all process malloc zones; excludes non-malloc VM mappings; not RSS or a complete leak detector"
    })
}

#[cfg(all(feature = "qa", not(target_os = "macos")))]
fn qa_allocator_snapshot() -> serde_json::Value {
    serde_json::Value::Null
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse().normalized();
    if let Some(raw_level) = args.observability_log_level.as_deref()
        && ObservabilityLogLevel::parse(raw_level).is_none()
    {
        eprintln!("invalid observability log level `{raw_level}`, fallback to default `warn`");
    }
    let private_transports = args.private_transports()?;
    let runtime_tuning = args.runtime_tuning()?;
    let observability = args.observability_config();
    init_native_tracing(observability.log_level);
    pushgo_gateway::util::set_sandbox_mode(args.sandbox_mode);
    pushgo_gateway::util::install_panic_trace_hook();
    if let Some(mode) = args.ordinary_cutover.as_deref() {
        let database = args
            .db_url
            .as_deref()
            .ok_or("--db-url is required for offline cutover")?;
        let backup = args
            .ordinary_cutover_backup
            .as_deref()
            .ok_or("--ordinary-cutover-backup is required")?;
        pushgo_gateway::ordinary::cutover::run(
            database,
            mode,
            backup,
            args.ordinary_source_profile.as_deref(),
        )
        .await?;
        return Ok(());
    }
    if let Some(mode) = args.db_upgrade.as_deref() {
        run_db_upgrade_subpath(&args, mode).await?;
        return Ok(());
    }
    let apns_endpoint = apns_endpoint(args.sandbox_mode);
    let token_service_url = args.token_service_base_url()?;
    print_startup_diagnostics(
        &args,
        private_transports,
        &observability,
        runtime_tuning,
        apns_endpoint,
        token_service_url.as_str(),
    );

    let (apns, fcm, wns) = provider_clients(
        &args,
        runtime_tuning,
        apns_endpoint,
        token_service_url.as_str(),
    )?;

    let addr: SocketAddr = args.http_addr.parse()?;
    let docs_html = include_str!("api/docs.html");
    let (listener, runtime) = initialize_runtime_then_bind(
        addr,
        || build_app(&args, apns, fcm, wns, docs_html),
        shutdown_app_runtime_after_startup_failure,
    )
    .await?;
    let AppRuntime { router, shutdown } = runtime;
    #[cfg(feature = "qa")]
    let shutdown = {
        let mut shutdown = shutdown;
        if let Some(directory) = args.qa_resource_observation_dir.as_deref()
            && let Err(error) =
                shutdown.start_qa_resource_observation(directory, qa_allocator_snapshot)
        {
            let _ = shutdown.shutdown(APP_SHUTDOWN_GRACE).await;
            return Err(error.into());
        }
        shutdown
    };

    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "gateway.listening",
        http_addr = %(addr.to_string())
    );
    let private = shutdown.private_state();
    let mut failure = shutdown.failure_receiver();
    let stop_claims = shutdown.ordinary_stop_requester();
    let counters = shutdown.ordinary_counters();
    let (http_stop, stop_rx) = watch::channel(false);
    // This is the normal Gateway router and its only HTTP listener. The
    // connection driver adds bounded transport ownership before request tasks.
    let mut serve = Box::pin(pushgo_gateway::ordinary::server::serve(
        listener,
        router,
        pushgo_gateway::ordinary::server::HttpLimits::default(),
        counters,
        stop_rx,
    ));
    let (initial_serve_result, runtime_failure) = tokio::select! {
        biased;
        reason = wait_runtime_failure(&mut failure) => (None, Some(reason)),
        result = &mut serve => (Some(result), None),
        _ = shutdown_signal() => (None, None),
    };
    let http_ended_unexpectedly = initial_serve_result.is_some();
    stop_claims.send_replace(true);
    if let Some(private) = private {
        private.begin_shutdown();
    }
    http_stop.send_replace(true);
    let deadline = TokioInstant::now() + APP_SHUTDOWN_GRACE;
    let (serve_result, shutdown_report, http_shutdown_timed_out) =
        if let Some(result) = initial_serve_result {
            (
                Some(result),
                Some(shutdown.shutdown_until(deadline).await),
                false,
            )
        } else {
            finish_shutdown_until(&mut serve, shutdown.shutdown_until(deadline), deadline).await
        };
    // A timed-out connection is aborted by dropping the driver's JoinSet.
    // AppShutdown has not been polled in that case: its abnormal Drop retains
    // dataset ownership until this process exits, so a replacement cannot race
    // an old HTTP/SQL operation that is still being cancelled.
    drop(serve);
    if http_shutdown_timed_out {
        return Err(
            "HTTP graceful shutdown deadline exceeded; product owner retained until process exit"
                .into(),
        );
    }
    let shutdown_report = shutdown_report.expect("HTTP drained before application shutdown");
    if let Some(result) = serve_result {
        result?;
    }
    if let Some(reason) = runtime_failure {
        return Err(format!("product runtime failed; restart required: {reason}").into());
    }
    if http_ended_unexpectedly {
        return Err("HTTP listener ended unexpectedly".into());
    }
    if shutdown_report.panicked > 0 || shutdown_report.aborted > 0 || shutdown_report.failed > 0 {
        return Err(format!(
            "application runtime did not shut down cleanly: panicked={}, aborted={}, failed={}",
            shutdown_report.panicked, shutdown_report.aborted, shutdown_report.failed,
        )
        .into());
    }

    Ok(())
}

type ProviderClients = (
    Arc<dyn pushgo_gateway::providers::ApnsClient>,
    Arc<dyn pushgo_gateway::providers::FcmClient>,
    Arc<dyn pushgo_gateway::providers::WnsClient>,
);

fn provider_clients(
    args: &Args,
    tuning: RuntimeTuning,
    apns_endpoint: &str,
    token_service_url: &str,
) -> Result<ProviderClients, Box<dyn Error>> {
    #[cfg(feature = "qa")]
    if let Some(directory) = args.qa_provider_fixture_dir.as_deref() {
        if !args.http_addr.parse::<SocketAddr>()?.ip().is_loopback() {
            return Err("QA Provider fixtures require a loopback HTTP listener".into());
        }
        // The feature-only fixture is selected before creating token owners or
        // real Provider clients. It cannot enter a normal product build.
        return Ok(pushgo_gateway::qa::ProductMockClients::from_directory(directory)?.clients());
    }
    #[cfg(not(feature = "qa"))]
    let _ = args;
    let client = pushgo_gateway::token_service_http_client()?;
    let apns_tokens = pushgo_gateway::remote_apns_token_provider(token_service_url, client.clone());
    let fcm_tokens = pushgo_gateway::remote_fcm_token_provider(token_service_url, client.clone());
    let wns_tokens = pushgo_gateway::remote_wns_token_provider(token_service_url, client);
    Ok((
        Arc::new(ApnsService::new_with_connection_budget(
            apns_tokens,
            apns_endpoint,
            tuning.providers.apns,
        )?),
        Arc::new(FcmService::new_with_connection_budget(
            fcm_tokens,
            FCM_SEND_BASE_URL,
            tuning.providers.fcm,
        )?),
        Arc::new(WnsService::new(wns_tokens)?),
    ))
}

async fn initialize_runtime_then_bind<R, Init, InitFuture, Cleanup, CleanupFuture>(
    addr: SocketAddr,
    initialize: Init,
    cleanup: Cleanup,
) -> Result<(TcpListener, R), Box<dyn Error>>
where
    Init: FnOnce() -> InitFuture,
    InitFuture: Future<Output = Result<R, Box<dyn Error>>>,
    Cleanup: FnOnce(R) -> CleanupFuture,
    CleanupFuture: Future<Output = ()>,
{
    // Storage/bootstrap and every other fallible correctness gate owned by
    // application initialization must complete before the public socket can
    // accept a TCP handshake.
    let runtime = initialize().await?;
    match TcpListener::bind(addr).await {
        Ok(listener) => Ok((listener, runtime)),
        Err(err) => {
            cleanup(runtime).await;
            Err(Box::new(err))
        }
    }
}

async fn shutdown_app_runtime_after_startup_failure(runtime: AppRuntime) {
    let AppRuntime { router, shutdown } = runtime;
    // Release HTTP-owned dispatch senders before joining provider workers.
    drop(router);
    let report = shutdown.shutdown(APP_SHUTDOWN_GRACE).await;
    let clean = report.panicked == 0 && report.aborted == 0 && report.failed == 0;
    if clean {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "gateway.startup_bind_failed_shutdown_finished",
            joined = (report.joined as u64),
            panicked = (report.panicked as u64),
            aborted = (report.aborted as u64)
        );
    } else {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::ERROR,
            event = "gateway.startup_bind_failed_shutdown_finished",
            joined = (report.joined as u64),
            panicked = (report.panicked as u64),
            aborted = (report.aborted as u64)
        );
    }
}

async fn finish_shutdown_until<S, H, R>(
    serve: &mut S,
    app_shutdown: H,
    deadline: TokioInstant,
) -> (Option<S::Output>, Option<R>, bool)
where
    S: Future + Unpin,
    H: Future<Output = R>,
{
    match timeout_at(deadline, serve).await {
        Ok(result) => (Some(result), Some(app_shutdown.await), false),
        // Dropping the unpolled shutdown future keeps normal Storage and the
        // exclusive owner out of their orderly close/release path.
        Err(_) => (None, None, true),
    }
}

async fn wait_runtime_failure(failure: &mut watch::Receiver<Option<String>>) -> String {
    loop {
        if let Some(reason) = failure.borrow().clone() {
            return reason;
        }
        if failure.changed().await.is_err() {
            return "product health owner disappeared".into();
        }
    }
}

async fn run_db_upgrade_subpath(args: &Args, raw_mode: &str) -> Result<(), Box<dyn Error>> {
    let mode = match raw_mode.trim().to_ascii_lowercase().as_str() {
        "plan" => UpgradeMode::PlanOnly,
        "run" | "execute" => UpgradeMode::Execute,
        other => {
            return Err(
                format!("invalid --db-upgrade value `{other}` (expected plan or run)").into(),
            );
        }
    };
    let config = StorageInitConfig {
        db_url: args.db_url.clone(),
        runtime_profile: args.runtime_profile()?,
        mcp_enabled: args.mcp_enabled,
        managed_upgrade: false,
    };
    if matches!(mode, UpgradeMode::PlanOnly) {
        UpgradeManager::new(config).run(mode).await?;
    } else {
        pushgo_gateway::ordinary::owner::run_exclusive_upgrade(config, mode).await?;
    }
    Ok(())
}

fn init_native_tracing(log_level: ObservabilityLogLevel) {
    let default_directive = log_level.as_str();
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_target(true)
        .with_thread_ids(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_ansi(false)
        .finish();
    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("native tracing init failed: {err}");
    }
}

/// Wait for Ctrl+C or SIGTERM, then trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut term) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            term.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn apns_endpoint(sandbox_mode: bool) -> &'static str {
    if sandbox_mode {
        APNS_SANDBOX_ENDPOINT
    } else {
        APNS_PRODUCTION_ENDPOINT
    }
}

fn print_startup_diagnostics(
    args: &Args,
    private_transports: PrivateTransports,
    observability: &ObservabilityConfig,
    runtime_tuning: RuntimeTuning,
    apns_endpoint: &str,
    token_service_url: &str,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "gateway.startup",
        http_addr = %(args.http_addr.as_str()),
        sandbox_mode = (args.sandbox_mode),
        private_channel_enabled = (private_transports.any_enabled()),
        private_transport_quic_enabled = (private_transports.quic),
        private_transport_tcp_enabled = (private_transports.tcp),
        private_transport_wss_enabled = (private_transports.wss),
        runtime_profile = %(runtime_tuning.profile.as_str()),
        private_online_fast_path_enabled = (runtime_tuning.private.online_fast_path_enabled),
        runtime_counter_channel_capacity = (runtime_tuning.runtime_counters.channel_capacity as u64),
        // Configured resource limits, not live allocations or open connection counts.
        provider_apns_owned_attempt_limit = (runtime_tuning.providers.apns as u64),
        provider_fcm_owned_attempt_limit = (runtime_tuning.providers.fcm as u64),
        provider_wns_owned_attempt_limit = (runtime_tuning.providers.wns as u64),
        sqlite_core_read_connection_limit = (runtime_tuning.sqlite.core_read_connections as u64),
        sqlite_page_cache_kib = (runtime_tuning.sqlite.page_cache_kib),
        external_db_max_connections = (runtime_tuning.external_db.max_connections as u64),
        external_db_min_connections = (runtime_tuning.external_db.min_connections as u64),
        device_cache_max_entries = (runtime_tuning.cache.device_max as u64),
        dispatch_targets_cache_max_entries = (runtime_tuning.cache.dispatch_targets_max as u64),
        observability_log_level = %(observability.log_level.as_str()),
        db_observability_enabled = false,
        mcp_enabled = (args.mcp_enabled),
        apns_endpoint = %(apns_endpoint),
        token_service_url = %(token_service_url)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;

    #[test]
    fn startup_diagnostics_report_resource_limits_without_retired_dispatch_fields() {
        #[derive(Clone)]
        struct LogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for LogWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        for (profile, read_limit, page_kib, db_min, db_max, device_max, targets_max) in [
            ("small", 2, 512, 0, 8, 512, 512),
            ("public", 4, 4096, 4, 64, 4096, 8192),
        ] {
            let args = Args::parse_from([
                "gateway",
                "--db-url",
                "sqlite::memory:",
                "--runtime-profile",
                profile,
            ]);
            let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
            let writer = LogWriter(Arc::clone(&buffer));
            let subscriber = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                print_startup_diagnostics(
                    &args,
                    args.private_transports().unwrap(),
                    &args.observability_config(),
                    args.runtime_tuning().unwrap(),
                    APNS_PRODUCTION_ENDPOINT,
                    "http://127.0.0.1:1",
                );
            });
            let log: serde_json::Value = serde_json::from_slice(&buffer.lock().unwrap()).unwrap();
            let fields = log["fields"].as_object().unwrap();
            assert_eq!(fields["event"], "gateway.startup");
            assert_eq!(fields["runtime_profile"], profile);
            for (field, expected) in [
                ("sqlite_core_read_connection_limit", read_limit),
                ("sqlite_page_cache_kib", page_kib),
                ("external_db_min_connections", db_min),
                ("external_db_max_connections", db_max),
                ("device_cache_max_entries", device_max),
                ("dispatch_targets_cache_max_entries", targets_max),
            ] {
                assert_eq!(fields[field], expected, "{profile}: {field}");
            }
            for retired in [
                "dispatch_worker_count",
                "dispatch_queue_capacity",
                "provider_apns_max_in_flight",
                "provider_fcm_max_in_flight",
                "provider_wns_max_in_flight",
            ] {
                assert!(!fields.contains_key(retired), "retired field: {retired}");
            }
        }
    }

    #[tokio::test]
    async fn stalled_http_drain_keeps_application_shutdown_unpolled() {
        let mut stalled_http = Box::pin(std::future::pending::<Result<(), std::io::Error>>());
        let started = TokioInstant::now();
        let deadline = started + std::time::Duration::from_millis(25);
        let app_started = Arc::new(AtomicBool::new(false));
        let app_started_probe = Arc::clone(&app_started);

        let (serve_result, app_report, timed_out) = finish_shutdown_until(
            &mut stalled_http,
            async move {
                app_started_probe.store(true, Ordering::SeqCst);
                "app_shutdown_completed"
            },
            deadline,
        )
        .await;

        assert!(serve_result.is_none());
        assert!(timed_out);
        assert!(app_report.is_none());
        assert!(!app_started.load(Ordering::SeqCst));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "a stalled HTTP drain must remain bounded"
        );
    }

    #[tokio::test]
    async fn application_shutdown_starts_after_http_drain() {
        let http_finished = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&http_finished);
        let mut http = Box::pin(async move {
            tokio::task::yield_now().await;
            finished.store(true, Ordering::SeqCst);
            Ok::<(), std::io::Error>(())
        });
        let (result, report, timed_out) = finish_shutdown_until(
            &mut http,
            async move {
                assert!(http_finished.load(Ordering::SeqCst));
                "owner_can_close"
            },
            TokioInstant::now() + std::time::Duration::from_secs(1),
        )
        .await;
        assert!(!timed_out);
        assert!(result.unwrap().is_ok());
        assert_eq!(report, Some("owner_can_close"));
    }

    #[tokio::test]
    async fn runtime_failure_is_observed_even_before_first_watch_change() {
        let (failure, mut receiver) = watch::channel(Some("fixed owner lost".to_string()));
        assert_eq!(
            wait_runtime_failure(&mut receiver).await,
            "fixed owner lost"
        );
        failure.send_replace(None);
        drop(failure);
        assert_eq!(
            wait_runtime_failure(&mut receiver).await,
            "product health owner disappeared"
        );
    }

    #[tokio::test]
    async fn bind_failure_joins_initialized_runtime_and_preserves_bind_error() {
        let occupied = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupied listener should bind");
        let addr = occupied
            .local_addr()
            .expect("occupied address should exist");
        let joined = Arc::new(AtomicBool::new(false));
        let joined_after_cleanup = Arc::clone(&joined);

        struct OwnedTask {
            stop: oneshot::Sender<()>,
            handle: tokio::task::JoinHandle<()>,
        }

        let result = initialize_runtime_then_bind(
            addr,
            || async {
                let (stop, stop_rx) = oneshot::channel();
                let handle = tokio::spawn(async move {
                    let _ = stop_rx.await;
                });
                Ok(OwnedTask { stop, handle })
            },
            move |owned| async move {
                let _ = owned.stop.send(());
                owned
                    .handle
                    .await
                    .expect("owned startup task should join cleanly");
                joined_after_cleanup.store(true, Ordering::SeqCst);
            },
        )
        .await;
        let Err(result) = result else {
            panic!("occupied HTTP address must fail binding");
        };

        assert_eq!(
            result
                .downcast_ref::<std::io::Error>()
                .expect("original bind error should be preserved")
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        assert!(joined.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn failed_correctness_gate_never_binds_the_http_port() {
        let probe = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe listener should bind");
        let addr = probe.local_addr().expect("probe address should exist");
        drop(probe);

        let result = initialize_runtime_then_bind(
            addr,
            || async move {
                let before_gate_failure = TcpListener::bind(addr)
                    .await
                    .expect("HTTP port must remain unbound while correctness gates run");
                drop(before_gate_failure);
                Err::<(), Box<dyn Error>>(Box::new(std::io::Error::other(
                    "legacy pending acceptance order",
                )))
            },
            |_| async {},
        )
        .await;

        assert!(result.is_err());
        let after_gate_failure = TcpListener::bind(addr)
            .await
            .expect("failed correctness gate must leave the HTTP port unbound");
        drop(after_gate_failure);
    }
}
