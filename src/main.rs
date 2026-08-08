use std::{
    error::Error,
    future::{Future, IntoFuture},
    net::SocketAddr,
    sync::Arc,
};

use clap::Parser;
use tokio::{
    net::TcpListener,
    signal,
    sync::oneshot,
    time::{Instant as TokioInstant, timeout_at},
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use pushgo_gateway::{
    app::{AppRuntime, build_app},
    args::{Args, ObservabilityConfig, ObservabilityLogLevel, PrivateTransports},
    private::PrivateState,
    providers::{ApnsService, FcmService, WnsService},
    runtime_config::RuntimeTuning,
    storage::{
        StorageInitConfig,
        database::upgrade::{UpgradeManager, UpgradeMode},
    },
};

use crate::token_providers::remote::{
    apns::ApnsTokenProvider as RemoteApnsTokenProvider,
    fcm::FcmTokenProvider as RemoteFcmTokenProvider, gateway::build_token_service_http_client,
    wns::WnsTokenProvider as RemoteWnsTokenProvider,
};

mod token_providers;

const APNS_PRODUCTION_ENDPOINT: &str = "https://api.push.apple.com";
const APNS_SANDBOX_ENDPOINT: &str = "https://api.sandbox.push.apple.com";
const FCM_SEND_BASE_URL: &str = "https://fcm.googleapis.com";
const APP_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(20);

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
    if let Some(mode) = args.db_upgrade.as_deref() {
        run_db_upgrade_subpath(&args, mode).await?;
        return Ok(());
    }
    let apns_endpoint = apns_endpoint(args.sandbox_mode);
    let token_service = args.token_service_client_config()?;
    print_startup_diagnostics(
        &args,
        private_transports,
        &observability,
        runtime_tuning,
        apns_endpoint,
        token_service.base_url(),
        token_service.auth_configured(),
    );

    let client = build_token_service_http_client()?;
    let authorization = token_service.authorization_header();

    let apns_token_provider = Arc::new(RemoteApnsTokenProvider::new(
        token_service.base_url(),
        authorization.clone(),
        client.clone(),
    ));
    let fcm_token_provider = Arc::new(RemoteFcmTokenProvider::new(
        token_service.base_url(),
        authorization.clone(),
        client.clone(),
    ));
    let wns_token_provider = Arc::new(RemoteWnsTokenProvider::new(
        token_service.base_url(),
        authorization,
        client,
    ));

    let apns = Arc::new(ApnsService::new_with_profile(
        apns_token_provider,
        apns_endpoint,
        runtime_tuning.profile,
    )?);
    let fcm = Arc::new(FcmService::new_with_profile(
        fcm_token_provider,
        FCM_SEND_BASE_URL,
        runtime_tuning.profile,
    )?);
    let wns = Arc::new(WnsService::new_with_profile(
        wns_token_provider,
        runtime_tuning.profile,
    )?);

    // Bind before starting any application-owned background task. A bind
    // failure must not leave a partially-started private runtime behind.
    let addr: SocketAddr = args.http_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    let docs_html = include_str!("api/docs.html");
    let AppRuntime { router, shutdown } = build_app(&args, apns, fcm, wns, docs_html).await?;

    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "gateway.listening",
        http_addr = %(addr.to_string())
    );
    let private = shutdown.private_state();
    let (shutdown_started_tx, mut shutdown_started_rx) = oneshot::channel();
    let graceful_shutdown = async move {
        shutdown_signal(private).await;
        let _ = shutdown_started_tx.send(());
    };
    let mut serve = Box::pin(
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(graceful_shutdown)
        .into_future(),
    );

    let (serve_result, shutdown_report, http_shutdown_timed_out) = tokio::select! {
        biased;
        result = &mut serve => {
            let report = shutdown.shutdown(APP_SHUTDOWN_GRACE).await;
            (Some(result), report, false)
        }
        signal_result = &mut shutdown_started_rx => {
            if signal_result.is_err() {
                // The notifier is owned by the HTTP serve future. It can only
                // disappear before sending if that future has already ended.
                let result = (&mut serve).await;
                let report = shutdown.shutdown(APP_SHUTDOWN_GRACE).await;
                (Some(result), report, false)
            } else {
                let deadline = TokioInstant::now() + APP_SHUTDOWN_GRACE;
                finish_shutdown_until(
                    &mut serve,
                    shutdown.shutdown_until(deadline),
                    deadline,
                )
                .await
            }
        }
    };
    // Axum owns per-connection tasks. Dropping the serve future after its
    // absolute deadline, followed by returning from `main`, makes Tokio abort
    // any connection that ignored graceful shutdown (for example a stalled
    // request body or upgraded connection).
    drop(serve);

    if http_shutdown_timed_out {
        return Err(format!(
            "HTTP graceful shutdown deadline exceeded: panicked={}, aborted={}",
            shutdown_report.panicked, shutdown_report.aborted
        )
        .into());
    }
    if let Some(serve_result) = serve_result {
        serve_result?;
    }
    if shutdown_report.panicked > 0 || shutdown_report.aborted > 0 {
        return Err(format!(
            "application runtime did not shut down cleanly: panicked={}, aborted={}",
            shutdown_report.panicked, shutdown_report.aborted
        )
        .into());
    }

    Ok(())
}

async fn finish_shutdown_until<S, H, R>(
    serve: &mut S,
    app_shutdown: H,
    deadline: TokioInstant,
) -> (Option<S::Output>, R, bool)
where
    S: Future + Unpin,
    H: Future<Output = R>,
{
    let (timed_serve_result, report) = tokio::join!(timeout_at(deadline, serve), app_shutdown,);
    match timed_serve_result {
        Ok(result) => (Some(result), report, false),
        Err(_) => (None, report, true),
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
    let manager = UpgradeManager::new(StorageInitConfig {
        db_url: args.db_url.clone(),
        runtime_profile: args.runtime_profile()?,
        mcp_enabled: args.mcp_enabled,
        managed_upgrade: false,
    });
    manager.run(mode).await?;
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
async fn shutdown_signal(private: Option<Arc<PrivateState>>) {
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

    if let Some(private) = private {
        private.begin_shutdown();
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
    token_service_auth_configured: bool,
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
        dispatch_worker_count = (runtime_tuning.dispatch.worker_count as u64),
        dispatch_queue_capacity = (runtime_tuning.dispatch.queue_capacity as u64),
        runtime_counter_channel_capacity = (runtime_tuning.runtime_counters.channel_capacity as u64),
        external_db_max_connections = (runtime_tuning.external_db.max_connections as u64),
        provider_apns_max_in_flight = (runtime_tuning.provider.apns_max_in_flight as u64),
        provider_fcm_max_in_flight = (runtime_tuning.provider.fcm_max_in_flight as u64),
        provider_wns_max_in_flight = (runtime_tuning.provider.wns_max_in_flight as u64),
        observability_log_level = %(observability.log_level.as_str()),
        db_observability_enabled = false,
        mcp_enabled = (args.mcp_enabled),
        apns_endpoint = %(apns_endpoint),
        token_service_url = %(token_service_url),
        token_service_auth_configured = token_service_auth_configured
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_http_drain_cannot_extend_the_absolute_shutdown_deadline() {
        let mut stalled_http = Box::pin(std::future::pending::<Result<(), std::io::Error>>());
        let started = TokioInstant::now();
        let deadline = started + std::time::Duration::from_millis(25);

        let (serve_result, app_report, timed_out) = finish_shutdown_until(
            &mut stalled_http,
            async {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                "app_shutdown_completed"
            },
            deadline,
        )
        .await;

        assert!(serve_result.is_none());
        assert!(timed_out);
        assert_eq!(app_report, "app_shutdown_completed");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "a stalled HTTP drain must remain bounded"
        );
    }
}
