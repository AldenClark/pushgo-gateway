use std::{error::Error, net::SocketAddr, sync::Arc};

use clap::Parser;
use tokio::{net::TcpListener, signal};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use pushgo_gateway::{
    app::{AppRuntime, build_app},
    args::{Args, ObservabilityConfig, ObservabilityLogLevel, PrivateTransports},
    private::PrivateState,
    providers::{ApnsService, FcmService, WnsService},
};

use crate::token_providers::remote::{
    apns::ApnsTokenProvider as RemoteApnsTokenProvider,
    fcm::FcmTokenProvider as RemoteFcmTokenProvider,
    wns::WnsTokenProvider as RemoteWnsTokenProvider,
};

mod token_providers;

const APNS_PRODUCTION_ENDPOINT: &str = "https://api.push.apple.com";
const APNS_SANDBOX_ENDPOINT: &str = "https://api.sandbox.push.apple.com";
const FCM_SEND_BASE_URL: &str = "https://fcm.googleapis.com";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse().normalized();
    if let Some(raw_level) = args.observability_log_level.as_deref()
        && ObservabilityLogLevel::parse(raw_level).is_none()
    {
        eprintln!("invalid observability log level `{raw_level}`, fallback to default `warn`");
    }
    let private_transports = args.private_transports()?;
    let observability = args.observability_config();
    init_native_tracing(observability.log_level);
    pushgo_gateway::util::set_sandbox_mode(args.sandbox_mode);
    pushgo_gateway::util::install_panic_trace_hook();
    let apns_endpoint = apns_endpoint(args.sandbox_mode);
    let token_service_url = args.token_service_base_url()?;
    print_startup_diagnostics(
        &args,
        private_transports,
        &observability,
        apns_endpoint,
        token_service_url.as_str(),
    );

    let client = reqwest::Client::builder()
        .user_agent(concat!("pushgo-gateway/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| pushgo_gateway::Error::Internal(err.to_string()))?;

    let apns_token_provider = Arc::new(RemoteApnsTokenProvider::new(
        token_service_url.as_str(),
        client.clone(),
    ));
    let fcm_token_provider = Arc::new(RemoteFcmTokenProvider::new(
        token_service_url.as_str(),
        client.clone(),
    ));
    let wns_token_provider = Arc::new(RemoteWnsTokenProvider::new(
        token_service_url.as_str(),
        client,
    ));

    let apns = Arc::new(ApnsService::new(apns_token_provider, apns_endpoint)?);
    let fcm = Arc::new(FcmService::new(fcm_token_provider, FCM_SEND_BASE_URL)?);
    let wns = Arc::new(WnsService::new(wns_token_provider)?);

    let docs_html = include_str!("api/docs.html");
    let AppRuntime { router, private } = build_app(&args, apns, fcm, wns, docs_html).await?;

    let addr: SocketAddr = args.http_addr.parse()?;

    let listener = TcpListener::bind(addr).await?;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "gateway.listening",
        http_addr = %(addr.to_string())
    );
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(private))
    .await?;

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
        observability_profile = %(observability.profile.as_str()),
        private_online_fast_path_enabled = (args.private_online_fast_path_enabled_resolved()),
        diagnostics_api_enabled = (observability.diagnostics_api_enabled),
        observability_log_level = %(observability.log_level.as_str()),
        stats_enabled = (observability.stats_enabled),
        mcp_enabled = (args.mcp_enabled),
        apns_endpoint = %(apns_endpoint),
        token_service_url = %(token_service_url)
    );
}
