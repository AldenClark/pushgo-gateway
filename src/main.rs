use std::{error::Error, net::SocketAddr, sync::Arc};

use clap::Parser;
use tokio::{net::TcpListener, signal};

use pushgo_gateway::{
    app::{AppRuntime, build_app},
    args::{Args, ObservabilityConfig, PrivateTransports},
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
    let private_transports = args.private_transports()?;
    let observability = args.observability_config();
    pushgo_gateway::util::set_sandbox_mode(args.sandbox_mode);
    pushgo_gateway::util::set_trace_logs_mode(observability.trace_logs_enabled);
    if observability.trace_logs_enabled {
        pushgo_gateway::util::set_trace_log_file(args.trace_log_file.as_str())?;
    }
    pushgo_gateway::util::install_panic_trace_hook();
    let apns_endpoint = apns_endpoint(args.sandbox_mode);
    let token_service_url = args.token_service_url.trim().to_string();
    print_startup_diagnostics(
        &args,
        private_transports,
        &observability,
        apns_endpoint,
        token_service_url.as_str(),
        args.trace_log_file.as_str(),
    );

    let client = reqwest::Client::builder()
        .user_agent(concat!("pushgo-gateway/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| pushgo_gateway::Error::Internal(err.to_string()))?;

    let apns_token_provider = Arc::new(RemoteApnsTokenProvider::new(
        token_service_url.as_str(),
        client.clone(),
    )?);
    let fcm_token_provider = Arc::new(RemoteFcmTokenProvider::new(
        token_service_url.as_str(),
        client.clone(),
    )?);
    let wns_token_provider = Arc::new(RemoteWnsTokenProvider::new(
        token_service_url.as_str(),
        client,
    )?);

    let apns = Arc::new(ApnsService::new(apns_token_provider, apns_endpoint)?);
    let fcm = Arc::new(FcmService::new(fcm_token_provider, FCM_SEND_BASE_URL)?);
    let wns = Arc::new(WnsService::new(wns_token_provider)?);

    let docs_html = include_str!("api/docs.html");
    let AppRuntime { router, private } = build_app(&args, apns, fcm, wns, docs_html).await?;

    let addr: SocketAddr = args.http_addr.parse()?;

    let listener = TcpListener::bind(addr).await?;
    pushgo_gateway::util::TraceEvent::new("gateway.listening")
        .field_str("http_addr", addr.to_string())
        .emit();
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(private))
    .await?;

    Ok(())
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
    trace_log_file: &str,
) {
    pushgo_gateway::util::TraceEvent::new("gateway.startup")
        .field_str("http_addr", args.http_addr.as_str())
        .field_bool("sandbox_mode", args.sandbox_mode)
        .field_bool("private_channel_enabled", private_transports.any_enabled())
        .field_bool("private_transport_quic_enabled", private_transports.quic)
        .field_bool("private_transport_tcp_enabled", private_transports.tcp)
        .field_bool("private_transport_wss_enabled", private_transports.wss)
        .field_str("observability_profile", observability.profile.as_str())
        .field_bool(
            "diagnostics_api_enabled",
            observability.diagnostics_api_enabled,
        )
        .field_bool("trace_logs_enabled", observability.trace_logs_enabled)
        .field_bool("stats_enabled", observability.stats_enabled)
        .field_bool("mcp_enabled", args.mcp_enabled)
        .field_str("apns_endpoint", apns_endpoint)
        .field_str("token_service_url", token_service_url)
        .field_str("trace_log_file", trace_log_file)
        .emit();
}
