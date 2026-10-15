// Common local fixture; root builds all candidates serially in Release.
use clap::Parser;
use pushgo_gateway::{
    Error as GatewayError,
    app::{AppRuntime, build_app},
    args::Args,
    providers::{
        ApnsService, ApnsTokenProvider, BoxFuture, FcmAccess, FcmService, FcmTokenProvider,
        TokenInfo, WnsService, WnsTokenProvider,
    },
};
use std::{error::Error, future::IntoFuture, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::oneshot,
};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    db_url: String,
    #[arg(long)]
    http_addr: SocketAddr,
    #[arg(long)]
    mock_endpoint: String,
}

struct LocalTokens;
fn local_token() -> TokenInfo {
    TokenInfo {
        token: Arc::from("fixture-local-only"),
        expires_in: 3600,
    }
}
impl ApnsTokenProvider for LocalTokens {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, GatewayError>> {
        Box::pin(async { Ok(local_token()) })
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, GatewayError>> {
        ApnsTokenProvider::token_info(self)
    }
    fn refresh_now<'a>(&'a self) -> BoxFuture<'a, Result<Arc<str>, GatewayError>> {
        Box::pin(async { Ok(local_token().token) })
    }
}
impl FcmTokenProvider for LocalTokens {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, GatewayError>> {
        Box::pin(async {
            Ok(FcmAccess {
                token: local_token(),
                project_id: Arc::from("fixture-project"),
            })
        })
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, GatewayError>> {
        FcmTokenProvider::token_info(self)
    }
}
impl WnsTokenProvider for LocalTokens {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, GatewayError>> {
        // WNS takes a channel URL from each device route: fail before any network IO.
        Box::pin(async { Err(GatewayError::Internal("WNS unused in local fixture".into())) })
    }
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, GatewayError>> {
        WnsTokenProvider::token_info(self)
    }
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let counts = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<
        String,
        u64,
    >::new()));
    use tracing_subscriber::prelude::*;
    tracing_subscriber::registry()
        .with(QueryCounts(counts.clone()))
        .with(tracing_subscriber::fmt::layer().json().with_ansi(false).with_filter(tracing_subscriber::filter::filter_fn(|meta| meta.target() == "gateway.trace_event" && *meta.level() <= tracing::Level::WARN)))
        .try_init()?;
    let periodic_counts = counts.clone();
    let stats = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            println!(
                "{}",
                serde_json::json!({"kind":"stats", "unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), "tasks":tokio::runtime::Handle::current().metrics().num_alive_tasks(), "dbcounts":*periodic_counts.lock().unwrap()})
            );
        }
    });
    let authority = cli
        .mock_endpoint
        .strip_prefix("http://")
        .ok_or("FCM endpoint must be http://127.0.0.1:<port>")?;
    let provider_addr: SocketAddr = authority.parse()?;
    if !provider_addr.ip().is_loopback()
        || provider_addr.port() == 0
        || !cli.http_addr.ip().is_loopback()
        || !cli.db_url.starts_with("sqlite://")
    {
        return Err("fixture requires loopback HTTP/provider endpoints and SQLite".into());
    }
    let mut args = Args::parse_from(["resource-fixture"]).normalized();
    args.http_addr = cli.http_addr.to_string();
    args.db_url = Some(cli.db_url);
    args.runtime_profile = "small".into();
    args.private_transports = "false".into();
    args.mcp_enabled = false;
    args.token = Some(std::env::var("DUAL_ROUTE_TEST_AUTH")?);
    args.token_service_url = "http://127.0.0.1:1".into();
    let profile = args.runtime_tuning()?.profile.as_str();
    let apns = Arc::new(ApnsService::new(Arc::new(LocalTokens), &cli.mock_endpoint)?);
    let fcm = Arc::new(FcmService::new(Arc::new(LocalTokens), &cli.mock_endpoint)?);
    let wns = Arc::new(WnsService::new(Arc::new(LocalTokens))?);
    let AppRuntime { router, shutdown } = build_app(&args, apns, fcm, wns, "local fixture").await?;
    // Fixture-only loopback snapshot; no DB query or product instrumentation.
    let router = router.route("/__fixture/stats", axum::routing::get(move || {
        let counts = counts.clone();
        async move {
            axum::Json(serde_json::json!({
                "unix_ms":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
                "tasks":tokio::runtime::Handle::current().metrics().num_alive_tasks(),
                "dbcounts":*counts.lock().unwrap()
            }))
        }
    }));
    let listener = TcpListener::bind(cli.http_addr).await?;
    let actual_addr = listener.local_addr()?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let (signal_tx, signal_rx) = oneshot::channel();
    let graceful = async move {
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
        let _ = signal_tx.send(());
    };
    let mut serve = Box::pin(
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(graceful)
        .into_future(),
    );
    println!(
        "READY pid={} http_addr={} profile={} private=false mcp=false provider={} db_url={} tasks={}",
        std::process::id(),
        actual_addr,
        profile,
        cli.mock_endpoint,
        args.db_url.as_deref().unwrap_or(""),
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    );
    let grace = Duration::from_secs(20);
    let (report, http_timed_out) = tokio::select! {
        result = &mut serve => {
            result?;
            (shutdown.shutdown(grace).await, false)
        }
        _ = signal_rx => {
            let deadline = tokio::time::Instant::now() + grace;
            let (report, served) = tokio::join!(
                shutdown.shutdown_until(deadline),
                tokio::time::timeout_at(deadline, &mut serve),
            );
            let timed_out = match served {
                Ok(result) => { result?; false }, Err(_) => true,
            };
            (report, timed_out)
        }
    };
    drop(serve);
    stats.abort();
    let _ = stats.await;
    println!(
        "SHUTDOWN pid={} joined={} panicked={} aborted={} http_timed_out={} tasks={}",
        std::process::id(),
        report.joined,
        report.panicked,
        report.aborted,
        http_timed_out,
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    );
    if report.panicked != 0 || report.aborted != 0 || http_timed_out {
        return Err("isolated Gateway did not shut down cleanly".into());
    }
    Ok(())
}

// SQLx QueryLogger emits on completion/drop. These are statement events, not
// successful transactions. Retain only the leading verb, never SQL or values.
struct QueryCounts(Arc<std::sync::Mutex<std::collections::BTreeMap<String, u64>>>);
struct QueryVerb(String);
impl tracing::field::Visit for QueryVerb {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "summary" {
            self.0 = value
                .split_whitespace()
                .next()
                .unwrap_or("OTHER")
                .to_ascii_uppercase();
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "summary" {
            self.record_str(field, &format!("{value:?}").trim_matches('"'));
        }
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for QueryCounts {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" {
            return;
        }
        let mut verb = QueryVerb("OTHER".into());
        event.record(&mut verb);
        let category = match verb.0.as_str() {
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "BEGIN" | "COMMIT" | "ROLLBACK"
            | "PRAGMA" | "CREATE" | "ALTER" => verb.0,
            _ => "OTHER".into(),
        };
        *self.0.lock().unwrap().entry(category).or_default() += 1;
    }
}
