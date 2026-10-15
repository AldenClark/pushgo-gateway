//! Synthetic loopback-only fixture for the ordinary SQLite/PostgreSQL authority.
use clap::Parser;
use free_delivery_prototype::{
    Config, DeliveryRuntime, HttpLimits, RealProviders,
    credentials::{CredentialProvider, ExistingTokenCredentials, FixtureCredentials},
    router_with_auth, serve,
};
use std::{
    collections::BTreeMap,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::watch,
};
use tracing_subscriber::prelude::*;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    db_url: String,
    #[arg(long)]
    http_addr: SocketAddr,
    #[arg(long)]
    mock_endpoint: String,
    /// Explicit loopback synthetic Token Service; uses the existing Remote owners.
    #[arg(long)]
    mock_token_service_endpoint: Option<String>,
    #[arg(long)]
    provider_budget: Option<usize>,
    #[arg(long)]
    claim_quantum: Option<usize>,
    #[arg(long)]
    public_base_url: Option<String>,
    /// Name of an environment variable containing a synthetic shared token.
    #[arg(long)]
    shared_token_env: Option<String>,
}
#[tokio::main(worker_threads = 4)]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let authority = cli
        .mock_endpoint
        .strip_prefix("http://")
        .ok_or("loopback http mock required")?;
    let provider_addr: SocketAddr = authority.parse()?;
    let db_backend = if cli.db_url.starts_with("sqlite://") {
        "sqlite"
    } else {
        let database = reqwest::Url::parse(&cli.db_url)?;
        if !matches!(database.scheme(), "postgres" | "postgresql" | "mysql")
            || !database.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            })
            || !["c4_", "c5_"]
                .iter()
                .any(|prefix| database.path().trim_start_matches('/').starts_with(prefix))
            || database.query_pairs().any(|(key, _)| {
                matches!(
                    key.as_ref(),
                    "host" | "hostaddr" | "port" | "dbname" | "database" | "socket"
                )
            })
        {
            return Err(
                "fixture SQL requires an explicit loopback c4_/c5_ synthetic database without endpoint overrides".into(),
            );
        }
        if database.scheme() == "mysql" {
            "mysql"
        } else {
            "postgres"
        }
    };
    if !provider_addr.ip().is_loopback()
        || provider_addr.port() == 0
        || !cli.http_addr.ip().is_loopback()
    {
        return Err("fixture requires loopback HTTP".into());
    }
    let counts = Arc::new(Mutex::new(BTreeMap::<String, u64>::new()));
    tracing_subscriber::registry()
        .with(QueryCounts(counts.clone()))
        .try_init()?;
    let listener = TcpListener::bind(cli.http_addr).await?;
    let address = listener.local_addr()?;
    let defaults = Config::default();
    let provider_budget = cli.provider_budget.unwrap_or(defaults.provider_budget);
    let config = Config {
        provider_budget,
        claim_quantum: cli
            .claim_quantum
            .unwrap_or(defaults.claim_quantum.min(provider_budget)),
        public_base_url: cli
            .public_base_url
            .unwrap_or_else(|| format!("http://{address}")),
        ..Config::default()
    };
    let credentials: Arc<dyn CredentialProvider> = match cli.mock_token_service_endpoint.as_deref()
    {
        Some(endpoint) => Arc::new(ExistingTokenCredentials::loopback_remote(endpoint)?),
        None => Arc::new(FixtureCredentials),
    };
    let transport = Arc::new(RealProviders::loopback_with_credentials(
        &cli.mock_endpoint,
        config.provider_budget,
        credentials,
        Arc::from("io.ethan.pushgo"),
    )?);
    let mut runtime = DeliveryRuntime::start(&cli.db_url, config, transport.clone()).await?;
    let counters = runtime.store.counters.clone();
    let stat_counts = counts.clone();
    let stat_counters = counters.clone();
    let configured_budget = runtime.store.config.provider_budget;
    let configured_quantum = runtime.store.config.claim_quantum;
    let stats = Arc::new(move || {
        let mut data = stat_counters.snapshot();
        data["timings"] = stat_counters.timings.snapshot();
        data["configured"] = serde_json::json!({"provider_safety_ceiling":configured_budget,"claim_quantum":configured_quantum,"http_connections":HttpLimits::default().connections,"http2_streams_per_connection":HttpLimits::default().streams_per_connection,"request_body_bytes":32*1024,"provider_response_bytes":16*1024,"history_hard_quota":null});
        data["dbcounts"] = serde_json::to_value(&*stat_counts.lock().unwrap()).unwrap();
        data["transport_errors"] = serde_json::json!(transport.transport_errors());
        data["provider_response_oversize"] = serde_json::json!(transport.oversized_responses());
        data["provider_resources"] = transport.resource_snapshot();
        data["allocator"] = allocator_snapshot();
        data["tasks"] = serde_json::json!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
        );
        data
    });
    let shared_token = cli
        .shared_token_env
        .as_deref()
        .map(std::env::var)
        .transpose()?;
    if shared_token
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > 4096)
    {
        return Err("invalid shared-token configuration".into());
    }
    let app = router_with_auth(
        runtime.store.clone(),
        stats.clone(),
        shared_token.as_deref(),
    );
    drop(shared_token);
    let (http_stop, http_rx) = watch::channel(false);
    let mut serve = tokio::spawn(serve(
        listener,
        app,
        HttpLimits::default(),
        counters.clone(),
        http_rx,
    ));
    let (stat_stop, mut stat_rx) = watch::channel(false);
    let periodic = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {_ = stat_rx.changed()=>break,_=interval.tick()=>{let mut data=stats();data["kind"]=serde_json::json!("stats");data["unix_ms"]=serde_json::json!(chrono::Utc::now().timestamp_millis());println!("{data}");}}
        }
    });
    println!(
        "READY pid={} http_addr={} profile=free private=false mcp=false provider={} db_backend={} tasks={}",
        std::process::id(),
        address,
        cli.mock_endpoint,
        db_backend,
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    );
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _=terminate.recv()=>{},
        _=tokio::signal::ctrl_c()=>{},
        error=runtime.wait_failure()=>{eprintln!("FATAL owner driver: {error}");std::process::exit(70);},
        result=&mut serve=>{eprintln!("FATAL HTTP ended unexpectedly: {result:?}");std::process::exit(70);}
    }
    http_stop.send_replace(true);
    // Never unlock while live handlers or SQLx commands can still mutate.
    let grace = Duration::from_secs(20);
    match tokio::time::timeout(grace, &mut serve).await {
        Ok(Ok(Ok(()))) => {}
        result => {
            eprintln!("FATAL HTTP quiescence: {result:?}");
            std::process::exit(70);
        }
    }
    stat_stop.send_replace(true);
    let _ = periodic.await;
    let report = match tokio::time::timeout(grace, runtime.shutdown()).await {
        Ok(report) => report,
        Err(_) => {
            eprintln!("FATAL authority quiescence timed out");
            std::process::exit(70);
        }
    };
    println!(
        "SHUTDOWN pid={} joined={} panicked={} aborted={} http_timed_out=false tasks={}",
        std::process::id(),
        report.joined,
        report.panicked,
        report.aborted,
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    );
    if report.panicked != 0 || report.aborted != 0 || report.failed != 0 {
        return Err("unclean driver shutdown".into());
    }
    Ok(())
}
// Actual SQLx QueryLogger events on completion/drop, not Store API counts or
// successful transactions. Never retain SQL or bound values in the observer.
struct QueryCounts(Arc<Mutex<BTreeMap<String, u64>>>);
// Measurement-only fixture surface. ABI checked against the installed macOS
// SDK malloc/malloc.h:534-539,614-615. Null zone sums all process malloc zones.
#[cfg(target_os = "macos")]
fn allocator_snapshot() -> serde_json::Value {
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
    // SAFETY: synchronous system API writes the correctly laid out live output;
    // the documented null zone selects all allocator zones in this process.
    unsafe {
        malloc_zone_statistics(std::ptr::null_mut(), &mut value);
    }
    serde_json::json!({"blocks_in_use":value.blocks_in_use,"bytes_in_use":value.size_in_use,"max_bytes_touched":value.max_size_in_use,"bytes_reserved":value.size_allocated,"scope":"process malloc zones; excludes non-malloc VM mappings"})
}
#[cfg(not(target_os = "macos"))]
fn allocator_snapshot() -> serde_json::Value {
    serde_json::Value::Null
}
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
            self.record_str(field, format!("{value:?}").trim_matches('"'));
        }
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for QueryCounts {
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        metadata.target() == "sqlx::query"
    }
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
