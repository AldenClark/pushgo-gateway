//! Synthetic loopback-only fixture for the ordinary SQLite/PostgreSQL authority.
#[cfg(feature = "commit-observer")]
#[path = "support/commit_observer_fixture.rs"]
mod commit_observer_fixture;
use clap::Parser;
use free_delivery_prototype::{
    Config, DeliveryRuntime, HttpLimits, RealProviders,
    credentials::{CredentialProvider, ExistingTokenCredentials, FixtureCredentials},
    private_http::{PrivateHttp, discovery_profile},
    private_listeners::{self, PrivateListener},
    private_mqtt::{self, MqttListener},
    private_runtime::{PrivateRuntime, PrivateRuntimeConfig},
    router_with_private, serve,
};
use std::{
    collections::BTreeMap,
    error::Error,
    net::SocketAddr,
    path::PathBuf,
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
    /// Explicitly enable the synthetic ordinary Private owner (default disabled).
    #[arg(long)]
    private_enabled: bool,
    /// Plaintext loopback HTTP edge only; native WSS TLS is not emulated.
    #[arg(long, requires = "private_enabled")]
    private_wss_enabled: bool,
    #[arg(long, requires = "private_enabled")]
    private_tcp_addr: Option<SocketAddr>,
    #[arg(long, requires = "private_enabled")]
    private_quic_addr: Option<SocketAddr>,
    /// Main MQTT5 receiver's plaintext loopback edge.
    #[arg(long, requires = "private_enabled")]
    private_mqtt_addr: Option<SocketAddr>,
    /// Existing synthetic PEM files; the fixture only reads them.
    #[arg(long, requires = "private_enabled")]
    private_tls_cert: Option<PathBuf>,
    #[arg(long, requires = "private_enabled")]
    private_tls_key: Option<PathBuf>,
}
#[tokio::main(worker_threads = 4)]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    #[cfg(feature = "commit-observer")]
    let commit_session = std::env::var_os("C5_COMMIT_STREAM").map(|path|
        commit_observer_fixture::Session::start(std::path::Path::new(&path))).transpose()?;
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
            || !["c4_", "c5_", "c6_"]
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
                "fixture SQL requires an explicit loopback c4_/c5_/c6_ synthetic database without endpoint overrides".into(),
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
    for address in [
        cli.private_tcp_addr,
        cli.private_quic_addr,
        cli.private_mqtt_addr,
    ]
    .into_iter()
    .flatten()
    {
        if !address.ip().is_loopback() {
            return Err("Private fixture listeners require loopback".into());
        }
    }
    if cli.private_enabled
        && !cli.private_wss_enabled
        && cli.private_tcp_addr.is_none()
        && cli.private_quic_addr.is_none()
        && cli.private_mqtt_addr.is_none()
    {
        return Err("Private fixture requires at least one explicitly selected transport".into());
    }
    let needs_tls = cli.private_tcp_addr.is_some() || cli.private_quic_addr.is_some();
    if needs_tls && (cli.private_tls_cert.is_none() || cli.private_tls_key.is_none()) {
        return Err("Private TCP/QUIC requires explicit synthetic TLS certificate and key".into());
    }
    if cli.private_tls_cert.is_some() != cli.private_tls_key.is_some() {
        return Err("Private TLS certificate and key must be supplied together".into());
    }
    for path in [cli.private_tls_cert.as_ref(), cli.private_tls_key.as_ref()]
        .into_iter()
        .flatten()
    {
        // The isolated native driver can supply a fresh in-memory synthetic
        // signing identity through an inherited anonymous pipe. No key file or
        // credential store is needed for this test configuration.
        use std::os::unix::fs::FileTypeExt;
        if !path.is_file() && !path.metadata().is_ok_and(|m| m.file_type().is_fifo()) {
            return Err("Private synthetic TLS file is missing".into());
        }
    }
    let counts = Arc::new(Mutex::new(BTreeMap::<String, u64>::new()));
    tracing_subscriber::registry()
        .with(QueryCounts(counts.clone()))
        .try_init()?;
    let listener = TcpListener::bind(cli.http_addr).await?;
    let address = listener.local_addr()?;
    let defaults = Config::default();
    let provider_budget = cli.provider_budget.unwrap_or(defaults.provider_budget);
    let mut config = Config {
        provider_budget,
        claim_quantum: cli
            .claim_quantum
            .unwrap_or(defaults.claim_quantum.min(provider_budget)),
        public_base_url: cli
            .public_base_url
            .clone()
            .unwrap_or_else(|| format!("http://{address}")),
        ..Config::default()
    };
    config.private.enabled = cli.private_enabled;
    if cli.private_wss_enabled {
        let public = reqwest::Url::parse(&config.public_base_url)?;
        let loopback = public.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if public.scheme() != "http"
            || !loopback
            || public.port_or_known_default() != Some(address.port())
        {
            return Err(
                "Private WSS fixture requires its plaintext loopback HTTP edge public base URL"
                    .into(),
            );
        }
    }
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
    let mut private = if cli.private_enabled {
        match PrivateServices::start(&runtime, &cli, address, shared_token.clone()).await {
            Ok(private) => Some(private),
            Err(error) => {
                eprintln!("FATAL Private startup: {error}");
                std::process::exit(70);
            }
        }
    } else {
        None
    };
    let private_stats = private.as_ref().map(|p| p.runtime.clone());
    let counters = runtime.store.counters.clone();
    let stat_counts = counts.clone();
    let stat_counters = counters.clone();
    let configured_budget = runtime.store.config.provider_budget;
    let configured_quantum = runtime.store.config.claim_quantum;
    let stats = Arc::new(move || {
        let mut data = stat_counters.snapshot();
        data["timings"] = stat_counters.timings.snapshot();
        data["configured"] = serde_json::json!({"provider_safety_ceiling":configured_budget,"claim_quantum":configured_quantum,"http_connections":HttpLimits::default().connections,"http2_streams_per_connection":HttpLimits::default().streams_per_connection,"message_request_body_bytes":free_delivery_prototype::MESSAGE_SUBMISSION_BODY_BYTES,"control_request_body_bytes":free_delivery_prototype::Config::default().max_body_bytes,"provider_response_bytes":16*1024,"history_hard_quota":null});
        data["dbcounts"] = serde_json::to_value(&*stat_counts.lock().unwrap()).unwrap();
        data["transport_errors"] = serde_json::json!(transport.transport_errors());
        data["provider_response_oversize"] = serde_json::json!(transport.oversized_responses());
        data["provider_resources"] = transport.resource_snapshot();
        if let Some(private) = private_stats.as_ref() {
            data["private_resources"] = private.resource_snapshot();
        }
        data["allocator"] = allocator_snapshot();
        data["tasks"] = serde_json::json!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
        );
        data
    });
    let app = router_with_private(
        runtime.store.clone(),
        stats.clone(),
        shared_token.as_deref(),
        private.as_ref().map(|owner| owner.http.clone()),
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
        "READY pid={} http_addr={} profile=free private={} mcp=false provider={} db_backend={} tasks={}",
        std::process::id(),
        address,
        cli.private_enabled,
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
    // Fence new sessions and stop every acceptor before joining any owner.
    if let Some(private) = private.as_ref() {
        private.stop_accepting();
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
    if let Some(private) = private.as_mut() {
        if !matches!(
            tokio::time::timeout(Duration::from_secs(40), private.shutdown()).await,
            Ok(Ok(()))
        ) {
            eprintln!("FATAL Private owners did not join cleanly");
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
    #[cfg(feature = "commit-observer")]
    if let Some(session) = commit_session { session.finish()?; }
    if report.panicked != 0 || report.aborted != 0 || report.failed != 0 {
        eprintln!("FATAL unclean driver shutdown");
        std::process::exit(70);
    }
    Ok(())
}
struct PrivateServices {
    runtime: PrivateRuntime,
    http: PrivateHttp,
    tcp: Option<PrivateListener>,
    quic: Option<PrivateListener>,
    mqtt: Option<MqttListener>,
}
impl PrivateServices {
    async fn start(
        delivery: &DeliveryRuntime,
        cli: &Cli,
        http_addr: SocketAddr,
        token: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let runtime = PrivateRuntime::new(
            delivery.store.clone(),
            token,
            PrivateRuntimeConfig::default(),
        )?;
        let mut config = private_listeners::server_config();
        config.tls_cert_path = cli
            .private_tls_cert
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        config.tls_key_path = cli
            .private_tls_key
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        config.tcp_listen_addr = cli.private_tcp_addr.map(|a| a.to_string());
        config.quic_listen_addr = cli.private_quic_addr.map(|a| a.to_string());
        let tcp = if cli.private_tcp_addr.is_some() {
            Some(private_listeners::start_tcp(runtime.clone(), config.clone()).await?)
        } else {
            None
        };
        let quic = if cli.private_quic_addr.is_some() {
            Some(private_listeners::start_quic(runtime.clone(), config.clone()).await?)
        } else {
            None
        };
        let mqtt = if let Some(address) = cli.private_mqtt_addr {
            Some(private_mqtt::start_mqtt(runtime.clone(), address).await?)
        } else {
            None
        };
        let tcp_addr = tcp.as_ref().map(|p| p.local_addr);
        let quic_addr = quic.as_ref().map(|p| p.local_addr);
        let mqtt_addr = mqtt.as_ref().map(|p| p.local_addr);
        let profile = discovery_profile(
            &delivery.store.config.public_base_url,
            tcp_addr,
            quic_addr,
            mqtt_addr,
            cli.private_wss_enabled,
            http_addr.port(),
        );
        let http = PrivateHttp::new(runtime.clone(), config, profile);
        println!(
            "PRIVATE_READY tcp_addr={} quic_addr={} mqtt_addr={} wss_edge_plaintext={} ws_subprotocol=pushgo-private.v1",
            tcp_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "disabled".into()),
            quic_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "disabled".into()),
            mqtt_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "disabled".into()),
            cli.private_wss_enabled
        );
        Ok(Self {
            runtime,
            http,
            tcp,
            quic,
            mqtt,
        })
    }
    fn stop_accepting(&self) {
        if let Some(listener) = self.tcp.as_ref() {
            listener.stop_accepting();
        }
        if let Some(listener) = self.quic.as_ref() {
            listener.stop_accepting();
        }
        if let Some(listener) = self.mqtt.as_ref() {
            listener.stop_accepting();
        }
        self.runtime.begin_shutdown();
    }
    async fn shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        self.http.shutdown().await?;
        if let Some(listener) = self.tcp.as_mut() {
            listener.shutdown().await?;
        }
        if let Some(listener) = self.quic.as_mut() {
            listener.shutdown().await?;
        }
        if let Some(listener) = self.mqtt.as_mut() {
            listener.shutdown().await?;
        }
        self.runtime.shutdown().await?;
        Ok(())
    }
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
