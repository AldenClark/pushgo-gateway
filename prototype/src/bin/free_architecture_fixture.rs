//! Synthetic loopback-only fixture for the independent SQLite authority.
use clap::Parser;
use free_delivery_prototype::{BoundedListener, Config, DeliveryRuntime, RealProviders, router};
use std::{
    collections::BTreeMap,
    error::Error,
    future::IntoFuture,
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
    #[arg(long, default_value_t = 32)]
    provider_budget: usize,
    #[arg(long, default_value = "fixed", value_parser = ["demand", "fixed"])]
    concurrency_mode: String,
    #[arg(long, default_value_t = 32)]
    claim_quantum: usize,
    #[arg(long)]
    public_base_url: Option<String>,
}
#[tokio::main(worker_threads = 4)]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let authority = cli
        .mock_endpoint
        .strip_prefix("http://")
        .ok_or("loopback http mock required")?;
    let provider_addr: SocketAddr = authority.parse()?;
    if !provider_addr.ip().is_loopback()
        || provider_addr.port() == 0
        || !cli.http_addr.ip().is_loopback()
        || !cli.db_url.starts_with("sqlite://")
        || !matches!(cli.provider_budget, 8 | 32)
        || !matches!(cli.claim_quantum, 8 | 32)
    {
        return Err("fixture requires loopback HTTP, SQLite and budget 8 or 32".into());
    }
    let counts = Arc::new(Mutex::new(BTreeMap::<String, u64>::new()));
    tracing_subscriber::registry()
        .with(QueryCounts(counts.clone()))
        .try_init()?;
    let listener = TcpListener::bind(cli.http_addr).await?;
    let address = listener.local_addr()?;
    let config = Config {
        provider_budget: cli.provider_budget,
        claim_quantum: cli.claim_quantum,
        demand_scaling: cli.concurrency_mode == "demand",
        public_base_url: cli
            .public_base_url
            .unwrap_or_else(|| format!("http://{address}")),
        ..Config::default()
    };
    let transport = Arc::new(RealProviders::loopback(&cli.mock_endpoint)?);
    let mut runtime = DeliveryRuntime::start(&cli.db_url, config, transport.clone()).await?;
    let counters = runtime.store.counters.clone();
    let stat_counts = counts.clone();
    let stat_counters = counters.clone();
    let stats = Arc::new(move || {
        let mut data = stat_counters.snapshot();
        data["dbcounts"] = serde_json::to_value(&*stat_counts.lock().unwrap()).unwrap();
        data["transport_errors"] = serde_json::json!(transport.transport_errors());
        data["tasks"] = serde_json::json!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
        );
        data
    });
    let app = router(runtime.store.clone(), stats.clone());
    let (http_stop, mut http_rx) = watch::channel(false);
    let mut serve = tokio::spawn(
        axum::serve(
            BoundedListener::new(
                listener,
                runtime.store.config.max_handlers,
                counters.clone(),
            ),
            app,
        )
        .with_graceful_shutdown(async move {
            while !*http_rx.borrow() {
                if http_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .into_future(),
    );
    let (stat_stop, mut stat_rx) = watch::channel(false);
    let periodic = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {_ = stat_rx.changed()=>break,_=interval.tick()=>{let mut data=stats();data["kind"]=serde_json::json!("stats");data["unix_ms"]=serde_json::json!(chrono::Utc::now().timestamp_millis());println!("{data}");}}
        }
    });
    println!(
        "READY pid={} http_addr={} profile=free private=false mcp=false provider={} db_url={} tasks={}",
        std::process::id(),
        address,
        cli.mock_endpoint,
        cli.db_url,
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
