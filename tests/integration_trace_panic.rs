use pushgo_gateway::util::install_panic_trace_hook;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[test]
fn panic_hook_emits_runtime_panic_event_without_crashing_hook() {
    init_test_tracing();
    install_panic_trace_hook();

    let raw_payload = "integration-secret-device-key-1234567890abcdef";
    let thread = std::thread::Builder::new()
        .name("integration-trace-panic".to_string())
        .spawn({
            let panic_payload = raw_payload.to_string();
            move || panic!("{panic_payload}")
        })
        .expect("spawn panic thread");
    assert!(thread.join().is_err(), "panic thread should fail");
}

fn init_test_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("warn"))
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}
