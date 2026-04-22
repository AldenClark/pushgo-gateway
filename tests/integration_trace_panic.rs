use std::path::{Path, PathBuf};

use pushgo_gateway::util::{
    install_panic_trace_hook, is_trace_logs_mode, set_trace_log_file, set_trace_logs_mode,
};

#[test]
fn panic_hook_writes_runtime_panic_event_to_trace_file() {
    let trace_file = unique_trace_file_path();
    cleanup_trace_files(trace_file.as_path());

    let _mode_guard = TraceModeGuard::new();
    set_trace_logs_mode(true);
    set_trace_log_file(
        trace_file
            .to_str()
            .expect("trace file path should be valid UTF-8"),
    )
    .expect("set trace log file");
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

    let trace_content = std::fs::read_to_string(trace_file.as_path()).expect("read trace file");
    assert!(
        trace_content
            .lines()
            .any(|line| line.contains("\"event\":\"runtime.panic\"")),
        "trace should include runtime.panic event"
    );
    assert!(
        trace_content.contains("\"thread\":\"integration-trace-panic\""),
        "trace should include thread name"
    );
    assert!(
        trace_content.contains("\"panic_message\""),
        "trace should include panic message field"
    );
    assert!(
        trace_content.contains("\"backtrace\""),
        "trace should include backtrace field"
    );
    assert!(
        !trace_content.contains(raw_payload),
        "trace payload should be redacted"
    );

    cleanup_trace_files(trace_file.as_path());
}

struct TraceModeGuard {
    previous: bool,
}

impl TraceModeGuard {
    fn new() -> Self {
        Self {
            previous: is_trace_logs_mode(),
        }
    }
}

impl Drop for TraceModeGuard {
    fn drop(&mut self) {
        set_trace_logs_mode(self.previous);
    }
}

fn unique_trace_file_path() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "pushgo-gateway-trace-panic-{}-{nanos}.log",
        std::process::id()
    ))
}

fn cleanup_trace_files(trace_file: &Path) {
    let _ = std::fs::remove_file(trace_file);
    for index in 1..=5 {
        let _ = std::fs::remove_file(format!("{}.{}", trace_file.display(), index));
    }
}
