use std::sync::atomic::{AtomicBool, Ordering};

static SANDBOX_MODE: AtomicBool = AtomicBool::new(false);
static TRACE_LOGS_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_sandbox_mode(enabled: bool) {
    SANDBOX_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_sandbox_mode() -> bool {
    SANDBOX_MODE.load(Ordering::Relaxed)
}

pub fn set_trace_logs_mode(enabled: bool) {
    TRACE_LOGS_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_trace_logs_mode() -> bool {
    TRACE_LOGS_MODE.load(Ordering::Relaxed)
}
