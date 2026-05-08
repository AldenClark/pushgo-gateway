use std::sync::atomic::{AtomicBool, Ordering};

static SANDBOX_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_sandbox_mode(enabled: bool) {
    SANDBOX_MODE.store(enabled, Ordering::Relaxed);
}

pub fn is_sandbox_mode() -> bool {
    SANDBOX_MODE.load(Ordering::Relaxed)
}
