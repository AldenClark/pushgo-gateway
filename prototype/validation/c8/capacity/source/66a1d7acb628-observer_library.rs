//! Measurement-only post-COMMIT boundary. No unsafe code and no retained fields.
use std::sync::OnceLock;
pub type Observer = fn(&str, &str, i64, &str);
static OBSERVER: OnceLock<Observer> = OnceLock::new();
pub fn install(observer: Observer) -> Result<(), Observer> { OBSERVER.set(observer) }
pub(crate) fn committed(delivery: &str, device: &str, attempt: i64, state: &str) {
    if let Some(callback) = OBSERVER.get() { callback(delivery, device, attempt, state); }
}
