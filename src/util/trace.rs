use std::panic;
use std::sync::Once;

use super::redact_text;

pub fn install_panic_trace_hook() {
    static INSTALL_ONCE: Once = Once::new();
    INSTALL_ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            let thread = std::thread::current();
            let thread_name = thread.name().unwrap_or("<unnamed>");
            let panic_message = panic_message(panic_info);
            let (panic_file, panic_line, panic_column) =
                if let Some(location) = panic_info.location() {
                    (
                        Some(location.file()),
                        Some(u64::from(location.line())),
                        Some(u64::from(location.column())),
                    )
                } else {
                    (None, None, None)
                };
            let backtrace = std::backtrace::Backtrace::force_capture().to_string();

            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::ERROR,
                event = "runtime.panic",
                thread = %(thread_name),
                panic_message = %(redact_text(panic_message)),
                panic_file = ?panic_file,
                panic_line = ?panic_line,
                panic_column = ?panic_column,
                backtrace = %(redact_text(backtrace))
            );

            previous(panic_info);
        }));
    });
}

fn panic_message(panic_info: &std::panic::PanicHookInfo<'_>) -> String {
    if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = panic_info.payload().downcast_ref::<String>() {
        return message.clone();
    }
    "<non_string_payload>".to_string()
}
