use chrono::Utc;
use serde_json::{Map, Value, json};
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    panic,
    path::{Path, PathBuf},
    sync::{Mutex, Once, OnceLock},
};

use super::{is_trace_logs_mode, redact_text};

const TRACE_LOG_ROTATE_MAX_BYTES: u64 = 64 * 1024 * 1024;
const TRACE_LOG_ROTATE_KEEP_FILES: u32 = 5;

#[derive(Default)]
struct TraceSink {
    file: Option<BufWriter<std::fs::File>>,
    path: Option<PathBuf>,
}

fn trace_sink() -> &'static Mutex<TraceSink> {
    static TRACE_SINK: OnceLock<Mutex<TraceSink>> = OnceLock::new();
    TRACE_SINK.get_or_init(|| Mutex::new(TraceSink::default()))
}

pub fn install_panic_trace_hook() {
    static INSTALL_ONCE: Once = Once::new();
    INSTALL_ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            let mut event = TraceEvent::new("runtime.panic")
                .field_str(
                    "thread",
                    std::thread::current().name().unwrap_or("<unnamed>"),
                )
                .field_redacted("panic_message", panic_message(panic_info));
            if let Some(location) = panic_info.location() {
                event = event
                    .field_str("panic_file", location.file())
                    .field_u64("panic_line", u64::from(location.line()))
                    .field_u64("panic_column", u64::from(location.column()));
            }
            let backtrace = std::backtrace::Backtrace::force_capture().to_string();
            event.field_redacted("backtrace", backtrace).emit();
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

pub fn set_trace_log_file(path: &str) -> std::io::Result<()> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "trace log file path cannot be empty",
        ));
    }

    let normalized_path = PathBuf::from(normalized);
    if let Some(parent) = normalized_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let writer = open_trace_writer(normalized_path.as_path())?;
    if let Ok(mut sink) = trace_sink().lock() {
        sink.path = Some(normalized_path);
        sink.file = Some(writer);
    }
    Ok(())
}

fn open_trace_writer(path: &Path) -> std::io::Result<BufWriter<std::fs::File>> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(BufWriter::new(file))
}

fn write_trace_line(line: &str) {
    if let Ok(mut sink) = trace_sink().lock()
        && prepare_sink_for_write(&mut sink, line.len()).is_ok()
        && let Some(file) = sink.file.as_mut()
        && file.write_all(line.as_bytes()).is_ok()
        && file.write_all(b"\n").is_ok()
        && file.flush().is_ok()
    {
        return;
    }
    eprintln!("{line}");
}

fn prepare_sink_for_write(sink: &mut TraceSink, incoming_len: usize) -> std::io::Result<()> {
    let Some(path) = sink.path.clone() else {
        return Ok(());
    };

    maybe_rotate_trace_file(
        sink,
        path.as_path(),
        incoming_len,
        TRACE_LOG_ROTATE_MAX_BYTES,
        TRACE_LOG_ROTATE_KEEP_FILES,
    )?;

    if sink.file.is_none() {
        sink.file = Some(open_trace_writer(path.as_path())?);
    }
    Ok(())
}

fn maybe_rotate_trace_file(
    sink: &mut TraceSink,
    path: &Path,
    incoming_len: usize,
    max_bytes: u64,
    keep_files: u32,
) -> std::io::Result<()> {
    if max_bytes == 0 {
        return Ok(());
    }

    let existing_len = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    let incoming = u64::try_from(incoming_len.saturating_add(1)).unwrap_or(u64::MAX);
    if existing_len.saturating_add(incoming) <= max_bytes {
        return Ok(());
    }

    if let Some(file) = sink.file.as_mut() {
        let _ = file.flush();
    }
    sink.file = None;
    rotate_trace_files(path, keep_files)
}

fn rotate_trace_files(path: &Path, keep_files: u32) -> std::io::Result<()> {
    if keep_files == 0 {
        return remove_file_if_exists(path);
    }

    remove_file_if_exists(rotated_trace_path(path, keep_files).as_path())?;
    for index in (1..keep_files).rev() {
        rename_file_if_exists(
            rotated_trace_path(path, index).as_path(),
            rotated_trace_path(path, index + 1).as_path(),
        )?;
    }
    rename_file_if_exists(path, rotated_trace_path(path, 1).as_path())
}

fn rotated_trace_path(path: &Path, index: u32) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(format!(".{index}"));
    PathBuf::from(os)
}

fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn rename_file_if_exists(source: &Path, target: &Path) -> std::io::Result<()> {
    match std::fs::rename(source, target) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
pub struct TraceEvent {
    event: &'static str,
    fields: Map<String, Value>,
}

impl TraceEvent {
    pub fn new(event: &'static str) -> Self {
        Self {
            event,
            fields: Map::new(),
        }
    }

    pub fn field_str(mut self, key: &'static str, value: impl AsRef<str>) -> Self {
        self.fields
            .insert(key.to_string(), Value::String(value.as_ref().to_string()));
        self
    }

    pub fn field_redacted(mut self, key: &'static str, value: impl AsRef<str>) -> Self {
        self.fields
            .insert(key.to_string(), Value::String(redact_text(value.as_ref())));
        self
    }

    pub fn field_bool(mut self, key: &'static str, value: bool) -> Self {
        self.fields.insert(key.to_string(), Value::Bool(value));
        self
    }

    pub fn field_u64(mut self, key: &'static str, value: u64) -> Self {
        self.fields.insert(key.to_string(), json!(value));
        self
    }

    pub fn field_i64(mut self, key: &'static str, value: i64) -> Self {
        self.fields.insert(key.to_string(), json!(value));
        self
    }

    pub fn emit(self) {
        if !is_trace_logs_mode() {
            return;
        }
        let mut record = self.into_record();
        record.insert(
            "component".to_string(),
            Value::String("gateway".to_string()),
        );
        match serde_json::to_string(&Value::Object(record)) {
            Ok(line) => write_trace_line(&line),
            Err(err) => write_trace_line(&format!(
                "{{\"component\":\"gateway\",\"event\":\"trace_encode_failed\",\"error\":\"{}\"}}",
                err
            )),
        }
    }

    fn into_record(self) -> Map<String, Value> {
        let mut record = Map::new();
        record.insert("ts_ms".to_string(), json!(Utc::now().timestamp_millis()));
        record.insert("event".to_string(), Value::String(self.event.to_string()));
        for (key, value) in self.fields {
            record.insert(key, value);
        }
        record
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{TraceEvent, rotate_trace_files, rotated_trace_path};

    #[test]
    fn trace_event_keeps_shape_and_redacts_sensitive_fields() {
        let record = TraceEvent::new("dispatch.provider_send_failed")
            .field_str("provider", "fcm")
            .field_redacted("device_key", "device-key-123456")
            .field_bool("invalid_token", false)
            .field_u64("status_code", 503)
            .into_record();

        assert_eq!(
            record.get("event").and_then(|value| value.as_str()),
            Some("dispatch.provider_send_failed")
        );
        assert_eq!(
            record.get("provider").and_then(|value| value.as_str()),
            Some("fcm")
        );
        let device_key = record
            .get("device_key")
            .and_then(|value| value.as_str())
            .expect("redacted device_key should exist");
        assert!(
            device_key.contains("..."),
            "redacted value should contain elision marker"
        );
        assert_eq!(
            record
                .get("invalid_token")
                .and_then(|value| value.as_bool()),
            Some(false)
        );
        assert_eq!(
            record.get("status_code").and_then(|value| value.as_u64()),
            Some(503)
        );
    }

    #[test]
    fn trace_file_rotation_rolls_current_and_keeps_latest_backups() {
        let trace_file = unique_trace_path("rotation");
        let backup_1 = rotated_trace_path(trace_file.as_path(), 1);
        let backup_2 = rotated_trace_path(trace_file.as_path(), 2);
        let backup_3 = rotated_trace_path(trace_file.as_path(), 3);

        std::fs::write(trace_file.as_path(), "current").expect("write trace file");
        std::fs::write(backup_1.as_path(), "prev-1").expect("write trace backup 1");
        std::fs::write(backup_2.as_path(), "prev-2").expect("write trace backup 2");

        rotate_trace_files(trace_file.as_path(), 2).expect("rotate trace files");

        assert_eq!(
            std::fs::read_to_string(backup_1.as_path()).expect("read backup 1"),
            "current"
        );
        assert_eq!(
            std::fs::read_to_string(backup_2.as_path()).expect("read backup 2"),
            "prev-1"
        );
        assert!(
            !backup_3.exists(),
            "backups older than keep-files limit should be removed"
        );

        let _ = std::fs::remove_file(trace_file);
        let _ = std::fs::remove_file(backup_1);
        let _ = std::fs::remove_file(backup_2);
    }

    fn unique_trace_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pushgo-gateway-trace-{tag}-{}-{nanos}.log",
            std::process::id()
        ))
    }
}
