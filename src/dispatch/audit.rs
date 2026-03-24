use std::{
    borrow::Cow,
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use serde::Serialize;

use crate::storage::Platform;

pub(crate) const DEFAULT_DISPATCH_AUDIT_CAPACITY: usize = 4096;
pub(crate) const MAX_DISPATCH_AUDIT_QUERY_LIMIT: usize = 500;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DispatchAuditEntry {
    pub timestamp_ms: i64,
    pub stage: String,
    pub correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_token: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_too_large: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DispatchAuditFilter<'a> {
    pub limit: usize,
    pub correlation_id: Option<&'a str>,
    pub delivery_id: Option<&'a str>,
    pub channel_id: Option<&'a str>,
}

pub(crate) struct DispatchAuditRecord<'a> {
    pub stage: &'static str,
    pub correlation_id: &'a str,
    pub delivery_id: Option<&'a str>,
    pub channel_id: Option<&'a str>,
    pub provider: Option<&'static str>,
    pub platform: Option<Platform>,
    pub path: Option<&'static str>,
    pub device_token: Option<&'a str>,
    pub success: Option<bool>,
    pub status_code: Option<u16>,
    pub invalid_token: Option<bool>,
    pub payload_too_large: Option<bool>,
    pub detail: Option<Cow<'a, str>>,
}

#[derive(Clone)]
pub(crate) struct DispatchAuditLog {
    capacity: usize,
    entries: Arc<Mutex<VecDeque<DispatchAuditEntry>>>,
}

impl DispatchAuditLog {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Arc::new(Mutex::new(VecDeque::with_capacity(capacity.max(1)))),
        }
    }

    pub(crate) fn record<'a>(&self, record: DispatchAuditRecord<'a>) {
        let mut entries = self.entries.lock().expect("dispatch audit lock poisoned");
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(DispatchAuditEntry {
            timestamp_ms: Utc::now().timestamp_millis(),
            stage: record.stage.to_string(),
            correlation_id: record.correlation_id.to_string(),
            delivery_id: record.delivery_id.map(ToString::to_string),
            channel_id: record.channel_id.map(ToString::to_string),
            provider: record.provider.map(ToString::to_string),
            platform: record.platform.map(platform_label).map(ToString::to_string),
            path: record.path.map(ToString::to_string),
            device_token: record.device_token.map(redact_device_token),
            success: record.success,
            status_code: record.status_code,
            invalid_token: record.invalid_token,
            payload_too_large: record.payload_too_large,
            detail: record.detail.map(|value| value.into_owned()),
        });
    }

    pub(crate) fn list_recent<'a>(
        &self,
        filter: DispatchAuditFilter<'a>,
    ) -> Vec<DispatchAuditEntry> {
        let limit = filter.limit.clamp(1, MAX_DISPATCH_AUDIT_QUERY_LIMIT);
        let entries = self.entries.lock().expect("dispatch audit lock poisoned");
        let mut out = Vec::with_capacity(limit);
        for entry in entries.iter().rev() {
            if !matches_filter(entry, filter) {
                continue;
            }
            out.push(entry.clone());
            if out.len() >= limit {
                break;
            }
        }
        out.reverse();
        out
    }
}

fn matches_filter(entry: &DispatchAuditEntry, filter: DispatchAuditFilter<'_>) -> bool {
    if let Some(correlation_id) = filter.correlation_id
        && entry.correlation_id != correlation_id
    {
        return false;
    }
    if let Some(delivery_id) = filter.delivery_id
        && entry.delivery_id.as_deref() != Some(delivery_id)
    {
        return false;
    }
    if let Some(channel_id) = filter.channel_id
        && entry.channel_id.as_deref() != Some(channel_id)
    {
        return false;
    }
    true
}

fn redact_device_token(token: &str) -> String {
    let visible = 8usize.min(token.len());
    format!("...{}", &token[token.len().saturating_sub(visible)..])
}

fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
    }
}

#[cfg(test)]
mod tests {
    use super::{DispatchAuditFilter, DispatchAuditLog, DispatchAuditRecord};

    #[test]
    fn ring_buffer_keeps_latest_entries() {
        let log = DispatchAuditLog::new(2);
        log.record(DispatchAuditRecord {
            stage: "a",
            correlation_id: "c1",
            delivery_id: Some("d1"),
            channel_id: None,
            provider: None,
            platform: None,
            path: None,
            device_token: None,
            success: None,
            status_code: None,
            invalid_token: None,
            payload_too_large: None,
            detail: None,
        });
        log.record(DispatchAuditRecord {
            stage: "b",
            correlation_id: "c2",
            delivery_id: Some("d2"),
            channel_id: None,
            provider: None,
            platform: None,
            path: None,
            device_token: None,
            success: None,
            status_code: None,
            invalid_token: None,
            payload_too_large: None,
            detail: None,
        });
        log.record(DispatchAuditRecord {
            stage: "c",
            correlation_id: "c3",
            delivery_id: Some("d3"),
            channel_id: None,
            provider: None,
            platform: None,
            path: None,
            device_token: None,
            success: None,
            status_code: None,
            invalid_token: None,
            payload_too_large: None,
            detail: None,
        });

        let entries = log.list_recent(DispatchAuditFilter {
            limit: 20,
            correlation_id: None,
            delivery_id: None,
            channel_id: None,
        });
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].stage, "b");
        assert_eq!(entries[1].stage, "c");
    }

    #[test]
    fn filter_by_delivery_id() {
        let log = DispatchAuditLog::new(8);
        for index in 0..3 {
            log.record(DispatchAuditRecord {
                stage: "enqueue",
                correlation_id: "corr",
                delivery_id: Some(if index == 1 { "d-hit" } else { "d-miss" }),
                channel_id: None,
                provider: None,
                platform: None,
                path: None,
                device_token: None,
                success: None,
                status_code: None,
                invalid_token: None,
                payload_too_large: None,
                detail: None,
            });
        }
        let entries = log.list_recent(DispatchAuditFilter {
            limit: 20,
            correlation_id: None,
            delivery_id: Some("d-hit"),
            channel_id: None,
        });
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].delivery_id.as_deref(), Some("d-hit"));
    }
}
