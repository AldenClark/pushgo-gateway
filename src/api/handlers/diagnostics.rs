use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::{
    api::{Error, HttpResult},
    app::AppState,
    dispatch::audit::{DispatchAuditEntry, DispatchAuditFilter, MAX_DISPATCH_AUDIT_QUERY_LIMIT},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchDiagnosticsQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default)]
    delivery_id: Option<String>,
    #[serde(default)]
    channel_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct DispatchDiagnosticsResponse {
    count: usize,
    entries: Vec<DispatchAuditEntry>,
}

pub(crate) async fn diagnostics_dispatch(
    State(state): State<AppState>,
    Query(query): Query<DispatchDiagnosticsQuery>,
) -> HttpResult {
    let limit = query.limit.unwrap_or(100);
    if limit == 0 {
        return Err(Error::validation("limit must be greater than 0"));
    }
    if limit > MAX_DISPATCH_AUDIT_QUERY_LIMIT {
        return Err(Error::validation(format!(
            "limit must not exceed {MAX_DISPATCH_AUDIT_QUERY_LIMIT}"
        )));
    }
    let correlation_id = query
        .correlation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let delivery_id = query
        .delivery_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let channel_id = query
        .channel_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let entries = state.dispatch_audit.list_recent(DispatchAuditFilter {
        limit,
        correlation_id,
        delivery_id,
        channel_id,
    });
    Ok(crate::api::ok(DispatchDiagnosticsResponse {
        count: entries.len(),
        entries,
    }))
}
