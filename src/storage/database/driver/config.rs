use super::*;
use crate::storage::StorageInitConfig;

pub(super) const DEFAULT_SQLITE_DB_URL: &str = "sqlite://./pushgo-gateway.db?mode=rwc";

impl DatabaseDriver {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        Self::new_with_config(StorageInitConfig {
            db_url: db_url.map(str::to_string),
            stats_enabled: true,
            mcp_enabled: true,
            ..StorageInitConfig::default()
        })
        .await
    }

    pub async fn new_with_config(config: StorageInitConfig) -> StoreResult<Self> {
        let normalized_db_url = Self::normalize_db_url(config.db_url.as_deref());
        let db_kind = DatabaseKind::from_url(normalized_db_url.as_str())?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "db.driver_selected",
            driver = %(db_kind.as_str())
        );
        match db_kind {
            DatabaseKind::Sqlite => Ok(DatabaseDriver::Sqlite(
                SqliteDb::new_with_config(
                    normalized_db_url.as_str(),
                    config.sqlite_telemetry_db_url.as_deref(),
                    config.sqlite_runtime_db_url.as_deref(),
                    config.stats_enabled,
                    config.mcp_enabled,
                )
                .await?,
            )),
            DatabaseKind::Postgres => Ok(DatabaseDriver::Postgres(
                PostgresDb::new(normalized_db_url.as_str()).await?,
            )),
            DatabaseKind::Mysql => Ok(DatabaseDriver::MySql(
                MySqlDb::new(normalized_db_url.as_str()).await?,
            )),
        }
    }

    pub(super) fn normalize_db_url(db_url: Option<&str>) -> String {
        let trimmed = db_url
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_SQLITE_DB_URL);
        if !trimmed.starts_with("sqlite://") {
            return trimmed.to_string();
        }
        if trimmed.contains("mode=") {
            return trimmed.to_string();
        }
        if trimmed.contains('?') {
            format!("{trimmed}&mode=rwc")
        } else {
            format!("{trimmed}?mode=rwc")
        }
    }
}
