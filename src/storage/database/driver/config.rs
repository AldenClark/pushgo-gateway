use super::*;

pub(super) const DEFAULT_SQLITE_DB_URL: &str = "sqlite://./pushgo-gateway.db?mode=rwc";

impl DatabaseDriver {
    pub async fn new(db_url: Option<&str>) -> StoreResult<Self> {
        let normalized_db_url = Self::normalize_db_url(db_url);
        let db_kind = DatabaseKind::from_url(normalized_db_url.as_str())?;
        match db_kind {
            DatabaseKind::Sqlite => Ok(DatabaseDriver::Sqlite(
                SqliteDb::new(normalized_db_url.as_str()).await?,
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
