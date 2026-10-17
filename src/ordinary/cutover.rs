//! Concrete offline entry points; each backend owns its native transaction.
use std::{error::Error, path::Path};

pub async fn run(
    url: &str,
    action: &str,
    backup: &Path,
    source_profile: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    use crate::storage::DatabaseKind;
    match DatabaseKind::from_url(url)? {
        DatabaseKind::Sqlite => super::sqlite_cutover::run(url, action, backup, source_profile).await,
        DatabaseKind::Postgres => super::pg_cutover::run(url, action, backup, source_profile).await,
        DatabaseKind::Mysql => Err("MySQL offline history cutover is not implemented".into()),
    }
}

pub async fn activate_before_runtime(
    url: Option<&str>,
    profile: &str,
) -> Result<(), super::store::KernelError> {
    use crate::storage::{DatabaseKind, database::DatabaseDriver};
    let normalized = DatabaseDriver::normalize_db_url_public(url);
    let backend = DatabaseKind::from_url(&normalized)
        .map_err(|error| super::store::KernelError::Invalid(error.to_string()))?;
    match backend {
        DatabaseKind::Sqlite => super::sqlite_cutover::activate_before_runtime(url, profile).await,
        DatabaseKind::Postgres => super::pg_cutover::activate_before_runtime(&normalized, profile)
            .await
            .map_err(|error| super::store::KernelError::Invalid(error.to_string())),
        DatabaseKind::Mysql => Ok(()),
    }
}
