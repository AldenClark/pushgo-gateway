use crate::storage::StoreError;
use crate::storage::database::migration::BackupPolicy;
use crate::storage::database::upgrade::error::UpgradeResult;
use crate::storage::types::DatabaseKind;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_EXTERNAL_BACKUP_AGE_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackupArtifact {
    pub uri: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalBackupManifest {
    version: u8,
    driver: String,
    database_sha256: String,
    artifact_uri: String,
    artifact_sha256: String,
    artifact_bytes: u64,
    completed_at_epoch_seconds: i64,
}

pub(crate) fn load_external_backup_manifest(
    db_url: &str,
    driver: DatabaseKind,
) -> UpgradeResult<BackupArtifact> {
    let path = std::env::var("PUSHGO_DB_UPGRADE_BACKUP_MANIFEST").map_err(|_| {
        StoreError::Upgrade(format!(
            "{} upgrade requires PUSHGO_DB_UPGRADE_BACKUP_MANIFEST pointing to a verified external backup manifest",
            driver.as_str()
        ))
    })?;
    load_external_backup_manifest_from_path(Path::new(path.trim()), db_url, driver)
}

fn load_external_backup_manifest_from_path(
    path: &Path,
    db_url: &str,
    driver: DatabaseKind,
) -> UpgradeResult<BackupArtifact> {
    if path.as_os_str().is_empty() {
        return Err(StoreError::Upgrade(
            "PUSHGO_DB_UPGRADE_BACKUP_MANIFEST must not be empty".to_string(),
        )
        .into());
    }
    if !std::fs::metadata(path)?.is_file() {
        return Err(StoreError::Upgrade(format!(
            "external backup manifest is not a regular file: {}",
            path.display()
        ))
        .into());
    }
    let raw = std::fs::read(path)?;
    let manifest: ExternalBackupManifest = serde_json::from_slice(&raw).map_err(|err| {
        StoreError::Upgrade(format!(
            "invalid external backup manifest {}: {err}",
            path.display()
        ))
    })?;
    validate_external_backup_manifest(&manifest, db_url, driver)?;
    verify_external_backup_artifact(&manifest)?;
    Ok(BackupArtifact {
        uri: manifest.artifact_uri.trim().to_string(),
        sha256: manifest.artifact_sha256.to_ascii_lowercase(),
        bytes: manifest.artifact_bytes,
    })
}

fn validate_external_backup_manifest(
    manifest: &ExternalBackupManifest,
    db_url: &str,
    driver: DatabaseKind,
) -> UpgradeResult<()> {
    if manifest.version != 1 {
        return Err(StoreError::Upgrade(format!(
            "unsupported external backup manifest version {}; expected 1",
            manifest.version
        ))
        .into());
    }
    if manifest.driver.trim() != driver.as_str() {
        return Err(StoreError::Upgrade(format!(
            "external backup manifest driver mismatch: expected {}, got {}",
            driver.as_str(),
            manifest.driver
        ))
        .into());
    }
    let expected_database_sha256 = sha256_hex(db_url.trim().as_bytes());
    if !manifest
        .database_sha256
        .trim()
        .eq_ignore_ascii_case(expected_database_sha256.as_str())
    {
        return Err(StoreError::Upgrade(
            "external backup manifest does not match the configured database URL fingerprint"
                .to_string(),
        )
        .into());
    }
    if manifest.artifact_uri.trim().is_empty() {
        return Err(StoreError::Upgrade(
            "external backup manifest artifact_uri must not be empty".to_string(),
        )
        .into());
    }
    if !is_sha256_hex(manifest.artifact_sha256.trim()) {
        return Err(StoreError::Upgrade(
            "external backup manifest artifact_sha256 must be exactly 64 hexadecimal characters"
                .to_string(),
        )
        .into());
    }
    if manifest.artifact_bytes == 0 {
        return Err(StoreError::Upgrade(
            "external backup manifest artifact_bytes must be greater than zero".to_string(),
        )
        .into());
    }
    let now = chrono::Utc::now().timestamp();
    if manifest.completed_at_epoch_seconds <= 0 || manifest.completed_at_epoch_seconds > now + 300 {
        return Err(StoreError::Upgrade(
            "external backup manifest completed_at_epoch_seconds is invalid or in the future"
                .to_string(),
        )
        .into());
    }
    if now.saturating_sub(manifest.completed_at_epoch_seconds) > MAX_EXTERNAL_BACKUP_AGE_SECONDS {
        return Err(StoreError::Upgrade(format!(
            "external backup manifest is stale; completed backup must be no older than {MAX_EXTERNAL_BACKUP_AGE_SECONDS} seconds"
        ))
        .into());
    }
    Ok(())
}

fn verify_external_backup_artifact(manifest: &ExternalBackupManifest) -> UpgradeResult<()> {
    let artifact_path = local_artifact_path(manifest.artifact_uri.trim())?;
    let metadata = std::fs::metadata(&artifact_path).map_err(|err| {
        StoreError::Upgrade(format!(
            "external backup artifact is not readable at {}: {err}",
            artifact_path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(StoreError::Upgrade(format!(
            "external backup artifact is not a regular file: {}",
            artifact_path.display()
        ))
        .into());
    }
    if metadata.len() != manifest.artifact_bytes {
        return Err(StoreError::Upgrade(format!(
            "external backup artifact size mismatch: manifest={}, actual={}",
            manifest.artifact_bytes,
            metadata.len()
        ))
        .into());
    }

    let file = std::fs::File::open(&artifact_path).map_err(|err| {
        StoreError::Upgrade(format!(
            "external backup artifact cannot be opened at {}: {err}",
            artifact_path.display()
        ))
    })?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            StoreError::Upgrade(format!(
                "external backup artifact cannot be read at {}: {err}",
                artifact_path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !actual_sha256.eq_ignore_ascii_case(manifest.artifact_sha256.trim()) {
        return Err(StoreError::Upgrade(
            "external backup artifact SHA-256 does not match the manifest".to_string(),
        )
        .into());
    }
    Ok(())
}

fn local_artifact_path(uri: &str) -> UpgradeResult<PathBuf> {
    let raw_path = uri.strip_prefix("file://").unwrap_or(uri);
    let path = PathBuf::from(raw_path);
    if !path.is_absolute() || uri.contains("://") && !uri.starts_with("file://") {
        return Err(StoreError::Upgrade(
            "external backup artifact_uri must be an absolute local path or file:/// URI so the gateway can verify the artifact bytes"
                .to_string(),
        )
        .into());
    }
    Ok(path)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
pub(crate) fn test_external_backup_artifact(driver: DatabaseKind, run_id: &str) -> BackupArtifact {
    BackupArtifact {
        uri: format!("test://{}/external-backup/{run_id}", driver.as_str()),
        sha256: sha256_hex(format!("{}:{run_id}", driver.as_str()).as_bytes()),
        bytes: 1,
    }
}

pub(crate) trait UpgradeBackupAccess {
    async fn create_upgrade_backup(
        &self,
        db_url: &str,
        driver: DatabaseKind,
        policy: BackupPolicy,
        run_id: &str,
    ) -> UpgradeResult<Option<BackupArtifact>>;

    async fn restore_upgrade_backup(
        &self,
        db_url: &str,
        artifact: &BackupArtifact,
    ) -> UpgradeResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn external_manifest_must_match_database_and_prove_non_empty_artifact() {
        let directory = tempfile::tempdir().expect("temp directory");
        let artifact_path = directory.path().join("pushgo.dump");
        std::fs::write(&artifact_path, b"verified external backup").expect("write artifact");
        let mut file =
            tempfile::NamedTempFile::new_in(directory.path()).expect("manifest temp file");
        let db_url = "postgres://user:secret@example.test/pushgo";
        write!(
            file,
            "{}",
            serde_json::json!({
                "version": 1,
                "driver": "postgres",
                "database_sha256": sha256_hex(db_url.as_bytes()),
                "artifact_uri": format!("file://{}", artifact_path.display()),
                "artifact_sha256": sha256_hex(b"verified external backup"),
                "artifact_bytes": 24,
                "completed_at_epoch_seconds": chrono::Utc::now().timestamp()
            })
        )
        .expect("write manifest");

        let artifact =
            load_external_backup_manifest_from_path(file.path(), db_url, DatabaseKind::Postgres)
                .expect("valid manifest");
        assert_eq!(artifact.uri, format!("file://{}", artifact_path.display()));
        assert_eq!(artifact.bytes, 24);

        let err = load_external_backup_manifest_from_path(
            file.path(),
            "postgres://user:secret@example.test/other",
            DatabaseKind::Postgres,
        )
        .expect_err("wrong database must fail");
        assert!(err.to_string().contains("database URL fingerprint"));
    }

    #[test]
    fn external_manifest_rejects_stale_or_tampered_artifact() {
        let directory = tempfile::tempdir().expect("temp directory");
        let artifact_path = directory.path().join("pushgo.dump");
        std::fs::write(&artifact_path, b"backup").expect("write artifact");
        let db_url = "mysql://user:secret@example.test/pushgo";

        let write_manifest = |completed_at_epoch_seconds: i64, artifact_sha256: String| {
            let path = directory
                .path()
                .join(format!("manifest-{completed_at_epoch_seconds}.json"));
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "version": 1,
                    "driver": "mysql",
                    "database_sha256": sha256_hex(db_url.as_bytes()),
                    "artifact_uri": artifact_path.display().to_string(),
                    "artifact_sha256": artifact_sha256,
                    "artifact_bytes": 6,
                    "completed_at_epoch_seconds": completed_at_epoch_seconds
                }))
                .expect("serialize manifest"),
            )
            .expect("write manifest");
            path
        };

        let stale = write_manifest(
            chrono::Utc::now().timestamp() - MAX_EXTERNAL_BACKUP_AGE_SECONDS - 1,
            sha256_hex(b"backup"),
        );
        let err = load_external_backup_manifest_from_path(&stale, db_url, DatabaseKind::Mysql)
            .expect_err("stale manifest must fail");
        assert!(err.to_string().contains("stale"));

        let tampered = write_manifest(chrono::Utc::now().timestamp(), "a".repeat(64));
        let err = load_external_backup_manifest_from_path(&tampered, db_url, DatabaseKind::Mysql)
            .expect_err("tampered artifact must fail");
        assert!(err.to_string().contains("SHA-256"));
    }
}
