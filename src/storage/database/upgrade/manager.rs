use std::time::Instant;

use crate::storage::database::DatabaseDriver;
use crate::storage::database::migration::BackupPolicy;
use crate::storage::database::upgrade::backup::{BackupArtifact, UpgradeBackupAccess};
use crate::storage::database::upgrade::error::{UpgradeError, UpgradeErrorContext, UpgradeResult};
use crate::storage::database::upgrade::lock::UpgradeLockAccess;
use crate::storage::database::upgrade::plan::{UpgradeAction, UpgradePlan};
use crate::storage::database::upgrade::reporter::UpgradeReporter;
use crate::storage::database::upgrade::state::{UpgradeRunStatus, UpgradeStateAccess};
use crate::storage::database::upgrade::verify::UpgradeVerifyAccess;
use crate::storage::{STORAGE_SCHEMA_VERSION, StorageInitConfig, types::DatabaseKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeMode {
    PlanOnly,
    Execute,
}

#[derive(Debug, Clone)]
pub struct UpgradeManager {
    config: StorageInitConfig,
    reporter: UpgradeReporter,
}

struct UpgradeFailureScope<'a> {
    db: &'a DatabaseDriver,
    driver: DatabaseKind,
    db_url: &'a str,
    plan: &'a UpgradePlan,
    run_id: &'a str,
    backup: Option<&'a BackupArtifact>,
}

impl UpgradeManager {
    pub fn new(config: StorageInitConfig) -> Self {
        Self {
            config,
            reporter: UpgradeReporter::new(),
        }
    }

    pub async fn inspect(&self) -> UpgradeResult<UpgradePlan> {
        let normalized = DatabaseDriver::normalize_db_url_public(self.config.db_url.as_deref());
        let driver = DatabaseKind::from_url(normalized.as_str())?;
        self.reporter.check_started(driver, STORAGE_SCHEMA_VERSION);
        let db = DatabaseDriver::open_for_upgrade(
            normalized.as_str(),
            driver,
            self.config.runtime_profile,
            self.config.mcp_enabled,
        )
        .await?;
        let plan = db.inspect_upgrade_plan().await?;
        self.reporter.plan(&plan);
        if let Err(err) = db.validate_runtime_durability().await {
            self.reporter
                .unsafe_durability_warning(err.to_string().as_str());
        }
        Ok(plan)
    }

    pub async fn run(&self, mode: UpgradeMode) -> UpgradeResult<Option<UpgradePlan>> {
        let normalized = DatabaseDriver::normalize_db_url_public(self.config.db_url.as_deref());
        let driver = DatabaseKind::from_url(normalized.as_str())?;
        self.reporter.check_started(driver, STORAGE_SCHEMA_VERSION);
        let db = DatabaseDriver::open_for_upgrade(
            normalized.as_str(),
            driver,
            self.config.runtime_profile,
            self.config.mcp_enabled,
        )
        .await?;
        let _lock = db.acquire_upgrade_lock(normalized.as_str()).await?;
        let plan = db.inspect_upgrade_plan().await?;
        self.reporter.plan(&plan);
        if matches!(mode, UpgradeMode::PlanOnly) {
            if let Err(err) = db.validate_runtime_durability().await {
                self.reporter
                    .unsafe_durability_warning(err.to_string().as_str());
            }
            return Ok(Some(plan));
        }
        db.validate_runtime_durability().await?;
        if matches!(plan.action, UpgradeAction::Noop) {
            self.reporter.verify_started();
            db.verify_upgrade(plan.target_schema_version.as_str())
                .await?;
            self.reporter
                .verify_completed(plan.target_schema_version.as_str());
            self.reporter.completed();
            return Ok(Some(plan));
        }
        db.ensure_upgrade_state_tables().await?;
        let unfinished = db.unfinished_upgrade_runs().await?;
        if !unfinished.is_empty() {
            let context = self.error_context(
                driver,
                normalized.as_str(),
                &plan,
                None,
                None,
                "Review pushgo_upgrade_runs, confirm no gateway is still upgrading, then clear or recover the unfinished run manually.",
            );
            return Err(UpgradeError::fatal(
                context,
                format!("unfinished upgrade run(s): {}", unfinished.join(",")),
            ));
        }
        let run_id = crate::util::generate_hex_id_128();
        db.insert_upgrade_run(
            run_id.as_str(),
            driver,
            plan.current_schema_version.as_deref(),
            plan.target_schema_version.as_str(),
        )
        .await?;
        self.reporter.status(UpgradeRunStatus::Planned);
        for (idx, step) in plan.steps.iter().enumerate() {
            db.insert_upgrade_step(
                run_id.as_str(),
                idx as i64,
                step.migration_id.as_str(),
                step.step_id.as_str(),
                step.description.as_str(),
            )
            .await?;
        }
        db.update_upgrade_run_status(
            run_id.as_str(),
            UpgradeRunStatus::PreflightOk,
            None,
            None,
            None,
        )
        .await?;
        self.reporter.status(UpgradeRunStatus::PreflightOk);

        let backup = match self
            .run_backup(&db, driver, normalized.as_str(), &plan, run_id.as_str())
            .await
        {
            Ok(backup) => backup,
            Err(err) => {
                return Err(self
                    .handle_failure(
                        UpgradeFailureScope {
                            db: &db,
                            driver,
                            db_url: normalized.as_str(),
                            plan: &plan,
                            run_id: run_id.as_str(),
                            backup: None,
                        },
                        err,
                    )
                    .await);
            }
        };
        db.update_upgrade_run_status(
            run_id.as_str(),
            UpgradeRunStatus::Migrating,
            backup.as_ref().map(|artifact| artifact.uri.as_str()),
            backup.as_ref().map(|artifact| artifact.sha256.as_str()),
            None,
        )
        .await?;
        self.reporter.status(UpgradeRunStatus::Migrating);

        let step_start = Instant::now();
        for (idx, step) in plan.steps.iter().enumerate() {
            db.update_upgrade_step(
                run_id.as_str(),
                idx as i64,
                UpgradeRunStatus::Migrating,
                None,
            )
            .await?;
            self.reporter.step_started(step);
        }
        if let Err(err) = self.execute_existing_bootstrap(normalized.as_str()).await {
            return Err(self
                .handle_failure(
                    UpgradeFailureScope {
                        db: &db,
                        driver,
                        db_url: normalized.as_str(),
                        plan: &plan,
                        run_id: run_id.as_str(),
                        backup: backup.as_ref(),
                    },
                    err,
                )
                .await);
        }
        for (idx, step) in plan.steps.iter().enumerate() {
            db.update_upgrade_step(
                run_id.as_str(),
                idx as i64,
                UpgradeRunStatus::Completed,
                None,
            )
            .await?;
            self.reporter
                .step_completed(step, step_start.elapsed().as_millis());
        }

        db.update_upgrade_run_status(
            run_id.as_str(),
            UpgradeRunStatus::Verifying,
            None,
            None,
            None,
        )
        .await?;
        self.reporter.verify_started();
        if let Err(err) = db.verify_upgrade(plan.target_schema_version.as_str()).await {
            return Err(self
                .handle_failure(
                    UpgradeFailureScope {
                        db: &db,
                        driver,
                        db_url: normalized.as_str(),
                        plan: &plan,
                        run_id: run_id.as_str(),
                        backup: backup.as_ref(),
                    },
                    err,
                )
                .await);
        }
        self.reporter
            .verify_completed(plan.target_schema_version.as_str());
        db.update_upgrade_run_status(
            run_id.as_str(),
            UpgradeRunStatus::Completed,
            None,
            None,
            None,
        )
        .await?;
        self.reporter.completed();
        Ok(Some(plan))
    }

    async fn run_backup(
        &self,
        db: &DatabaseDriver,
        driver: DatabaseKind,
        db_url: &str,
        plan: &UpgradePlan,
        run_id: &str,
    ) -> UpgradeResult<Option<BackupArtifact>> {
        let policy = if plan.requires_backup() {
            BackupPolicy::Required
        } else {
            BackupPolicy::None
        };
        if matches!(policy, BackupPolicy::None) {
            return Ok(None);
        }
        let path_hint = backup_path_hint(driver, db_url, run_id, policy);
        db.update_upgrade_run_status(
            run_id,
            UpgradeRunStatus::BackupStarted,
            Some(path_hint.as_str()),
            None,
            None,
        )
        .await?;
        self.reporter.status(UpgradeRunStatus::BackupStarted);
        self.reporter.backup_started(driver, path_hint.as_str());
        let artifact = db
            .create_upgrade_backup(db_url, driver, policy, run_id)
            .await?;
        if let Some(artifact) = artifact.as_ref() {
            self.reporter.backup_completed(artifact);
            db.update_upgrade_run_status(
                run_id,
                UpgradeRunStatus::BackupOk,
                Some(artifact.uri.as_str()),
                Some(artifact.sha256.as_str()),
                None,
            )
            .await?;
            self.reporter.status(UpgradeRunStatus::BackupOk);
        }
        Ok(artifact)
    }

    async fn execute_existing_bootstrap(&self, db_url: &str) -> UpgradeResult<()> {
        let mut config = self.config.clone();
        config.db_url = Some(db_url.to_string());
        config.managed_upgrade = false;
        let start = Instant::now();
        let driver = DatabaseDriver::new_with_config(config).await?;
        drop(driver);
        println!(
            "[upgrade] step completed migration=bootstrap step=storage_schema_bootstrap elapsed_ms={}",
            start.elapsed().as_millis()
        );
        Ok(())
    }

    async fn handle_failure(
        &self,
        scope: UpgradeFailureScope<'_>,
        err: impl Into<UpgradeError>,
    ) -> UpgradeError {
        let err = err.into();
        let err_text = err.to_string();
        self.reporter.failed(
            scope.plan.primary_migration_id(),
            scope.plan.primary_step_id(),
            err_text.as_str(),
        );
        let _ = scope
            .db
            .update_upgrade_run_status(
                scope.run_id,
                UpgradeRunStatus::Failed,
                scope.backup.map(|artifact| artifact.uri.as_str()),
                scope.backup.map(|artifact| artifact.sha256.as_str()),
                Some(err_text.as_str()),
            )
            .await;
        let mut rollback_attempted = false;
        let mut rollback_result = None;
        if let Some(artifact) = scope.backup {
            rollback_attempted = true;
            let _ = scope
                .db
                .update_upgrade_run_status(
                    scope.run_id,
                    UpgradeRunStatus::RollingBack,
                    None,
                    None,
                    None,
                )
                .await;
            self.reporter.rollback_started(Some(artifact.uri.as_str()));
            match scope
                .db
                .restore_upgrade_backup(scope.db_url, artifact)
                .await
            {
                Ok(()) => {
                    rollback_result = Some("rolled_back".to_string());
                    let _ = scope
                        .db
                        .update_upgrade_run_status(
                            scope.run_id,
                            UpgradeRunStatus::RolledBack,
                            None,
                            None,
                            None,
                        )
                        .await;
                    self.reporter
                        .rollback_completed(Some(artifact.uri.as_str()));
                }
                Err(restore_err) => {
                    rollback_result = Some(format!("rollback_failed: {restore_err}"));
                    let _ = scope
                        .db
                        .update_upgrade_run_status(
                            scope.run_id,
                            UpgradeRunStatus::RollbackFailed,
                            None,
                            None,
                            Some(restore_err.to_string().as_str()),
                        )
                        .await;
                }
            }
        }
        let mut context = self.error_context(
            scope.driver,
            scope.db_url,
            scope.plan,
            scope.plan.primary_migration_id(),
            scope.plan.primary_step_id(),
            "Stop all gateway instances, inspect the backup or external snapshot, restore if needed, then retry the upgrade with a single process.",
        );
        context.rollback_attempted = rollback_attempted;
        context.rollback_result = rollback_result;
        let context = UpgradeError::with_backup(context, scope.backup);
        self.reporter.fatal(&context);
        UpgradeError::fatal(context, err_text)
    }

    fn error_context(
        &self,
        driver: DatabaseKind,
        db_url: &str,
        plan: &UpgradePlan,
        migration_id: Option<&str>,
        step_id: Option<&str>,
        recovery: &str,
    ) -> UpgradeErrorContext {
        UpgradeErrorContext {
            driver,
            database_url: redact_database_url(db_url),
            current_schema_version: plan.current_schema_version.clone(),
            target_schema_version: plan.target_schema_version.clone(),
            migration_id: migration_id.map(ToString::to_string),
            step_id: step_id.map(ToString::to_string),
            backup_uri: None,
            rollback_attempted: false,
            rollback_result: None,
            recovery: recovery.to_string(),
        }
    }
}

fn backup_path_hint(
    driver: DatabaseKind,
    db_url: &str,
    run_id: &str,
    _policy: BackupPolicy,
) -> String {
    match driver {
        DatabaseKind::Sqlite => format!("{}.upgrade-{run_id}.bak", sqlite_path_for_display(db_url)),
        DatabaseKind::Postgres => format!("external-snapshot-or-pg_dump:{run_id}"),
        DatabaseKind::Mysql => format!("external-snapshot-or-mysqldump:{run_id}"),
    }
}

fn sqlite_path_for_display(db_url: &str) -> String {
    db_url
        .strip_prefix("sqlite://")
        .unwrap_or(db_url)
        .split('?')
        .next()
        .unwrap_or(db_url)
        .to_string()
}

fn redact_database_url(db_url: &str) -> String {
    if let Some((scheme, rest)) = db_url.split_once("://")
        && let Some(at_pos) = rest.find('@')
    {
        return format!("{scheme}://***@{}", &rest[at_pos + 1..]);
    }
    db_url.to_string()
}
