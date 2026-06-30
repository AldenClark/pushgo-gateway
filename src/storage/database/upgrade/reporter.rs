use std::time::Instant;

use crate::storage::database::upgrade::backup::BackupArtifact;
use crate::storage::database::upgrade::plan::{UpgradeAction, UpgradePlan, UpgradeStepPlan};
use crate::storage::database::upgrade::state::UpgradeRunStatus;
use crate::storage::types::DatabaseKind;

#[derive(Debug, Clone)]
pub struct UpgradeReporter {
    started_at: Instant,
}

impl UpgradeReporter {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }

    pub fn check_started(&self, driver: DatabaseKind, target_schema: &str) {
        println!(
            "[upgrade] check started driver={} target_schema={}",
            driver.as_str(),
            target_schema
        );
    }

    pub fn plan(&self, plan: &UpgradePlan) {
        println!(
            "[upgrade] current schema={} action={} pending={}",
            plan.current_schema_version.as_deref().unwrap_or("none"),
            plan.action.as_str(),
            plan.pending_migrations.len()
        );
        for migration in &plan.pending_migrations {
            println!(
                "[upgrade] migration={} risk={} backup={} rollback={}",
                migration.id,
                migration.risk.as_str(),
                migration.backup_policy.as_str(),
                migration.rollback_policy.as_str()
            );
        }
    }

    pub fn status(&self, status: UpgradeRunStatus) {
        println!("[upgrade] status={}", status.as_str());
    }

    pub fn backup_started(&self, backend: DatabaseKind, uri: &str) {
        println!(
            "[upgrade] backup started backend={} path={}",
            backend.as_str(),
            uri
        );
    }

    pub fn backup_completed(&self, artifact: &BackupArtifact) {
        println!(
            "[upgrade] backup completed path={} sha256={} bytes={}",
            artifact.uri, artifact.sha256, artifact.bytes
        );
    }

    pub fn step_started(&self, step: &UpgradeStepPlan) {
        println!(
            "[upgrade] step started migration={} step={}",
            step.migration_id, step.step_id
        );
    }

    pub fn step_completed(&self, step: &UpgradeStepPlan, elapsed_ms: u128) {
        println!(
            "[upgrade] step completed migration={} step={} elapsed_ms={}",
            step.migration_id, step.step_id, elapsed_ms
        );
    }

    pub fn verify_started(&self) {
        println!("[upgrade] verify started");
    }

    pub fn verify_completed(&self, schema: &str) {
        println!("[upgrade] verify completed schema={schema}");
    }

    pub fn completed(&self) {
        println!(
            "[upgrade] completed elapsed_ms={}",
            self.started_at.elapsed().as_millis()
        );
    }

    pub fn failed(&self, migration_id: Option<&str>, step_id: Option<&str>, error: &str) {
        println!(
            "[upgrade] failed migration={} step={} error={}",
            migration_id.unwrap_or("none"),
            step_id.unwrap_or("none"),
            error
        );
    }

    pub fn rollback_started(&self, backup_uri: Option<&str>) {
        println!(
            "[upgrade] rollback started backup={}",
            backup_uri.unwrap_or("none")
        );
    }

    pub fn rollback_completed(&self, backup_uri: Option<&str>) {
        println!(
            "[upgrade] rollback completed backup={}",
            backup_uri.unwrap_or("none")
        );
    }

    pub fn fatal(&self, context: &crate::storage::database::upgrade::error::UpgradeErrorContext) {
        println!(
            "[upgrade] fatal current_schema={} target_schema={} migration={} step={} rollback={} recovery=\"{}\"",
            context
                .current_schema_version
                .as_deref()
                .unwrap_or("unknown"),
            context.target_schema_version,
            context.migration_id.as_deref().unwrap_or("none"),
            context.step_id.as_deref().unwrap_or("none"),
            context
                .rollback_result
                .as_deref()
                .unwrap_or("not_attempted"),
            context.recovery
        );
    }
}

impl UpgradeAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::FreshInstall => "fresh_install",
            Self::Noop => "noop",
            Self::BackfillCurrent => "backfill_current",
            Self::HardResetRuntime => "hard_reset_runtime",
        }
    }
}
