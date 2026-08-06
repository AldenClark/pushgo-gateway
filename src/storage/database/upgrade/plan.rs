use crate::storage::database::migration::{
    SchemaMigrationAction, SchemaMigrationDefinition, SchemaMigrationPlan,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeAction {
    FreshInstall,
    Noop,
    BackfillCurrent,
    HardResetRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeStepPlan {
    pub migration_id: String,
    pub step_id: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradePlan {
    pub(crate) current_schema_version: Option<String>,
    pub(crate) target_schema_version: String,
    pub(crate) action: UpgradeAction,
    pub(crate) pending_migrations: Vec<SchemaMigrationDefinition>,
    pub(crate) steps: Vec<UpgradeStepPlan>,
}

impl UpgradePlan {
    pub(crate) fn from_schema_plan(plan: SchemaMigrationPlan) -> Self {
        let action = match plan.action {
            SchemaMigrationAction::FreshInstall => UpgradeAction::FreshInstall,
            SchemaMigrationAction::BackfillCurrent if plan.pending_migrations.is_empty() => {
                UpgradeAction::Noop
            }
            SchemaMigrationAction::BackfillCurrent => UpgradeAction::BackfillCurrent,
            SchemaMigrationAction::HardResetRuntime { .. } => UpgradeAction::HardResetRuntime,
        };
        let steps = plan
            .pending_migrations
            .iter()
            .flat_map(|migration| {
                migration.steps.iter().map(|step| UpgradeStepPlan {
                    migration_id: migration.id.to_string(),
                    step_id: step.id.to_string(),
                    description: step.description.to_string(),
                })
            })
            .collect();
        Self {
            current_schema_version: plan.current_version,
            target_schema_version: plan.target_version.to_string(),
            action,
            pending_migrations: plan.pending_migrations,
            steps,
        }
    }

    pub(crate) fn requires_backup(&self) -> bool {
        self.pending_migrations.iter().any(|migration| {
            matches!(
                migration.backup_policy,
                crate::storage::database::migration::BackupPolicy::Required
                    | crate::storage::database::migration::BackupPolicy::ExternalRequired
            )
        })
    }

    pub(crate) fn primary_migration_id(&self) -> Option<&str> {
        self.pending_migrations
            .first()
            .map(|migration| migration.id)
    }

    pub(crate) fn primary_step_id(&self) -> Option<&str> {
        self.steps.first().map(|step| step.step_id.as_str())
    }
}
