use crate::storage::{
    STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_LEGACY, STORAGE_SCHEMA_VERSION_OLDER_LEGACY,
    STORAGE_SCHEMA_VERSION_OLDEST_LEGACY, STORAGE_SCHEMA_VERSION_PREVIOUS, StoreError, StoreResult,
};

pub(crate) const DEVICE_IDENTITY_V8_MIGRATION: SchemaMigrationDefinition =
    SchemaMigrationDefinition {
        id: "20260417_001_device_identity_v8",
        description: "Hard-cut gateway runtime schema for device-key identity and provider route separation",
        checksum: "sha256:426de3f380802b8706ddd10151d30d4ba8286fddb234eeefc7800c42d7860a29",
        target_schema_version: STORAGE_SCHEMA_VERSION,
    };

pub(crate) const SCHEMA_MIGRATIONS: &[SchemaMigrationDefinition] = &[DEVICE_IDENTITY_V8_MIGRATION];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchemaMigrationDefinition {
    pub id: &'static str,
    pub description: &'static str,
    pub checksum: &'static str,
    pub target_schema_version: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SchemaMigrationAction {
    FreshInstall,
    BackfillCurrent,
    HardResetRuntime {
        reason: &'static str,
        migration: SchemaMigrationDefinition,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchemaMigrationPlan {
    pub current_version: Option<String>,
    pub target_version: &'static str,
    pub action: SchemaMigrationAction,
    pub pending_migrations: Vec<SchemaMigrationDefinition>,
}

impl SchemaMigrationPlan {
    pub fn for_state(
        current_version: Option<&str>,
        legacy_runtime_tables_present: bool,
        applied_migrations: &[AppliedSchemaMigration],
    ) -> StoreResult<Self> {
        let normalized = current_version
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let pending_migrations = pending_schema_migrations(applied_migrations);
        let latest = latest_schema_migration();
        let action = match normalized {
            None if legacy_runtime_tables_present => SchemaMigrationAction::HardResetRuntime {
                reason: "legacy_runtime_without_schema_meta",
                migration: latest,
            },
            None => SchemaMigrationAction::FreshInstall,
            Some(version) if version == STORAGE_SCHEMA_VERSION => {
                SchemaMigrationAction::BackfillCurrent
            }
            Some(version) if is_legacy_hard_cut_version(version) => {
                SchemaMigrationAction::HardResetRuntime {
                    reason: "legacy_schema_hard_cut",
                    migration: latest,
                }
            }
            Some(version) => {
                return Err(StoreError::SchemaVersionMismatch {
                    expected: STORAGE_SCHEMA_VERSION.to_string(),
                    actual: version.to_string(),
                });
            }
        };
        Ok(Self {
            current_version: normalized.map(ToString::to_string),
            target_version: STORAGE_SCHEMA_VERSION,
            action,
            pending_migrations,
        })
    }

    pub fn hard_reset_migration(&self) -> Option<SchemaMigrationDefinition> {
        match self.action {
            SchemaMigrationAction::HardResetRuntime { migration, .. } => Some(migration),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedSchemaMigration {
    pub id: String,
    pub checksum: String,
    pub success: bool,
}

pub(crate) fn latest_schema_migration() -> SchemaMigrationDefinition {
    SCHEMA_MIGRATIONS
        .last()
        .copied()
        .expect("schema migrations should not be empty")
}

pub(crate) fn validate_applied_schema_migrations(
    applied: &[AppliedSchemaMigration],
) -> StoreResult<()> {
    for applied_migration in applied {
        let Some(expected) = SCHEMA_MIGRATIONS
            .iter()
            .find(|migration| migration.id == applied_migration.id)
            .copied()
        else {
            return Err(StoreError::SchemaVersionMismatch {
                expected: STORAGE_SCHEMA_VERSION.to_string(),
                actual: format!("unknown migration {}", applied_migration.id),
            });
        };
        validate_applied_schema_migration(applied_migration, expected)?;
    }
    Ok(())
}

pub(crate) fn pending_schema_migrations(
    applied: &[AppliedSchemaMigration],
) -> Vec<SchemaMigrationDefinition> {
    SCHEMA_MIGRATIONS
        .iter()
        .copied()
        .filter(|migration| {
            !applied
                .iter()
                .any(|applied_migration| applied_migration.id == migration.id)
        })
        .collect()
}

fn validate_applied_schema_migration(
    applied: &AppliedSchemaMigration,
    expected: SchemaMigrationDefinition,
) -> StoreResult<()> {
    if applied.checksum != expected.checksum {
        return Err(StoreError::SchemaVersionMismatch {
            expected: format!("{} {}", expected.id, expected.checksum),
            actual: format!("{} {}", applied.id, applied.checksum),
        });
    }
    if !applied.success {
        return Err(StoreError::SchemaVersionMismatch {
            expected: format!("{} success=true", expected.id),
            actual: format!("{} success=false", applied.id),
        });
    }
    Ok(())
}

fn is_legacy_hard_cut_version(version: &str) -> bool {
    matches!(
        version,
        STORAGE_SCHEMA_VERSION_PREVIOUS
            | STORAGE_SCHEMA_VERSION_LEGACY
            | STORAGE_SCHEMA_VERSION_OLDER_LEGACY
            | STORAGE_SCHEMA_VERSION_OLDEST_LEGACY
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedSchemaMigration, DEVICE_IDENTITY_V8_MIGRATION, SCHEMA_MIGRATIONS,
        SchemaMigrationAction, SchemaMigrationPlan, latest_schema_migration,
        pending_schema_migrations, validate_applied_schema_migrations,
    };
    use crate::storage::{STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_PREVIOUS};

    #[test]
    fn migration_catalog_exposes_latest_schema_version() {
        assert_eq!(latest_schema_migration(), DEVICE_IDENTITY_V8_MIGRATION);
        assert_eq!(
            latest_schema_migration().target_schema_version,
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            SCHEMA_MIGRATIONS.last(),
            Some(&DEVICE_IDENTITY_V8_MIGRATION)
        );
    }

    #[test]
    fn missing_meta_with_runtime_tables_hard_resets() {
        let plan = SchemaMigrationPlan::for_state(None, true, &[]).expect("plan should resolve");
        assert!(plan.hard_reset_migration().is_some());
        assert_eq!(
            plan.action,
            SchemaMigrationAction::HardResetRuntime {
                reason: "legacy_runtime_without_schema_meta",
                migration: DEVICE_IDENTITY_V8_MIGRATION,
            }
        );
        assert_eq!(plan.pending_migrations, vec![DEVICE_IDENTITY_V8_MIGRATION]);
    }

    #[test]
    fn previous_version_hard_resets() {
        let plan =
            SchemaMigrationPlan::for_state(Some(STORAGE_SCHEMA_VERSION_PREVIOUS), false, &[])
                .expect("plan should resolve");
        assert!(plan.hard_reset_migration().is_some());
    }

    #[test]
    fn current_version_backfills() {
        let applied = vec![AppliedSchemaMigration {
            id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
            checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
            success: true,
        }];
        let plan = SchemaMigrationPlan::for_state(Some(STORAGE_SCHEMA_VERSION), true, &applied)
            .expect("plan should resolve");
        assert_eq!(plan.action, SchemaMigrationAction::BackfillCurrent);
        assert!(plan.pending_migrations.is_empty());
    }

    #[test]
    fn migration_validation_rejects_unknown_ids() {
        let err = validate_applied_schema_migrations(&[AppliedSchemaMigration {
            id: "20260418_999_unknown".to_string(),
            checksum: "sha256:unknown".to_string(),
            success: true,
        }])
        .expect_err("unknown migration should fail validation");
        assert!(matches!(
            err,
            crate::storage::StoreError::SchemaVersionMismatch { .. }
        ));
    }

    #[test]
    fn pending_migrations_excludes_recorded_rows() {
        let pending = pending_schema_migrations(&[AppliedSchemaMigration {
            id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
            checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
            success: true,
        }]);
        assert!(pending.is_empty());
    }
}
