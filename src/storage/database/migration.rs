use crate::storage::{
    STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_BETA1, STORAGE_SCHEMA_VERSION_FORMAL_RELEASE,
    STORAGE_SCHEMA_VERSION_LEGACY, STORAGE_SCHEMA_VERSION_MIGRATABLE,
    STORAGE_SCHEMA_VERSION_OLDER_LEGACY, STORAGE_SCHEMA_VERSION_OLDEST_LEGACY,
    STORAGE_SCHEMA_VERSION_PREVIOUS, StoreError, StoreResult,
};

pub(crate) const DEVICE_IDENTITY_V8_MIGRATION: SchemaMigrationDefinition =
    SchemaMigrationDefinition {
        id: "20260417_001_device_identity_v8",
        description: "Hard-cut gateway runtime schema for device-key identity and provider route separation",
        checksum: "sha256:426de3f380802b8706ddd10151d30d4ba8286fddb234eeefc7800c42d7860a29",
        target_schema_version: STORAGE_SCHEMA_VERSION_MIGRATABLE,
        risk: MigrationRisk::RuntimeReset,
        backup_policy: BackupPolicy::Required,
        rollback_policy: RollbackPolicy::RestoreBackup,
        steps: &[
            MigrationStepDefinition {
                id: "drop_legacy_runtime_tables",
                description: "Drop legacy runtime tables that cannot be shape-migrated safely",
            },
            MigrationStepDefinition {
                id: "recreate_runtime_tables",
                description: "Recreate runtime tables with device-key identity schema",
            },
        ],
    };

pub(crate) const OBSERVABILITY_V9_MIGRATION: SchemaMigrationDefinition =
    SchemaMigrationDefinition {
        id: "20260422_001_observability_v9",
        description: "Drop deprecated delivery_audit table and finalize diagnostics + tracing + stats matrix",
        checksum: "sha256:8f4cb15c7dc5a328a88f596f59eaec157045a78287cf27a52f88f0a5518f5e47",
        target_schema_version: STORAGE_SCHEMA_VERSION_BETA1,
        risk: MigrationRisk::Destructive,
        backup_policy: BackupPolicy::Recommended,
        rollback_policy: RollbackPolicy::ManualRestore,
        steps: &[
            MigrationStepDefinition {
                id: "drop_deprecated_observability_tables",
                description: "Drop deprecated observability tables superseded by tracing and counters",
            },
            MigrationStepDefinition {
                id: "normalize_epoch_columns",
                description: "Normalize legacy second timestamps to milliseconds once",
            },
        ],
    };

pub(crate) const FORMAL_RELEASE_V10_MIGRATION: SchemaMigrationDefinition =
    SchemaMigrationDefinition {
        id: "20260805_001_release_v10",
        description: "Apply the managed 1.3.0 formal-release schema, idempotency collation, and provider-token identity migration",
        checksum: "sha256:f526ca103e36ed4ca6a0e0bddb6ebe2aff757a4c11417ff7d26500e2513b0bb1",
        target_schema_version: STORAGE_SCHEMA_VERSION,
        risk: MigrationRisk::DataShapeChange,
        backup_policy: BackupPolicy::Required,
        rollback_policy: RollbackPolicy::RestoreBackup,
        steps: &[
            MigrationStepDefinition {
                id: "apply_formal_schema",
                description: "Add formal-release columns, indexes, and binary identifier collations",
            },
            MigrationStepDefinition {
                id: "merge_provider_token_identities",
                description: "Canonicalize APNs tokens and merge case-only duplicate device identities",
            },
            MigrationStepDefinition {
                id: "verify_formal_contract",
                description: "Verify the formal-release schema and provider-token semantic markers",
            },
        ],
    };

pub(crate) const CONCURRENCY_FENCING_V11_MIGRATION: SchemaMigrationDefinition =
    SchemaMigrationDefinition {
        id: "20260808_001_concurrency_fencing_v11",
        description: "Add durable claim fencing, provider run ownership, and route revisions",
        checksum: "sha256:5ac8609854a01918f99f837fb1240aa74c8543f17fa777cf786520884271296e",
        target_schema_version: STORAGE_SCHEMA_VERSION,
        risk: MigrationRisk::AdditiveSchema,
        backup_policy: BackupPolicy::Required,
        rollback_policy: RollbackPolicy::RestoreBackup,
        steps: &[
            MigrationStepDefinition {
                id: "add_concurrency_fencing_columns",
                description: "Add outbox claim generation, provider run ownership, and route revision columns",
            },
            MigrationStepDefinition {
                id: "normalize_legacy_claims",
                description: "Release legacy claimed outbox rows after the required writer drain",
            },
            MigrationStepDefinition {
                id: "verify_concurrency_contract",
                description: "Verify fencing columns, indexes, and provider run state invariants",
            },
        ],
    };

pub(crate) const SCHEMA_MIGRATIONS: &[SchemaMigrationDefinition] = &[
    DEVICE_IDENTITY_V8_MIGRATION,
    OBSERVABILITY_V9_MIGRATION,
    FORMAL_RELEASE_V10_MIGRATION,
    CONCURRENCY_FENCING_V11_MIGRATION,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SchemaMigrationDefinition {
    pub id: &'static str,
    pub description: &'static str,
    pub checksum: &'static str,
    pub target_schema_version: &'static str,
    pub risk: MigrationRisk,
    pub backup_policy: BackupPolicy,
    pub rollback_policy: RollbackPolicy,
    pub steps: &'static [MigrationStepDefinition],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum MigrationRisk {
    Trivial,
    AdditiveSchema,
    DataShapeChange,
    RuntimeReset,
    Destructive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BackupPolicy {
    None,
    Recommended,
    Required,
    ExternalRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum RollbackPolicy {
    TransactionOnly,
    RestoreBackup,
    ManualRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MigrationStepDefinition {
    pub id: &'static str,
    pub description: &'static str,
}

impl MigrationRisk {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Trivial => "Trivial",
            Self::AdditiveSchema => "AdditiveSchema",
            Self::DataShapeChange => "DataShapeChange",
            Self::RuntimeReset => "RuntimeReset",
            Self::Destructive => "Destructive",
        }
    }
}

impl BackupPolicy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Recommended => "Recommended",
            Self::Required => "Required",
            Self::ExternalRequired => "ExternalRequired",
        }
    }
}

impl RollbackPolicy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TransactionOnly => "TransactionOnly",
            Self::RestoreBackup => "RestoreBackup",
            Self::ManualRestore => "ManualRestore",
        }
    }
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
    pub(crate) fn for_state(
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
            Some(version) if version == STORAGE_SCHEMA_VERSION_FORMAL_RELEASE => {
                SchemaMigrationAction::BackfillCurrent
            }
            Some(version) if version == STORAGE_SCHEMA_VERSION_MIGRATABLE => {
                SchemaMigrationAction::BackfillCurrent
            }
            Some(version) if version == STORAGE_SCHEMA_VERSION_BETA1 => {
                SchemaMigrationAction::BackfillCurrent
            }
            Some(version) if is_legacy_hard_cut_version(version) => {
                SchemaMigrationAction::HardResetRuntime {
                    reason: "legacy_schema_hard_cut",
                    migration: latest,
                }
            }
            Some(version) => {
                emit_schema_validation_failed("schema_version_mismatch", None, None);
                return Err(StoreError::SchemaVersionMismatch {
                    expected: STORAGE_SCHEMA_VERSION.to_string(),
                    actual: version.to_string(),
                });
            }
        };
        emit_schema_plan_resolved(&action, normalized, pending_migrations.len());
        Ok(Self {
            current_version: normalized.map(ToString::to_string),
            target_version: STORAGE_SCHEMA_VERSION,
            action,
            pending_migrations,
        })
    }

    pub(crate) fn hard_reset_migration(&self) -> Option<SchemaMigrationDefinition> {
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
            emit_schema_validation_failed(
                "unknown_migration_id",
                Some(applied_migration.id.as_str()),
                None,
            );
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
        emit_schema_validation_failed(
            "checksum_mismatch",
            Some(applied.id.as_str()),
            Some(expected.id),
        );
        return Err(StoreError::SchemaVersionMismatch {
            expected: format!("{} {}", expected.id, expected.checksum),
            actual: format!("{} {}", applied.id, applied.checksum),
        });
    }
    if !applied.success {
        emit_schema_validation_failed(
            "migration_not_successful",
            Some(applied.id.as_str()),
            Some(expected.id),
        );
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

fn emit_schema_validation_failed(
    reason: &'static str,
    migration_id: Option<&str>,
    expected_migration_id: Option<&str>,
) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "db.schema_validation_failed",
        reason = %(reason),
        migration_id = ?migration_id,
        expected_migration_id = ?expected_migration_id
    );
}

fn emit_schema_plan_resolved(
    action: &SchemaMigrationAction,
    current_version: Option<&str>,
    pending_migrations: usize,
) {
    let action_name = match action {
        SchemaMigrationAction::FreshInstall => "fresh_install",
        SchemaMigrationAction::BackfillCurrent => "backfill_current",
        SchemaMigrationAction::HardResetRuntime { .. } => "hard_reset_runtime",
    };
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "db.schema_plan_resolved",
        action = %(action_name),
        pending_migrations = (pending_migrations as u64),
        current_version = ?current_version
    );
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedSchemaMigration, CONCURRENCY_FENCING_V11_MIGRATION, DEVICE_IDENTITY_V8_MIGRATION,
        FORMAL_RELEASE_V10_MIGRATION, OBSERVABILITY_V9_MIGRATION, SCHEMA_MIGRATIONS,
        SchemaMigrationAction, SchemaMigrationPlan, latest_schema_migration,
        pending_schema_migrations, validate_applied_schema_migrations,
    };
    use crate::storage::{
        STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_BETA1,
        STORAGE_SCHEMA_VERSION_FORMAL_RELEASE, STORAGE_SCHEMA_VERSION_MIGRATABLE,
        STORAGE_SCHEMA_VERSION_PREVIOUS,
    };

    #[test]
    fn migration_catalog_exposes_latest_schema_version() {
        assert_eq!(latest_schema_migration(), CONCURRENCY_FENCING_V11_MIGRATION);
        assert_eq!(
            latest_schema_migration().target_schema_version,
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            SCHEMA_MIGRATIONS.last(),
            Some(&CONCURRENCY_FENCING_V11_MIGRATION)
        );
    }

    #[test]
    fn migration_catalog_declares_upgrade_policy_for_every_migration() {
        for migration in SCHEMA_MIGRATIONS {
            assert!(!migration.id.trim().is_empty());
            assert!(!migration.description.trim().is_empty());
            assert!(!migration.checksum.trim().is_empty());
            assert!(!migration.target_schema_version.trim().is_empty());
            assert!(
                !migration.steps.is_empty(),
                "{} must expose at least one operator-visible step",
                migration.id
            );
            for step in migration.steps {
                assert!(
                    !step.id.trim().is_empty() && !step.description.trim().is_empty(),
                    "{} contains an incomplete step policy",
                    migration.id
                );
            }
        }
    }

    #[test]
    fn missing_meta_with_runtime_tables_hard_resets() {
        let plan = SchemaMigrationPlan::for_state(None, true, &[]).expect("plan should resolve");
        assert!(plan.hard_reset_migration().is_some());
        assert_eq!(
            plan.action,
            SchemaMigrationAction::HardResetRuntime {
                reason: "legacy_runtime_without_schema_meta",
                migration: CONCURRENCY_FENCING_V11_MIGRATION,
            }
        );
        assert_eq!(
            plan.pending_migrations,
            vec![
                DEVICE_IDENTITY_V8_MIGRATION,
                OBSERVABILITY_V9_MIGRATION,
                FORMAL_RELEASE_V10_MIGRATION,
                CONCURRENCY_FENCING_V11_MIGRATION
            ]
        );
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
        let applied = vec![
            AppliedSchemaMigration {
                id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
                checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: OBSERVABILITY_V9_MIGRATION.id.to_string(),
                checksum: OBSERVABILITY_V9_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: FORMAL_RELEASE_V10_MIGRATION.id.to_string(),
                checksum: FORMAL_RELEASE_V10_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: CONCURRENCY_FENCING_V11_MIGRATION.id.to_string(),
                checksum: CONCURRENCY_FENCING_V11_MIGRATION.checksum.to_string(),
                success: true,
            },
        ];
        let plan = SchemaMigrationPlan::for_state(Some(STORAGE_SCHEMA_VERSION), true, &applied)
            .expect("plan should resolve");
        assert_eq!(plan.action, SchemaMigrationAction::BackfillCurrent);
        assert!(plan.pending_migrations.is_empty());
    }

    #[test]
    fn v8_schema_version_backfills_through_v11_in_place() {
        let applied = vec![AppliedSchemaMigration {
            id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
            checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
            success: true,
        }];
        let plan =
            SchemaMigrationPlan::for_state(Some(STORAGE_SCHEMA_VERSION_MIGRATABLE), true, &applied)
                .expect("plan should resolve");
        assert_eq!(plan.action, SchemaMigrationAction::BackfillCurrent);
        assert_eq!(
            plan.pending_migrations,
            vec![
                OBSERVABILITY_V9_MIGRATION,
                FORMAL_RELEASE_V10_MIGRATION,
                CONCURRENCY_FENCING_V11_MIGRATION
            ]
        );
    }

    #[test]
    fn beta1_v9_schema_backfills_to_v11_in_place() {
        let applied = vec![
            AppliedSchemaMigration {
                id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
                checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: OBSERVABILITY_V9_MIGRATION.id.to_string(),
                checksum: OBSERVABILITY_V9_MIGRATION.checksum.to_string(),
                success: true,
            },
        ];
        let plan =
            SchemaMigrationPlan::for_state(Some(STORAGE_SCHEMA_VERSION_BETA1), true, &applied)
                .expect("beta1 plan should resolve");
        assert_eq!(plan.action, SchemaMigrationAction::BackfillCurrent);
        assert_eq!(
            plan.pending_migrations,
            vec![
                FORMAL_RELEASE_V10_MIGRATION,
                CONCURRENCY_FENCING_V11_MIGRATION
            ]
        );
    }

    #[test]
    fn formal_v10_schema_backfills_concurrency_fencing_in_place() {
        let applied = vec![
            AppliedSchemaMigration {
                id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
                checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: OBSERVABILITY_V9_MIGRATION.id.to_string(),
                checksum: OBSERVABILITY_V9_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: FORMAL_RELEASE_V10_MIGRATION.id.to_string(),
                checksum: FORMAL_RELEASE_V10_MIGRATION.checksum.to_string(),
                success: true,
            },
        ];
        let plan = SchemaMigrationPlan::for_state(
            Some(STORAGE_SCHEMA_VERSION_FORMAL_RELEASE),
            true,
            &applied,
        )
        .expect("formal v10 plan should resolve");
        assert_eq!(plan.action, SchemaMigrationAction::BackfillCurrent);
        assert_eq!(
            plan.pending_migrations,
            vec![CONCURRENCY_FENCING_V11_MIGRATION]
        );
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
        let pending = pending_schema_migrations(&[
            AppliedSchemaMigration {
                id: DEVICE_IDENTITY_V8_MIGRATION.id.to_string(),
                checksum: DEVICE_IDENTITY_V8_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: OBSERVABILITY_V9_MIGRATION.id.to_string(),
                checksum: OBSERVABILITY_V9_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: FORMAL_RELEASE_V10_MIGRATION.id.to_string(),
                checksum: FORMAL_RELEASE_V10_MIGRATION.checksum.to_string(),
                success: true,
            },
            AppliedSchemaMigration {
                id: CONCURRENCY_FENCING_V11_MIGRATION.id.to_string(),
                checksum: CONCURRENCY_FENCING_V11_MIGRATION.checksum.to_string(),
                success: true,
            },
        ]);
        assert!(pending.is_empty());
    }
}
