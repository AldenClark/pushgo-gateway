use std::{fs, path::Path};

const CHECKED_DIRS: &[&str] = &[
    "src/delivery_core/auth.rs",
    "src/delivery_core/error.rs",
    "src/delivery_core/payload",
    "src/delivery_core/planning",
    "src/delivery_core/response.rs",
    "src/domain_model",
];

const SUBMIT_RUNTIME_ADAPTER: &str = "src/delivery_core/execution/submit_runtime.rs";

const FORBIDDEN_PATTERNS: &[&str] = &[
    "crate::api",
    "crate::app",
    "crate::mcp",
    "crate::mqtt",
    "crate::providers",
    "crate::private",
    "crate::dispatch",
    "api::",
    "PrivatePayloadEnvelope",
    "ProviderPullDelivery",
    "AppState",
];

#[test]
fn delivery_core_semantic_layers_do_not_depend_on_edges_or_executors() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for relative_dir in CHECKED_DIRS {
        scan_rust_files(&manifest_dir.join(relative_dir), &mut |path, contents| {
            if path == manifest_dir.join(SUBMIT_RUNTIME_ADAPTER) {
                return;
            }
            for pattern in FORBIDDEN_PATTERNS {
                if contents.contains(pattern) {
                    violations.push(format!(
                        "{} contains forbidden dependency pattern `{}`",
                        path.strip_prefix(manifest_dir).unwrap_or(path).display(),
                        pattern
                    ));
                }
            }
        });
    }

    assert!(
        violations.is_empty(),
        "delivery_core domain/payload/planning boundary violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn submit_runtime_api_adapter_is_isolated_to_delivery_core_execution() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let adapter_source = fs::read_to_string(manifest_dir.join(SUBMIT_RUNTIME_ADAPTER))
        .expect("submit runtime adapter should be readable");
    let api_adapter_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/delivery_core_adapter.rs"))
            .expect("api delivery core adapter should be readable");
    let mut violations = Vec::new();

    for required in [
        "impl SubmitRuntime for AppState",
        "dispatch_entity_notification",
        "core_error_from_api",
    ] {
        if !adapter_source.contains(required) {
            violations.push(format!(
                "submit runtime adapter is missing transition marker `{required}`"
            ));
        }
    }
    for forbidden in [
        "impl SubmitRuntime for AppState",
        "dispatch_entity_notification",
        "legacy_summary_to_delivery_summary",
    ] {
        if api_adapter_source.contains(forbidden) {
            violations.push(format!(
                "api delivery_core_adapter still owns submit runtime marker `{forbidden}`"
            ));
        }
    }
    if adapter_source.contains("legacy_summary_to_delivery_summary") {
        violations.push(
            "submit runtime adapter still owns duplicate summary mapping after core summary migration"
                .to_string(),
        );
    }

    assert!(
        violations.is_empty(),
        "API submit runtime dependency must stay isolated in delivery_core::execution::submit_runtime:\n{}",
        violations.join("\n")
    );
}

#[test]
fn submit_runtime_contract_uses_stable_core_names_not_legacy_names() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let checked_files = [
        "src/delivery_core/submit.rs",
        "src/delivery_core/execution/mod.rs",
        "src/delivery_core/execution/request.rs",
        "src/delivery_core/execution/submit_runtime.rs",
        "src/api/handlers/delivery_core_adapter.rs",
    ];
    let forbidden = [
        concat!("legacy_", "dispatch"),
        concat!("Legacy", "MessageDispatchInput"),
        concat!("Legacy", "EventDispatchInput"),
        concat!("Legacy", "ThingDispatchInput"),
    ];
    let mut violations = Vec::new();

    for relative_file in checked_files {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("submit runtime contract source should be readable");
        for pattern in forbidden {
            if source.contains(pattern) {
                violations.push(format!(
                    "{relative_file} still uses legacy submit runtime marker `{pattern}`"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "submit runtime contract must use stable core naming, not legacy transition names:\n{}",
        violations.join("\n")
    );
}

#[test]
fn default_source_path_does_not_reintroduce_db_observability_or_legacy_stats_surface() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_roots = [
        "src/api",
        "src/app.rs",
        "src/args.rs",
        "src/delivery_core",
        "src/dispatch",
        "src/main.rs",
        "src/mcp",
        "src/mqtt",
        "src/private",
        "src/runtime_counters.rs",
        "src/services",
        "src/storage",
    ];
    let forbidden = [
        "StatsCollector",
        "StatsRuntimeTuning",
        "DispatchStatsEvent",
        "StatsEvent",
        "ChannelStatsDailyDelta",
        "DeviceStatsDailyDelta",
        "GatewayStatsHourlyDelta",
        "OpsStatsHourlyDelta",
        "stats_enabled",
        "gateway.stats.worker",
        "event = \"stats.",
        "INSERT INTO channel_stats_daily",
        "INSERT INTO device_stats_daily",
        "INSERT INTO gateway_stats_hourly",
        "INSERT INTO ops_stats_hourly",
        "INSERT INTO device_route_audit",
        "INSERT INTO subscription_audit",
        "CREATE TABLE IF NOT EXISTS channel_stats_daily",
        "CREATE TABLE IF NOT EXISTS device_stats_daily",
        "CREATE TABLE IF NOT EXISTS gateway_stats_hourly",
        "CREATE TABLE IF NOT EXISTS ops_stats_hourly",
        "CREATE TABLE IF NOT EXISTS device_route_audit",
        "CREATE TABLE IF NOT EXISTS subscription_audit",
    ];
    let allowed_drop_prefix = "DROP TABLE IF EXISTS ";
    let mut violations = Vec::new();

    for root in source_roots {
        scan_rust_files(&manifest_dir.join(root), &mut |path, contents| {
            if is_test_source(path) {
                return;
            }
            for line in contents.lines() {
                for pattern in forbidden {
                    if line.contains(pattern) {
                        violations.push(format!(
                            "{} contains legacy observability pattern `{}`: {}",
                            path.strip_prefix(manifest_dir).unwrap_or(path).display(),
                            pattern,
                            line.trim()
                        ));
                    }
                }
                if line.contains("channel_stats_daily")
                    || line.contains("device_stats_daily")
                    || line.contains("gateway_stats_hourly")
                    || line.contains("ops_stats_hourly")
                    || line.contains("device_route_audit")
                    || line.contains("subscription_audit")
                {
                    let trimmed = line.trim();
                    if !trimmed.contains(allowed_drop_prefix) {
                        violations.push(format!(
                            "{} references legacy observability table outside bootstrap drop path: {}",
                            path.strip_prefix(manifest_dir).unwrap_or(path).display(),
                            trimmed
                        ));
                    }
                }
            }
        });
    }

    assert!(
        violations.is_empty(),
        "legacy DB observability/runtime stats surface must stay out of the default source path:\n{}",
        violations.join("\n")
    );
}

#[test]
fn public_docs_do_not_reintroduce_db_observability_contract() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = ["readme.md"];
    let forbidden = [
        "Operations Stats (DB)",
        "运营统计（入库）",
        "stats is persisted",
        "ops_stats_hourly (`bucket_hour`",
        "gateway now writes operational hourly counters",
        "gateway 还会把运营向小时计数写入",
        "stats 10 秒刷盘",
        "stats 2 秒刷盘",
        "stats flush",
    ];
    let mut violations = Vec::new();

    for relative_file in docs {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("public doc should be readable");
        for pattern in forbidden {
            if source.contains(pattern) {
                violations.push(format!(
                    "{relative_file} still documents legacy DB observability contract `{pattern}`"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "public docs must describe tracing-based troubleshooting, not DB stats/audit writes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn public_surface_uses_tracing_level_not_observability_modes() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let checked_roots = [
        "src/args.rs",
        "src/app.rs",
        "src/main.rs",
        "scripts",
        "tests",
        "readme.md",
    ];
    let forbidden = [
        concat!("--observability-", "profile"),
        concat!("PUSHGO_OBSERVABILITY_", "PROFILE"),
        concat!("Observability", "Profile"),
        concat!("observability_", "profile"),
    ];
    let mut violations = Vec::new();

    for relative_root in checked_roots {
        scan_rust_files_and_text(&manifest_dir.join(relative_root), &mut |path, contents| {
            for pattern in forbidden {
                if contents.contains(pattern) {
                    violations.push(format!(
                        "{} exposes removed observability profile surface `{pattern}`",
                        path.strip_prefix(manifest_dir).unwrap_or(path).display()
                    ));
                }
            }
        });
    }

    assert!(
        violations.is_empty(),
        "observability profile surface must stay removed; troubleshooting is opt-in tracing level/RUST_LOG only:\n{}",
        violations.join("\n")
    );
}

#[test]
fn implementation_audit_tracks_design_and_plan_phases() {
    let workspace_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway repo should have workspace parent");
    let audit = fs::read_to_string(
        workspace_dir.join("docs/design/gateway-domain-delivery-core-implementation-audit.md"),
    )
    .expect("implementation audit should be readable");
    let mut violations = Vec::new();

    for required in [
        "gateway-domain-delivery-core-design.md",
        "gateway-domain-delivery-core-implementation-plan.md",
        "Phase 0: Behavior Lock",
        "Phase 1: Core Facade And Store Traits",
        "Phase 2: Message Domain Normalization",
        "Phase 3: Event And Thing Normalization",
        "Phase 4: Payload Pipeline Extraction",
        "Phase 5: DeliveryPlan, Queue Claim, Backpressure",
        "Phase 6: Execution Boundaries",
        "Phase 7: MQTT Roles",
        "Phase 8: Observability Removal And Tracing",
        "Phase 9: Active Data Lifecycle Cleanup",
        "scripts/storage_crossdb_parity.sh",
        "Completion Criteria",
    ] {
        if !audit.contains(required) {
            violations.push(format!(
                "implementation audit is missing required coverage marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "implementation audit must track all design/plan phases and remaining gates:\n{}",
        violations.join("\n")
    );
}

#[test]
fn provider_adapters_do_not_own_payload_size_path_selection() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let provider_job_adapter_files = [
        "src/api/handlers/message/dispatch/android.rs",
        "src/api/handlers/message/dispatch/apple.rs",
        "src/api/handlers/message/dispatch/windows.rs",
    ];
    let provider_job_adapter_forbidden = [
        "ProviderDeliverySelection::",
        ".encoded_len()",
        ".encoded_body(",
        "record_provider_path_rejected(",
        ".try_send_apns(",
        ".try_send_fcm(",
        ".try_send_wns(",
        "ApnsJob",
        "FcmJob",
        "WnsJob",
    ];
    let mut violations = Vec::new();

    for relative_file in provider_job_adapter_files {
        let path = manifest_dir.join(relative_file);
        let contents = fs::read_to_string(&path).expect("provider adapter should be readable");
        for pattern in provider_job_adapter_forbidden {
            if contents.contains(pattern) {
                violations.push(format!(
                    "{} still owns provider path decision pattern `{}`",
                    relative_file, pattern
                ));
            }
        }
    }
    let provider_coordinator_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/provider.rs"))
            .expect("provider coordinator should be readable");
    let provider_coordinator_production = provider_coordinator_source
        .split_once("#[cfg(test)]")
        .map_or(provider_coordinator_source.as_str(), |(production, _)| {
            production
        });
    for pattern in [
        "ProviderDeliverySelection::",
        ".encoded_len()",
        ".encoded_body(",
    ] {
        if provider_coordinator_production.contains(pattern) {
            violations.push(format!(
                "src/api/handlers/message/dispatch/provider.rs still owns provider payload-size decision pattern `{pattern}`"
            ));
        }
    }

    let provider_execution_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/provider.rs"))
            .expect("provider execution source should be readable");
    for required in [
        "prepare_apns_payload",
        "prepare_fcm_payload",
        "prepare_wns_payload",
        "ProviderPayloadPreparationError",
        "ProviderDeliverySelection::resolve",
        "ProviderDeliverySelection::direct",
        "ProviderDeliverySelection::wakeup_pull",
    ] {
        if !provider_execution_source.contains(required) {
            violations.push(format!(
                "provider execution boundary is missing payload path selection marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "provider payload size/path selection should stay in the provider execution coordinator:\n{}",
        violations.join("\n")
    );
}

#[test]
fn provider_payload_set_construction_is_owned_by_core_execution() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_provider_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/provider.rs"))
            .expect("core provider execution source should be readable");
    let api_types_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/types.rs"))
            .expect("api dispatch types source should be readable");
    let api_dispatch_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/mod.rs"))
            .expect("api dispatch source should be readable");
    let core_coordinator_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/coordinator.rs"))
            .expect("core coordinator source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) struct ProviderPayloadSet",
        "pub(crate) struct ProviderPayloadSetInput",
        "pub(crate) fn build_provider_payload_set",
        "ApnsPayload::new",
        "WnsPayload::new",
        "quantize_watch_payload",
        "apns_collapse_id",
    ] {
        if !core_provider_source.contains(required) {
            violations.push(format!(
                "core provider execution is missing payload-set construction marker `{required}`"
            ));
        }
    }
    for forbidden in [
        "ApnsPayload::new",
        "WnsPayload::new",
        "quantize_watch_payload",
        "has_watchos_apns",
    ] {
        if api_types_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch types still owns provider payload-set construction marker `{forbidden}`"
            ));
        }
        if api_dispatch_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch coordinator still owns provider payload-set construction marker `{forbidden}`"
            ));
        }
    }
    for required in [
        "type ProviderPayloads = ProviderPayloadSet",
        "build_provider_payload_set",
        "ProviderPayloadSetInput",
    ] {
        if !core_coordinator_source.contains(required) {
            violations.push(format!(
                "core dispatch coordinator is missing provider payload-set adapter marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "provider payload-set construction must live in delivery_core::execution::provider:\n{}",
        violations.join("\n")
    );
}

#[test]
fn provider_job_enqueue_is_owned_by_core_execution_boundary() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let provider_execution_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/provider.rs"))
            .expect("provider execution source should be readable");
    let mut violations = Vec::new();

    for required in [
        "ProviderDispatchPayload",
        "ProviderDispatchContext",
        "enqueue_provider_dispatch",
        "try_send_apns",
        "try_send_fcm",
        "try_send_wns",
    ] {
        if !provider_execution_source.contains(required) {
            violations.push(format!(
                "provider execution boundary is missing job enqueue marker `{required}`"
            ));
        }
    }

    for relative_file in [
        "src/api/handlers/message/dispatch/android.rs",
        "src/api/handlers/message/dispatch/apple.rs",
        "src/api/handlers/message/dispatch/windows.rs",
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("adapter should be readable");
        if !source.contains("enqueue_provider_dispatch") {
            violations.push(format!(
                "{relative_file} does not call the core provider enqueue boundary"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "provider job construction/enqueue must be owned by delivery_core::execution::provider:\n{}",
        violations.join("\n")
    );
}

#[test]
fn storage_cleanup_hard_delete_requires_frozen_subscriptions() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let maintenance_files = [
        "src/storage/database/sqlite/access/maintenance.rs",
        "src/storage/database/pg/access/maintenance.rs",
        "src/storage/database/mysql/access/maintenance.rs",
    ];
    let forbidden = [
        "s.status <> 'active'",
        "s.status != 'active'",
        "status <> 'active'",
        "status != 'active'",
    ];
    let mut violations = Vec::new();

    for relative_file in maintenance_files {
        let path = manifest_dir.join(relative_file);
        let contents = fs::read_to_string(&path).expect("maintenance source should be readable");
        if !contents.contains("SUBSCRIPTION_STATUS_FROZEN")
            || !contents.contains("status = 'frozen'")
        {
            violations.push(format!(
                "{} does not prove frozen subscription cleanup state is used",
                relative_file
            ));
        }
        for pattern in forbidden {
            if contents.contains(pattern) {
                violations.push(format!(
                    "{} allows inactive-or-any-non-active subscription hard delete pattern `{}`",
                    relative_file, pattern
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "hard delete cleanup must require frozen subscriptions, not merely non-active subscriptions:\n{}",
        violations.join("\n")
    );
}

#[test]
fn storage_queue_state_boundaries_match_delivery_roles() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bootstrap_files = [
        "src/storage/database/sqlite/bootstrap.rs",
        "src/storage/database/pg/bootstrap.rs",
        "src/storage/database/mysql/bootstrap.rs",
    ];
    let provider_access_files = [
        "src/storage/database/sqlite/access/provider.rs",
        "src/storage/database/pg/access/provider.rs",
        "src/storage/database/mysql/access/provider.rs",
    ];
    let mut violations = Vec::new();

    for relative_file in bootstrap_files {
        let source =
            fs::read_to_string(manifest_dir.join(relative_file)).expect("bootstrap source");
        if !source.contains("private_outbox")
            || !source.contains("status")
            || !source.contains("attempts")
            || !source.contains("claimed_at")
            || !source.contains("next_attempt_at")
        {
            violations.push(format!(
                "{relative_file} does not keep private_outbox claim/retry state"
            ));
        }
        if !source.contains("provider_pull_queue") {
            violations.push(format!(
                "{relative_file} does not define provider_pull_queue"
            ));
        }
        for forbidden in [
            "provider_pull_queue (status",
            "ALTER TABLE provider_pull_queue ADD COLUMN claimed_at",
            "ALTER TABLE provider_pull_queue ADD COLUMN claim_until",
            "ALTER TABLE provider_pull_queue ADD COLUMN lease_until",
            "ALTER TABLE provider_pull_queue ADD COLUMN attempt_no",
            "ALTER TABLE provider_pull_queue ADD COLUMN retry_at",
        ] {
            if source.contains(forbidden) {
                violations.push(format!(
                    "{relative_file} models provider_pull_queue as worker claim queue via `{forbidden}`"
                ));
            }
        }
    }

    for relative_file in provider_access_files {
        let source =
            fs::read_to_string(manifest_dir.join(relative_file)).expect("provider access source");
        for required in [
            "pull_provider_item",
            "pull_provider_items",
            "ack_provider_item",
            "DELETE FROM provider_pull_queue",
        ] {
            if !source.contains(required) {
                violations.push(format!(
                    "{relative_file} is missing provider pull-cache behavior marker `{required}`"
                ));
            }
        }
        for forbidden in ["claimed_at", "lease_until", "attempt_no", "retry_at"] {
            if source.contains(forbidden) {
                violations.push(format!(
                    "{relative_file} leaks worker claim/retry semantics into provider pull cache via `{forbidden}`"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "storage queue state must distinguish private outbox retry state from provider pull cache:\n{}",
        violations.join("\n")
    );
}

#[test]
fn domain_model_contract_lives_outside_delivery_core() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let domain_model_dir = manifest_dir.join("src/domain_model");
    let delivery_core_domain =
        fs::read_to_string(manifest_dir.join("src/delivery_core/domain/mod.rs"))
            .expect("delivery_core domain compatibility module should be readable");
    let mut violations = Vec::new();

    for required in [
        "message.rs",
        "event.rs",
        "thing.rs",
        "spec.rs",
        "projection.rs",
        "ids.rs",
        "common.rs",
    ] {
        if !domain_model_dir.join(required).exists() {
            violations.push(format!("src/domain_model is missing {required}"));
        }
    }

    if !delivery_core_domain.contains("pub(crate) use crate::domain_model") {
        violations.push(
            "delivery_core::domain must stay a compatibility re-export of domain_model".to_string(),
        );
    }
    if delivery_core_domain.contains("pub(crate) mod message")
        || delivery_core_domain.contains("pub(crate) mod event")
        || delivery_core_domain.contains("pub(crate) mod thing")
    {
        violations.push(
            "delivery_core::domain reintroduced model implementations under delivery core"
                .to_string(),
        );
    }

    assert!(
        violations.is_empty(),
        "domain model contract must remain a shared layer outside delivery_core:\n{}",
        violations.join("\n")
    );
}

#[test]
fn queue_claim_contract_has_worker_lease_attempt_retry_semantics() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let queue_contract =
        fs::read_to_string(manifest_dir.join("src/delivery_core/store/delivery_queue.rs"))
            .expect("delivery queue contract should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) struct QueueWorkerId",
        "pub(crate) struct QueueLease",
        "lease_until_ts",
        "pub(crate) struct QueueAttempt",
        "attempt_no",
        "pub(crate) struct QueueRetry",
        "retry_at",
        "pub(crate) enum QueueClaimState",
        "pub(crate) struct QueueClaimRequest",
        "pub(crate) struct QueueClaimedTarget",
        "worker_id: QueueWorkerId",
        "QueueClaimedTarget::from_private_outbox",
    ] {
        if !queue_contract.contains(required) {
            violations.push(format!(
                "delivery queue contract is missing queue semantic marker `{required}`"
            ));
        }
    }

    let storage_entry = fs::read_to_string(manifest_dir.join("src/storage/types/private.rs"))
        .expect("private storage types should be readable");
    for required in [
        "pub claimed_by: Option<String>",
        "pub claimed_at: Option<i64>",
    ] {
        if !storage_entry.contains(required) {
            violations.push(format!(
                "private outbox storage entry is missing claim ownership marker `{required}`"
            ));
        }
    }

    for relative_file in [
        "src/storage/database/sqlite/access/outbox.rs",
        "src/storage/database/pg/access/outbox.rs",
        "src/storage/database/mysql/access/outbox.rs",
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("outbox claim source should be readable");
        for required in [
            "worker_id: &str",
            "claimed_by",
            "claimed_at IS NULL OR claimed_at <=",
            "OUTBOX_STATUS_PENDING",
            "OUTBOX_STATUS_CLAIMED",
            "OUTBOX_STATUS_SENT",
        ] {
            if !source.contains(required) {
                violations.push(format!(
                    "{relative_file} is missing queue claim/lease marker `{required}`"
                ));
            }
        }
        if relative_file.contains("/pg/") && !source.contains("FOR UPDATE SKIP LOCKED") {
            violations.push("postgres claim path must use FOR UPDATE SKIP LOCKED".to_string());
        }
        if relative_file.contains("/sqlite/") && !source.contains("BEGIN IMMEDIATE") {
            violations
                .push("sqlite claim path must use bounded single-writer transaction".to_string());
        }
        if relative_file.contains("/mysql/") && !source.contains("FOR UPDATE") {
            violations.push("mysql claim path must use row locking".to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "queue claim/lease/retry semantics must be explicit in core and storage:\n{}",
        violations.join("\n")
    );
}

#[test]
fn active_data_lifecycle_has_delivery_activity_signals() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    let access_source = fs::read_to_string(manifest_dir.join("src/storage/database/access.rs"))
        .expect("database access source should be readable");
    if !access_source.contains("touch_device_activity") {
        violations.push(
            "DeviceRouteDatabaseAccess is missing touch_device_activity activity signal"
                .to_string(),
        );
    }

    let private_delivery_source =
        fs::read_to_string(manifest_dir.join("src/storage/storage/private_delivery.rs"))
            .expect("private delivery storage source should be readable");
    let channel_service_source = fs::read_to_string(manifest_dir.join("src/services/channel.rs"))
        .expect("channel service source should be readable");
    let channel_sync_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/core/channels/sync.rs"))
            .expect("channel sync source should be readable");
    let subscription_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/core/channels/subscription.rs"))
            .expect("channel subscription source should be readable");
    let mqtt_server_source = fs::read_to_string(manifest_dir.join("src/mqtt/server.rs"))
        .expect("mqtt server source should be readable");
    let private_auth_source =
        fs::read_to_string(manifest_dir.join("src/private/warp_engine/server_app/auth.rs"))
            .expect("private auth source should be readable");
    for required in [
        "record_device_activity_best_effort",
        "\"private_ack\"",
        "\"provider_pull\"",
        "\"provider_ack\"",
    ] {
        if !private_delivery_source.contains(required) {
            violations.push(format!(
                "private/provider delivery path is missing activity marker `{required}`"
            ));
        }
    }
    for (source_name, source, required, touch_marker) in [
        (
            "private channel subscribe",
            channel_service_source.as_str(),
            "\"private_channel_subscribe\"",
            "record_device_activity_best_effort",
        ),
        (
            "provider channel subscribe",
            subscription_source.as_str(),
            "\"provider_channel_subscribe\"",
            "record_route_activity_for_device_key",
        ),
        (
            "channel sync",
            channel_sync_source.as_str(),
            "\"private_channel_sync\"",
            "record_device_activity_best_effort",
        ),
        (
            "channel sync",
            channel_sync_source.as_str(),
            "\"provider_channel_sync\"",
            "record_route_activity_for_device_key",
        ),
        (
            "mqtt connect",
            mqtt_server_source.as_str(),
            "\"mqtt_connect\"",
            "record_device_activity_best_effort",
        ),
        (
            "private connect",
            private_auth_source.as_str(),
            "\"private_connect\"",
            "record_device_activity_best_effort",
        ),
    ] {
        if !source.contains(touch_marker) || !source.contains(required) {
            violations.push(format!(
                "{source_name} path is missing active-device activity marker `{required}`"
            ));
        }
    }

    for relative_file in [
        "src/storage/database/sqlite/access/routes.rs",
        "src/storage/database/pg/access/routes.rs",
        "src/storage/database/mysql/access/routes.rs",
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("route source should be readable");
        for required in ["touch_device_activity", "route_updated_at"] {
            if !source.contains(required) {
                violations.push(format!(
                    "{relative_file} is missing device activity persistence marker `{required}`"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "active data lifecycle must refresh device activity from successful ACK/PULL paths:\n{}",
        violations.join("\n")
    );
}

#[test]
fn maintenance_cleanup_tracing_explains_thresholds_and_counts() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let storage_system_source =
        fs::read_to_string(manifest_dir.join("src/storage/storage/system.rs"))
            .expect("storage system source should be readable");
    let private_fallback_source =
        fs::read_to_string(manifest_dir.join("src/private/runtime_tasks/fallback.rs"))
            .expect("private fallback source should be readable");
    let mut violations = Vec::new();

    for required in [
        "event = \"storage.maintenance_cleanup_started\"",
        "event = \"storage.maintenance_cleanup_dry_run\"",
        "event = \"storage.maintenance_cleanup_finished\"",
        "private_outbox_pruned",
        "provider_pull_pruned",
        "orphan_devices_pruned",
        "stale_subscriptions_pruned",
        "frozen_subscriptions_pruned",
        "soft_deleted_devices_pruned",
        "orphan_channels_pruned",
        "private_stale_outbox_before",
        "dedupe_before",
        "orphan_device_before",
        "stale_subscription_before",
        "frozen_subscription_before",
        "soft_deleted_device_before",
        "orphan_channel_before",
    ] {
        if !storage_system_source.contains(required) {
            violations.push(format!(
                "storage cleanup tracing is missing explanatory marker `{required}`"
            ));
        }
    }

    for required in [
        "event = \"private.maintenance_cleanup\"",
        "private_outbox_pruned",
        "provider_pull_pruned",
        "orphan_devices_pruned",
        "stale_subscriptions_pruned",
        "frozen_subscriptions_pruned",
        "soft_deleted_devices_pruned",
        "orphan_channels_pruned",
    ] {
        if !private_fallback_source.contains(required) {
            violations.push(format!(
                "private maintenance cleanup tracing is missing count marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "maintenance cleanup must stay explainable through redacted tracing counts and thresholds:\n{}",
        violations.join("\n")
    );
}

#[test]
fn submit_runtime_dispatch_execution_consumes_plan_derived_targets() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dispatch_files = [
        "src/api/handlers/message/dispatch/mod.rs",
        "src/api/handlers/message/dispatch/provider.rs",
        "src/api/handlers/message/dispatch/private.rs",
        "src/api/handlers/message/dispatch/types.rs",
    ];
    let mut violations = Vec::new();
    for relative_file in dispatch_files {
        let path = manifest_dir.join(relative_file);
        let contents = fs::read_to_string(&path).expect("dispatch source should be readable");
        if contents.contains("provider_devices") {
            violations.push(format!(
                "{} still references pre-plan provider_devices execution field",
                relative_file
            ));
        }
        if contents.contains("subscribers: Vec<DeviceId>")
            || contents.contains("private_subscribers_from_plan")
        {
            violations.push(format!(
                "{} still references pre-plan private subscriber execution field",
                relative_file
            ));
        }
        for forbidden_definition in [
            "struct ProviderExecutionTarget",
            "struct PrivateExecutionTarget",
            "fn provider_targets_from_plan",
            "fn private_targets_from_plan",
        ] {
            if contents.contains(forbidden_definition) {
                violations.push(format!(
                    "{} owns core execution target definition `{}`",
                    relative_file, forbidden_definition
                ));
            }
        }
    }

    for (relative_file, required) in [
        (
            "src/delivery_core/execution/private.rs",
            "private_targets_from_plan",
        ),
        (
            "src/delivery_core/execution/private.rs",
            "PrivateExecutionTarget",
        ),
        (
            "src/delivery_core/execution/private.rs",
            "execute_private_deliveries",
        ),
        (
            "src/delivery_core/execution/private.rs",
            "PrivateDeliveryExecution",
        ),
        (
            "src/delivery_core/execution/provider.rs",
            "provider_targets_from_plan",
        ),
        (
            "src/delivery_core/execution/provider.rs",
            "ProviderExecutionTarget",
        ),
        (
            "src/delivery_core/execution/mqtt_receiver.rs",
            "mqtt_receiver_targets_from_plan",
        ),
        (
            "src/delivery_core/execution/mqtt_receiver.rs",
            "MqttReceiverExecutionTarget",
        ),
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("core execution source should be readable");
        if !source.contains(required) {
            violations.push(format!(
                "{relative_file} is missing plan-derived execution marker `{required}`"
            ));
        }
    }
    let api_private_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/private.rs"))
            .expect("api private dispatch source should be readable");
    for forbidden in [
        ".enqueue_private_deliveries(",
        ".try_deliver_to_device(",
        "dispatch.private_realtime_delivery_failed",
        "dispatch.private_enqueue_failed",
    ] {
        if api_private_source.contains(forbidden) {
            violations.push(format!(
                "api private dispatch still owns private execution side effect `{forbidden}`"
            ));
        }
    }
    for required in ["execute_private_deliveries", "PrivateDeliveryExecution"] {
        if !api_private_source.contains(required) {
            violations.push(format!(
                "api private dispatch does not call core private execution marker `{required}`"
            ));
        }
    }
    let api_provider_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/provider.rs"))
            .expect("api provider dispatch source should be readable");
    if api_provider_source.contains(".enqueue_provider_pull_item(") {
        violations.push(
            "api provider dispatch still owns provider pull queue write side effect".to_string(),
        );
    }
    for required in [
        "cache_provider_pull_delivery",
        "ProviderPullCacheRequest",
        ".enqueue_provider_pull_item(",
        "cleanup_invalid_provider_token",
        "ProviderInvalidTokenCleanup",
        ".unsubscribe_channel_if_provider_route_current(",
        ".clear_private_outbox_for_device(",
        ".clear_device_outbox(",
    ] {
        let provider_execution =
            fs::read_to_string(manifest_dir.join("src/delivery_core/execution/provider.rs"))
                .expect("provider execution source should be readable");
        if !provider_execution.contains(required) {
            violations.push(format!(
                "provider execution boundary is missing provider-pull cache marker `{required}`"
            ));
        }
    }
    let provider_execution =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/provider.rs"))
            .expect("provider execution source should be readable");
    if provider_execution.contains(".unsubscribe_channel_for_device_key(") {
        violations.push(
            "provider invalid-token cleanup must not use unconditional unsubscribe".to_string(),
        );
    }
    let dispatch_worker_source = fs::read_to_string(manifest_dir.join("src/dispatch/workers.rs"))
        .expect("dispatch worker source should be readable");
    for forbidden in [
        ".unsubscribe_channel_for_device_key(",
        ".cleanup_private_outbox_on_invalid_token(",
        ".clear_private_outbox_for_device(",
        ".clear_device_outbox(",
    ] {
        if dispatch_worker_source.contains(forbidden) {
            violations.push(format!(
                "provider worker still owns invalid-token cleanup side effect `{forbidden}`"
            ));
        }
    }
    if !dispatch_worker_source.contains("cleanup_invalid_provider_token") {
        violations
            .push("provider worker does not call core invalid-token cleanup boundary".to_string());
    }

    assert!(
        violations.is_empty(),
        "submit runtime dispatch execution should consume DeliveryPlan-derived targets:\n{}",
        violations.join("\n")
    );
}

#[test]
fn provider_target_preparation_is_owned_by_core_execution_boundary() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_provider_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/provider.rs"))
            .expect("core provider execution source should be readable");
    let api_provider_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/provider.rs"))
            .expect("api provider dispatch source should be readable");
    let api_types_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/types.rs"))
            .expect("api dispatch types source should be readable");
    let api_ids_source = fs::read_to_string(manifest_dir.join("src/api/handlers/message/ids.rs"))
        .expect("api ids source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) trait ProviderRouteResolver",
        "pub(crate) struct ProviderTargetPreparation",
        "pub(crate) struct ResolvedProviderTarget",
        "pub(crate) fn prepare_provider_target",
        "ProviderStatsDeviceKey::resolve",
        "ProviderPullTarget::for_provider_target",
        "wakeup_data_with_delivery_id",
        "data.insert(\"delivery_id\".to_string(), delivery_id.to_string())",
    ] {
        if !core_provider_source.contains(required) {
            violations.push(format!(
                "core provider execution is missing target preparation marker `{required}`"
            ));
        }
    }

    for forbidden in [
        "struct ProviderRouteBinding",
        "ProviderStatsDeviceKey::resolve",
        "ProviderPullTarget::for_provider_target",
        "wakeup_data_with_delivery_id",
        "data.insert(\"delivery_id\".to_string(), delivery_id.to_string())",
    ] {
        if api_provider_source.contains(forbidden) {
            violations.push(format!(
                "api provider dispatch still owns provider target preparation marker `{forbidden}`"
            ));
        }
    }
    if api_ids_source.contains("wakeup_data_with_delivery_id") {
        violations.push(
            "api message ids still expose provider wakeup delivery-id preparation helper"
                .to_string(),
        );
    }
    for required in [
        "AppProviderRouteResolver",
        "prepare_provider_target",
        "impl From<CoreResolvedProviderTarget> for ResolvedProviderTarget",
        "provider_pull_target.map(ProviderPullDelivery::from)",
    ] {
        let source = if required.starts_with("impl From") || required.starts_with("provider_pull") {
            &api_types_source
        } else {
            &api_provider_source
        };
        if !source.contains(required) {
            violations.push(format!(
                "api provider adapter is missing core target adapter marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "provider target preparation must live in delivery_core::execution::provider:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dispatch_summary_semantics_are_owned_by_delivery_core() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_response_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/response.rs"))
            .expect("delivery core response source should be readable");
    let api_lifecycle_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/dispatch_lifecycle.rs"))
            .expect("api dispatch lifecycle source should be readable");
    let core_dedupe_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/dedupe.rs"))
            .expect("delivery core dedupe source should be readable");
    let submit_runtime_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/submit_runtime.rs"))
            .expect("submit runtime adapter source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) struct DeliverySummary",
        "pub(crate) enum DeliveryDedupeStatus",
        "pub(crate) enum DeliveryDispatchStatus",
        "pub(crate) enum DeliveryDedupeSettleAction",
        "fn dedupe_settle_action",
        "fn failure_error_message",
    ] {
        if !core_response_source.contains(required) {
            violations.push(format!(
                "delivery core response is missing dispatch summary semantic marker `{required}`"
            ));
        }
    }
    for forbidden in [
        "pub(crate) struct NotificationDispatchSummary",
        "pub(crate) enum DispatchDedupeStatus",
        "enum DispatchOpDedupeAction",
        "fn dedupe_action",
        "summary.dedupe_settle_action()",
    ] {
        if api_lifecycle_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch lifecycle still owns core summary semantic `{forbidden}`"
            ));
        }
    }
    for required in ["type NotificationDispatchSummary = DeliverySummary"] {
        if !api_lifecycle_source.contains(required) {
            violations.push(format!(
                "api dispatch lifecycle is missing core summary adapter marker `{required}`"
            ));
        }
    }
    if !core_dedupe_source.contains("summary.dedupe_settle_action()") {
        violations.push(
            "delivery core dedupe does not use DeliverySummary dedupe settle action".to_string(),
        );
    }
    if submit_runtime_source.contains("legacy_summary_to_delivery_summary") {
        violations.push(
            "submit runtime adapter still maps duplicate summary types instead of returning core DeliverySummary"
                .to_string(),
        );
    }

    assert!(
        violations.is_empty(),
        "dispatch summary/finalization semantics must live in delivery_core::response:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dispatch_progress_semantics_are_owned_by_delivery_core() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_progress_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/progress.rs"))
            .expect("core dispatch progress source should be readable");
    let api_counters_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/counters.rs"))
            .expect("api counters source should be readable");
    let api_types_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/types.rs"))
            .expect("api dispatch types source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) struct DispatchProgress",
        "pub(crate) struct PrivateEnqueueProgress",
        "fn record_private_success",
        "fn record_provider_queued",
        "fn record_provider_failure",
        "pub(crate) enum BusyKind",
        "BusyKind::PrivateEnqueueBackpressure",
        "fn classify_busy",
        "fn is_too_busy",
        "PRIVATE_ENQUEUE_TOO_BUSY_FAIL_RATIO_PERCENT",
    ] {
        if !core_progress_source.contains(required) {
            violations.push(format!(
                "core dispatch progress is missing progress semantic marker `{required}`"
            ));
        }
    }
    for forbidden in [
        "struct DispatchProgress",
        "struct PrivateEnqueueProgress",
        "PRIVATE_ENQUEUE_TOO_BUSY",
        "fn record_provider_success",
        "fn record_provider_failure",
        "fn is_too_busy",
        "merge_device_counter_delta",
    ] {
        if api_counters_source.contains(forbidden) {
            violations.push(format!(
                "api counters still owns dispatch progress semantic `{forbidden}`"
            ));
        }
        if api_types_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch types still owns dispatch progress semantic `{forbidden}`"
            ));
        }
    }
    if !api_counters_source.contains("record_dispatch(DispatchCounterEvent") {
        violations.push(
            "api counters should remain only the AppState runtime-counter adapter".to_string(),
        );
    }

    assert!(
        violations.is_empty(),
        "dispatch progress and too-busy semantics must live in delivery_core::execution::progress:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dispatch_op_dedupe_state_machine_is_owned_by_delivery_core() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_dedupe_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/dedupe.rs"))
            .expect("delivery core dedupe source should be readable");
    let api_lifecycle_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/dispatch_lifecycle.rs"))
            .expect("api dispatch lifecycle source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) trait DispatchDedupeStore",
        "pub(crate) struct DispatchOpGuard",
        "enum DispatchOpGuardDecision",
        "OpDedupeReservation::Sent",
        "OpDedupeReservation::Pending",
        "OpDedupeReservation::Reserved",
        "dispatch.dedupe_reserved",
        "dispatch.dedupe_settled",
    ] {
        if !core_dedupe_source.contains(required) {
            violations.push(format!(
                "delivery core dedupe is missing op-dedupe state-machine marker `{required}`"
            ));
        }
    }

    for forbidden in [
        "enum DispatchOpGuardDecision",
        "OpDedupeReservation::Sent",
        "OpDedupeReservation::Pending",
        "OpDedupeReservation::Reserved",
        "dispatch.dedupe_reserved",
        "dispatch.dedupe_settled",
        "dispatch.dedupe_finalize_failed",
        "dispatch.dedupe_clear_pending_failed",
    ] {
        if api_lifecycle_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch lifecycle still owns op-dedupe state-machine marker `{forbidden}`"
            ));
        }
    }

    for required in [
        "impl DispatchDedupeStore for AppState",
        "CoreDispatchOpGuard::begin_submission",
        ".finish_recoverable(state, dispatch_result)",
    ] {
        if !api_lifecycle_source.contains(required) {
            violations.push(format!(
                "api dispatch lifecycle is missing thin core-dedupe adapter marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "dispatch op-dedupe state machine must live in delivery_core::execution::dedupe:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dispatch_preparation_builder_is_owned_by_delivery_core() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_prepare_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/prepare.rs"))
            .expect("delivery core prepare source should be readable");
    let core_coordinator_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/coordinator.rs"))
            .expect("delivery core coordinator source should be readable");
    let api_dispatch_types_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/types.rs"))
            .expect("api dispatch types source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) struct DispatchPreparationInput",
        "pub(crate) struct PreparedDispatchCore",
        "pub(crate) fn prepare_dispatch_core",
        "CustomPayloadData::new",
        "DeliveryPlanner::plan",
        "private_targets_from_plan",
        "provider_targets_from_plan",
        "mqtt_receiver_supports_payload",
        "normalize_ttl_to_expires_at",
    ] {
        if !core_prepare_source.contains(required) {
            violations.push(format!(
                "delivery core prepare is missing dispatch preparation marker `{required}`"
            ));
        }
    }

    for forbidden in [
        "CustomPayloadData::new",
        "DeliveryPlanner::plan",
        "DeliveryPlanInput",
        "DeliveryPlanCandidate",
        "private_targets_from_plan",
        "provider_targets_from_plan",
        "mqtt_receiver_supports_payload",
        "should_promote_notification_title",
        "should_embed_standard_notification_text",
    ] {
        if api_dispatch_types_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch types still owns preparation marker `{forbidden}`"
            ));
        }
    }

    for required in [
        "PreparedDispatch::build",
        "prepare_dispatch_core",
        "DispatchPreparationInput",
        "DispatchExecutionRuntime",
    ] {
        if !core_coordinator_source.contains(required) {
            violations.push(format!(
                "delivery core coordinator is missing preparation orchestration marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "payload/plan dispatch preparation must live in delivery_core::execution::prepare:\n{}",
        violations.join("\n")
    );
}

#[test]
fn dispatch_execution_coordinator_is_owned_by_delivery_core() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_coordinator_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/coordinator.rs"))
            .expect("delivery core coordinator source should be readable");
    let api_dispatch_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/mod.rs"))
            .expect("api dispatch coordinator source should be readable");
    let api_types_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/types.rs"))
            .expect("api dispatch types source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) trait DispatchExecutionRuntime",
        "pub(crate) trait DispatchExecutionDelegate",
        "pub(crate) struct PreparedDispatch",
        "pub(crate) async fn execute_dispatch",
        "emit_dispatch_request_started",
        "emit_dispatch_request_finished",
        "emit_dispatch_request_failed",
        "record_dispatch_counters",
        "impl ProviderPayloads",
        "fn build(prepared: &PreparedDispatch",
    ] {
        if !core_coordinator_source.contains(required) {
            violations.push(format!(
                "delivery core coordinator is missing execution marker `{required}`"
            ));
        }
    }

    for forbidden in [
        "fn emit_dispatch_request_started",
        "fn emit_dispatch_request_finished",
        "fn emit_dispatch_request_failed",
        "PreparedDispatch::build",
        "prepare_dispatch_core",
        "DispatchBuildContext",
        "struct PreparedDispatch",
        "struct ProviderPayloads",
        "impl ProviderPayloads",
    ] {
        if api_dispatch_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch module still owns execution coordinator marker `{forbidden}`"
            ));
        }
        if api_types_source.contains(forbidden) {
            violations.push(format!(
                "api dispatch types still owns execution coordinator marker `{forbidden}`"
            ));
        }
    }

    for required in [
        "impl DispatchExecutionRuntime for AppState",
        "impl DispatchExecutionDelegate for ApiDispatchDelegate",
        "execute_dispatch(",
    ] {
        if !api_dispatch_source.contains(required) {
            violations.push(format!(
                "api dispatch module is missing thin coordinator adapter marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "dispatch execution coordinator must live in delivery_core::execution::coordinator:\n{}",
        violations.join("\n")
    );
}

#[test]
fn submit_facade_must_validate_source_response_mode_boundary() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let submit_source = fs::read_to_string(manifest_dir.join("src/delivery_core/submit.rs"))
        .expect("submit source should be readable");
    let mut violations = Vec::new();
    for forbidden in ["let _source =", "let _response_mode ="] {
        if submit_source.contains(forbidden) {
            violations.push(format!(
                "submit facade still discards command field with `{}`",
                forbidden
            ));
        }
    }
    for required in [
        "validate_submit_context(command.source, command.response_mode)",
        "source_response_mode_mismatch",
        "IngressSource::MqttPublish | IngressSource::MqttWill",
    ] {
        if !submit_source.contains(required) {
            violations.push(format!(
                "submit facade is missing source/response boundary marker `{}`",
                required
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "submit facade must enforce protocol source/response-mode admission:\n{}",
        violations.join("\n")
    );
}

#[test]
fn mcp_entity_tools_share_domain_submit_commands() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mcp_entity_source = fs::read_to_string(manifest_dir.join("src/mcp/rpc/entity.rs"))
        .expect("mcp entity source should be readable");
    let mut violations = Vec::new();

    for forbidden in [
        "event_create_authorized",
        "event_update_authorized",
        "event_close_authorized",
        "thing_create_authorized",
        "thing_update_authorized",
        "thing_archive_authorized",
        "thing_delete_authorized",
    ] {
        if mcp_entity_source.contains(forbidden) {
            violations.push(format!(
                "MCP entity tool still routes through HTTP authorized helper `{forbidden}`"
            ));
        }
    }

    for required in [
        "source: IngressSource::McpTool",
        "response_mode: ResponseMode::McpJson",
        "DomainCommandInput::Event",
        "DomainCommandInput::Thing",
        "submit_mcp_event_command",
        "submit_mcp_thing_command",
    ] {
        if !mcp_entity_source.contains(required) {
            violations.push(format!(
                "MCP entity tool is missing shared submit marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "MCP Event/Thing tools must share delivery_core submit commands with HTTP routes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn mqtt_roles_are_explicit_in_gateway_boundary() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let roles_source = fs::read_to_string(manifest_dir.join("src/mqtt/roles.rs"))
        .expect("mqtt roles source should be readable");
    let server_source = fs::read_to_string(manifest_dir.join("src/mqtt/server.rs"))
        .expect("mqtt server source should be readable");
    let ingress_source = fs::read_to_string(manifest_dir.join("src/mqtt/server/ingress_server.rs"))
        .expect("mqtt ingress server source should be readable");
    let receiver_source =
        fs::read_to_string(manifest_dir.join("src/mqtt/server/private_receiver.rs"))
            .expect("mqtt private receiver source should be readable");
    let mut violations = Vec::new();

    for required in [
        "enum MqttRole",
        "IngressPublish",
        "IngressWill",
        "PrivateReceiver",
        "MQTT_EXTERNAL_BRIDGE_IN_ROLE",
        "MQTT_EXTERNAL_BRIDGE_OUT_ROLE",
    ] {
        if !roles_source.contains(required) {
            violations.push(format!(
                "MQTT roles boundary is missing marker `{required}`"
            ));
        }
    }
    for required in ["mod ingress_server;", "mod private_receiver;"] {
        if !server_source.contains(required) {
            violations.push(format!(
                "MQTT server does not wire role module `{required}`"
            ));
        }
    }
    for required in [
        "MqttRole::IngressPublish",
        "MqttRole::IngressWill",
        "handle_publish",
        "validate_will",
        "send_will",
    ] {
        if !ingress_source.contains(required) {
            violations.push(format!(
                "MQTT ingress role module is missing marker `{required}`"
            ));
        }
    }
    for required in [
        "MqttRole::PrivateReceiver",
        "handle_puback",
        "write_delivery",
    ] {
        if !receiver_source.contains(required) {
            violations.push(format!(
                "MQTT private receiver role module is missing marker `{required}`"
            ));
        }
    }
    for forbidden in [
        "MqttRole::IngressPublish",
        "MqttRole::IngressWill",
        "MqttRole::PrivateReceiver",
        "async fn handle_publish",
        "async fn send_will",
        "async fn write_delivery",
        "async fn handle_puback",
    ] {
        if server_source.contains(forbidden) {
            violations.push(format!(
                "MQTT role implementation leaked back into server.rs via `{forbidden}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "MQTT ingress/private receiver/future bridge roles must stay explicit:\n{}",
        violations.join("\n")
    );
}

#[test]
fn planner_must_consume_domain_delivery_policy() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let planner_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/planning/planner.rs"))
            .expect("planner source should be readable");
    let prepare_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/prepare.rs"))
            .expect("dispatch prepare source should be readable");
    let core_coordinator_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/execution/coordinator.rs"))
            .expect("core coordinator source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) delivery_policy: DomainDeliveryPolicy",
        "input.delivery_policy.allow_private_realtime",
        "input.delivery_policy.allow_private_outbox",
        "input.delivery_policy.allow_provider_inline",
        "input.delivery_policy.allow_provider_wakeup_pull",
        "input.delivery_policy.allow_mqtt_receiver",
        "DeliverySkipReason::DomainPolicyDisabled",
    ] {
        if !planner_source.contains(required) {
            violations.push(format!(
                "DeliveryPlanner is missing domain delivery policy marker `{required}`"
            ));
        }
    }
    for required in ["delivery_policy,", "DeliveryPlanInput {"] {
        if !prepare_source.contains(required) {
            violations.push(format!(
                "core dispatch prepare is missing delivery policy propagation marker `{required}`"
            ));
        }
    }
    if !core_coordinator_source.contains("prepare_dispatch_core") {
        violations.push(
            "core dispatch coordinator should call the core dispatch preparation boundary"
                .to_string(),
        );
    }

    assert!(
        violations.is_empty(),
        "domain delivery policy must be consumed by planning, not only stored on projections:\n{}",
        violations.join("\n")
    );
}

#[test]
fn domain_action_specs_must_remain_descriptive_contracts() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let spec_source = fs::read_to_string(manifest_dir.join("src/domain_model/spec.rs"))
        .expect("domain spec source should be readable");
    let message_source = fs::read_to_string(manifest_dir.join("src/domain_model/message.rs"))
        .expect("message domain source should be readable");
    let event_source = fs::read_to_string(manifest_dir.join("src/domain_model/event.rs"))
        .expect("event domain source should be readable");
    let thing_source = fs::read_to_string(manifest_dir.join("src/domain_model/thing.rs"))
        .expect("thing domain source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) struct ActionSpec",
        "pub(crate) enum DomainModelKind",
        "pub(crate) enum DomainActionKind",
        "pub(crate) enum EntityIdKind",
        "required_fields",
        "forbidden_fields",
        "generated_id",
        "required_existing_id",
        "required_time_field",
    ] {
        if !spec_source.contains(required) {
            violations.push(format!("domain ActionSpec is missing `{required}`"));
        }
    }
    for (model, source) in [
        ("message", message_source.as_str()),
        ("event", event_source.as_str()),
        ("thing", thing_source.as_str()),
    ] {
        if !source.contains("ActionSpec") {
            violations.push(format!(
                "{model} domain module does not own ActionSpec metadata"
            ));
        }
    }
    for required in [
        "MessageSend::SPEC",
        "EventCommandKind::Create.spec()",
        "ThingCommandKind::Delete.spec()",
    ] {
        if !spec_source.contains(required) {
            violations.push(format!(
                "domain spec tests do not assert current contract marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "ActionSpec must remain a typed descriptive contract beside domain normalization:\n{}",
        violations.join("\n")
    );
}

#[test]
fn domain_commands_do_not_trust_payload_channel_identity() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let domain_files = [
        "src/domain_model/message.rs",
        "src/domain_model/event.rs",
        "src/domain_model/thing.rs",
    ];
    let mut violations = Vec::new();

    for relative in domain_files {
        let source = fs::read_to_string(manifest_dir.join(relative))
            .expect("domain source should be readable");
        if source.contains("pub(crate) channel_id: String") {
            violations.push(format!(
                "{relative} still stores payload channel_id inside a domain command"
            ));
        }
        if source.contains("\"channel_id\",") || source.contains("&[\"channel_id\"") {
            violations.push(format!(
                "{relative} still treats channel_id as a domain action field"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "channel identity must come from SubmitContext/Auth, not model payload fields:\n{}",
        violations.join("\n")
    );
}

#[test]
fn event_and_thing_domain_commands_do_not_interpret_business_payload_values() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let event_source = fs::read_to_string(manifest_dir.join("src/domain_model/event.rs"))
        .expect("event domain source should be readable");
    let thing_source = fs::read_to_string(manifest_dir.join("src/domain_model/thing.rs"))
        .expect("thing domain source should be readable");
    let value_mod_source =
        fs::read_to_string(manifest_dir.join("src/value/mod.rs")).expect("value mod readable");
    let mut violations = Vec::new();

    for forbidden in [
        "EventSeverity",
        "EventStatusText",
        "EventMessageText",
        "event_create_required_fields_missing",
        "event_state",
    ] {
        if event_source.contains(forbidden) {
            violations.push(format!(
                "event domain still interprets business payload via `{forbidden}`"
            ));
        }
    }
    for forbidden in [
        "ThingLocation",
        "ExternalIdPatchRef",
        "validate_manufacturer_attrs",
        "ExternalIdKey",
        "\"state\".to_string()",
    ] {
        if thing_source.contains(forbidden) {
            violations.push(format!(
                "thing domain still interprets business payload via `{forbidden}`"
            ));
        }
    }
    for forbidden in [
        "mod event;",
        "mod thing;",
        "EventSeverity",
        "ThingLocation",
        "ExternalIdKey",
    ] {
        if value_mod_source.contains(forbidden) {
            violations.push(format!(
                "value module still exports gateway-owned business parser `{forbidden}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "gateway should only validate technical Event/Thing fields and forward business payload values:\n{}",
        violations.join("\n")
    );
}

#[test]
fn payload_pipeline_keeps_materialization_steps_split() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let custom_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/payload/custom.rs"))
            .expect("custom payload source should be readable");
    let mut violations = Vec::new();

    for forbidden in [
        "postcard::to_allocvec",
        "build_provider_wakeup_data",
        "fn sanitize",
        "fn apple_thread_id",
        "fn encode_private_payload",
        "struct StandardFields",
    ] {
        if custom_source.contains(forbidden) {
            violations.push(format!(
                "CustomPayloadData still owns payload materialization detail `{forbidden}`"
            ));
        }
    }

    for (relative_file, required) in [
        (
            "src/delivery_core/payload/sanitize.rs",
            "PayloadFieldSanitizer",
        ),
        (
            "src/delivery_core/payload/standard.rs",
            "StandardPayloadBuilder",
        ),
        (
            "src/delivery_core/payload/notification.rs",
            "NotificationTextResolver",
        ),
        (
            "src/delivery_core/payload/private_envelope.rs",
            "PrivateEnvelopeEncoder",
        ),
        (
            "src/delivery_core/payload/provider_wakeup.rs",
            "ProviderWakeupProjection",
        ),
        (
            "src/delivery_core/payload/thread.rs",
            "AppleThreadIdResolver",
        ),
        (
            "src/delivery_core/payload/watch_light.rs",
            "quantize_watch_payload",
        ),
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("payload component source should be readable");
        if !source.contains(required) {
            violations.push(format!(
                "{relative_file} is missing payload component marker `{required}`"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "payload assembly must remain a split pipeline, not a broad materializer:\n{}",
        violations.join("\n")
    );
}

#[test]
fn watch_light_payload_quantization_is_owned_by_core_payload() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_source =
        fs::read_to_string(manifest_dir.join("src/delivery_core/payload/watch_light.rs"))
            .expect("watch light payload source should be readable");
    let api_handlers_mod = fs::read_to_string(manifest_dir.join("src/api/handlers/mod.rs"))
        .expect("api handlers mod should be readable");
    let api_dispatch_source =
        fs::read_to_string(manifest_dir.join("src/api/handlers/message/dispatch/mod.rs"))
            .expect("api dispatch source should be readable");
    let mut violations = Vec::new();

    for required in [
        "pub(crate) fn quantize_watch_payload",
        "watch_light_kind",
        "EntityKind::Event",
        "EntityKind::Thing",
        "EntityKind::Message",
    ] {
        if !core_source.contains(required) {
            violations.push(format!(
                "core watch light payload module is missing marker `{required}`"
            ));
        }
    }
    if manifest_dir
        .join("src/api/handlers/watch_light.rs")
        .exists()
    {
        violations
            .push("watch light payload quantization still exists under api handlers".to_string());
    }
    if api_handlers_mod.contains("watch_light") {
        violations.push("api handlers still exports watch_light payload module".to_string());
    }
    if api_dispatch_source.contains("api::handlers::watch_light") {
        violations.push("dispatch imports watch light payload logic from api handler".to_string());
    }

    assert!(
        violations.is_empty(),
        "watchOS/light provider payload projection must live in delivery_core::payload:\n{}",
        violations.join("\n")
    );
}

#[test]
fn delivery_core_store_contracts_are_narrow_and_explicit() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let store_mod_source = fs::read_to_string(manifest_dir.join("src/delivery_core/store/mod.rs"))
        .expect("store mod source should be readable");
    let mut violations = Vec::new();

    for (relative_file, required) in [
        ("src/delivery_core/store/channel.rs", "trait ChannelStore"),
        (
            "src/delivery_core/store/device_route.rs",
            "trait DeviceRouteStore",
        ),
        (
            "src/delivery_core/store/idempotency.rs",
            "trait IdempotencyStore",
        ),
        (
            "src/delivery_core/store/delivery_queue.rs",
            "trait DeliveryQueueStore",
        ),
        (
            "src/delivery_core/store/delivery_state.rs",
            "trait DeliveryStateStore",
        ),
        (
            "src/delivery_core/store/mcp_state.rs",
            "trait McpStateStore",
        ),
        (
            "src/delivery_core/store/counters.rs",
            "trait RuntimeCounterSink",
        ),
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("store contract source should be readable");
        if !source.contains(required) {
            violations.push(format!(
                "{relative_file} is missing store contract marker `{required}`"
            ));
        }
    }

    for required_module in [
        "pub(crate) mod channel;",
        "pub(crate) mod device_route;",
        "pub(crate) mod idempotency;",
        "pub(crate) mod delivery_queue;",
        "pub(crate) mod delivery_state;",
        "pub(crate) mod mcp_state;",
        "pub(crate) mod counters;",
    ] {
        if !store_mod_source.contains(required_module) {
            violations.push(format!("store module is missing `{required_module}`"));
        }
    }

    assert!(
        violations.is_empty(),
        "delivery core store contracts must stay explicit and narrow:\n{}",
        violations.join("\n")
    );
}

#[test]
fn provider_outcome_callers_cannot_bypass_durable_finalization_retry() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative_file in [
        "src/api/handlers/message/dispatch/mod.rs",
        "src/dispatch/runtime.rs",
    ] {
        let source = fs::read_to_string(manifest_dir.join(relative_file))
            .expect("provider outcome caller source should be readable");
        assert!(
            source.contains(".finalize_provider_dispatch_outcome_durably("),
            "{relative_file} must use the durable provider outcome finalizer"
        );
        assert!(
            !source.contains(".finalize_provider_dispatch_outcome("),
            "{relative_file} must not bypass the durable provider outcome finalizer"
        );
    }
}

#[test]
fn external_database_test_cleanup_removes_anonymous_data_volumes() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let backend_tests =
        fs::read_to_string(manifest_dir.join("src/storage/storage/tests/backend_init.rs"))
            .expect("external database test harness should be readable");
    let parity_script = fs::read_to_string(manifest_dir.join("scripts/storage_crossdb_parity.sh"))
        .expect("cross-database parity script should be readable");

    assert!(
        backend_tests.contains(".args([\"rm\", \"-f\", \"-v\", self.name.as_str()])"),
        "external database test containers must remove anonymous data volumes"
    );
    assert!(
        parity_script.contains("docker rm -f -v \"$1\""),
        "cross-database parity cleanup must remove anonymous data volumes"
    );
}

fn is_test_source(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "tests")
        || path
            .file_name()
            .is_some_and(|file_name| file_name == "tests.rs")
}

fn scan_rust_files(dir: &Path, visit: &mut impl FnMut(&Path, &str)) {
    if dir.is_file() {
        if dir.extension().is_some_and(|extension| extension == "rs") {
            let contents = fs::read_to_string(dir).expect("rust source should be utf-8");
            visit(dir, &contents);
        }
        return;
    }

    for entry in fs::read_dir(dir).expect("delivery_core directory should be readable") {
        let entry = entry.expect("delivery_core entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            scan_rust_files(&path, visit);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let contents = fs::read_to_string(&path).expect("rust source should be utf-8");
            visit(&path, &contents);
        }
    }
}

fn scan_rust_files_and_text(path: &Path, visit: &mut impl FnMut(&Path, &str)) {
    if path.is_file() {
        if should_scan_text_file(path) {
            let contents = fs::read_to_string(path).expect("text source should be utf-8");
            visit(path, &contents);
        }
        return;
    }

    for entry in fs::read_dir(path).expect("scan root should be readable") {
        let entry = entry.expect("scan entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if matches!(file_name, "target" | ".git") {
                continue;
            }
            scan_rust_files_and_text(&path, visit);
        } else if should_scan_text_file(&path) {
            let contents = fs::read_to_string(&path).expect("text source should be utf-8");
            visit(&path, &contents);
        }
    }
}

fn should_scan_text_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| matches!(extension, "rs" | "sh" | "md"))
}
