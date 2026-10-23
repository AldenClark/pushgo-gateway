//! Recoverable ordinary-message Widget invalidation, never a second message
//! identity, body, recipient ledger, Pull source or delivery receipt owner.
use crate::{
    api::handlers::message::widget_push_job,
    dispatch::{DispatchChannels, DurableProviderJob, WidgetPushJob},
    storage::{Platform, Storage, StoreError},
};
use std::sync::Arc;

use super::{KernelError, store::Result};

pub(crate) const WIDGET_REFRESH_PAGE_SIZE: usize = 128;

#[derive(Clone, Debug)]
pub(crate) struct WidgetRefresh {
    pub delivery_id: String,
    pub channel_id: [u8; 16],
    pub coalesce_order: i64,
    pub accepted_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct WidgetRefreshCursor {
    pub platform: String,
    pub token: String,
}

#[derive(Clone, Debug)]
pub(crate) struct WidgetRefreshTarget {
    pub device_key: String,
    pub platform: Platform,
    pub token: String,
}

fn ordinary_widget_job(refresh: &WidgetRefresh, target: WidgetRefreshTarget) -> WidgetPushJob {
    let mut job = widget_push_job(
        refresh.channel_id,
        "message",
        Arc::from(refresh.delivery_id.as_str()),
        Arc::from(refresh.delivery_id.as_str()),
        target.platform,
        target.device_key,
        target.token,
    );
    job.ordinary_target_scoped = true;
    job
}

/// One metadata-only continuation, shared by clones of the existing serial
/// projector. Restart intentionally resumes from the ledger and durable job
/// orders instead of persisting another per-target progress table.
#[derive(Default)]
pub(crate) struct WidgetProjectionState {
    continuation: Option<WidgetProjectionPass>,
    after_order: i64,
    cycle_ceiling: Option<i64>,
    #[cfg(test)]
    test_capacity_full: bool,
}

struct WidgetProjectionPass {
    refresh: WidgetRefresh,
    cursor: Option<WidgetRefreshCursor>,
    had_full: bool,
    #[cfg(test)]
    test_capacity_full: bool,
}

impl WidgetProjectionPass {
    fn new(refresh: WidgetRefresh) -> Self {
        Self {
            refresh,
            cursor: None,
            had_full: false,
            #[cfg(test)]
            test_capacity_full: false,
        }
    }
}

struct ProjectionOutcomeGuard {
    ordinary: super::OrdinaryStore,
    established: bool,
}

impl Drop for ProjectionOutcomeGuard {
    fn drop(&mut self) {
        if !self.established {
            self.ordinary
                .fail("ordinary Widget projection interrupted before its durable outcome");
        }
    }
}

/// The existing recovery worker projects at most eight pages per turn, each
/// with at most 128 metadata targets. The return value remains completed
/// snapshots, not page count. An unfinished page sequence keeps one cursor;
/// the ordinary canonical body remains exclusively in its ledger.
pub(crate) async fn project_pending(
    storage: &Storage,
    dispatch: &DispatchChannels,
    max_pages: usize,
) -> Result<usize> {
    let ordinary = storage.ordinary_handle().ok_or(KernelError::Unavailable)?;
    ordinary.health.ensure()?;
    let mut projecting = ordinary.widget_projection_gate.lock().await;
    // Cancellation must not silently retry an enqueue whose COMMIT was
    // interrupted. Restart inspects the durable order with a fresh cursor.
    let mut outcome = ProjectionOutcomeGuard {
        ordinary: ordinary.clone(),
        established: false,
    };
    let mut completed = 0;
    let mut used_pages = 0;
    let mut needs_more = false;
    let mut capacity_blocked = false;
    let budget = max_pages.min(8);
    for _ in 0..budget {
        ordinary.health.ensure()?;
        if projecting.continuation.is_none() {
            if projecting.cycle_ceiling.is_none() {
                projecting.cycle_ceiling = ordinary.widget_refresh_ceiling().await?;
                projecting.after_order = 0;
            }
            let Some(ceiling) = projecting.cycle_ceiling else {
                break;
            };
            if ceiling <= 0 {
                return Err(KernelError::Invalid(
                    "Widget invalidation has no durable acceptance order".into(),
                ));
            }
            let Some(refresh) = ordinary
                .widget_refresh_after(projecting.after_order, ceiling)
                .await?
            else {
                // New acceptance orders cannot keep an older capacity-blocked
                // marker behind an endlessly extending sweep. Wrap next turn.
                projecting.after_order = 0;
                projecting.cycle_ceiling = None;
                needs_more = true;
                break;
            };
            projecting.continuation = Some(WidgetProjectionPass::new(refresh));
        }
        let mut pass = projecting
            .continuation
            .take()
            .expect("selected Widget pass");
        #[cfg(test)]
        {
            pass.test_capacity_full = projecting.test_capacity_full;
        }
        used_pages += 1;
        let (finished, full) = project_one_page(storage, dispatch, &ordinary, &mut pass)
            .await
            .inspect_err(|_| {
                ordinary.fail("ordinary Widget projection did not establish a durable outcome");
            })?;
        capacity_blocked |= full;
        if finished {
            projecting.after_order = pass.refresh.coalesce_order;
            if !pass.had_full {
                completed += 1;
            }
        } else {
            projecting.continuation = Some(pass);
        }
    }
    if !capacity_blocked && (used_pages == budget && budget != 0 || needs_more) {
        // Keep the same worker/Notify owner. A known full outbox waits for the
        // existing timer or external wake instead of spinning through retries.
        ordinary.widget_wake.notify_one();
    }
    outcome.established = true;
    Ok(completed)
}

async fn project_one_page(
    storage: &Storage,
    dispatch: &DispatchChannels,
    ordinary: &super::OrdinaryStore,
    pass: &mut WidgetProjectionPass,
) -> Result<(bool, bool)> {
    let refresh = &pass.refresh;
    if refresh.coalesce_order <= 0 {
        return Err(KernelError::Invalid(
            "Widget invalidation has no durable acceptance order".into(),
        ));
    }
    let mut capacity_blocked = false;
    let mut finished = true;
    if !super::expiry::is_expired(refresh.expires_at, chrono::Utc::now().timestamp_millis()) {
        let page = ordinary
            .widget_refresh_targets(
                refresh.channel_id,
                pass.cursor.as_ref(),
                WIDGET_REFRESH_PAGE_SIZE,
            )
            .await?;
        finished = page.len() < WIDGET_REFRESH_PAGE_SIZE;
        if page.len() > WIDGET_REFRESH_PAGE_SIZE {
            return Err(KernelError::Invalid(
                "Widget selector exceeded its bounded page".into(),
            ));
        }
        for target in page {
            ordinary.health.ensure()?;
            let next = WidgetRefreshCursor {
                platform: target.platform.name().to_owned(),
                token: target.token.clone(),
            };
            if pass.cursor.as_ref().is_some_and(|previous| {
                (&next.platform, &next.token) <= (&previous.platform, &previous.token)
            }) {
                return Err(KernelError::Invalid(
                    "Widget selector failed to advance its keyset".into(),
                ));
            }
            if super::expiry::is_expired(refresh.expires_at, chrono::Utc::now().timestamp_millis())
            {
                finished = true;
                break;
            }
            let job = ordinary_widget_job(refresh, target);
            let mut record = DurableProviderJob::from_widget(&job)
                .to_record("pending", refresh.accepted_at, refresh.expires_at)
                .map_err(|error| KernelError::Invalid(error.to_string()))?;
            record.coalesce_order = refresh.coalesce_order;
            let enqueue: std::result::Result<bool, StoreError> = async {
                // Only this test build can synthesize a known capacity
                // rollback. Existing target jobs may still coalesce when the
                // new-job capacity is exhausted, matching normal Storage.
                #[cfg(test)]
                if pass.test_capacity_full
                    && ordinary
                        .widget_refresh_job_order(&record.job_id)
                        .await?
                        .is_none()
                {
                    return Err(StoreError::ProviderDispatchCapacityExceeded {
                        pending: 1_000_000,
                        capacity: 1_000_000,
                    });
                }
                storage.enqueue_ordinary_widget_refresh(&record).await
            }
            .await;
            match enqueue {
                Ok(true) => {
                    // This is only a bounded hint. The existing APNS_WIDGETS
                    // consumer recovers the same committed derived job.
                    let _ = dispatch.try_send_widget_push(job);
                }
                Ok(false) => {}
                Err(StoreError::ProviderDispatchCapacityExceeded { .. }) => {
                    pass.had_full = true;
                    capacity_blocked = true;
                }
                Err(error) => {
                    return Err(KernelError::Invalid(format!(
                        "Widget durable projection: {error}"
                    )));
                }
            }
            // A known rollback advances this scan, never the durable delivery
            // result. Retaining the marker replays failed targets next sweep,
            // while later existing jobs and channels can still make progress.
            pass.cursor = Some(next);
        }
    }
    // A newer accepted refresh may have atomically replaced this channel's
    // marker while its bounded pages were projected. Zero rows means the old
    // snapshot was superseded, not that the newer obligation may be removed.
    // Native COMMIT errors still propagate to the shared fail-stop guard.
    let expired =
        super::expiry::is_expired(refresh.expires_at, chrono::Utc::now().timestamp_millis());
    if finished && (!pass.had_full || expired) {
        let _ = ordinary
            .complete_widget_refresh(&refresh.delivery_id, refresh.coalesce_order)
            .await?;
        pass.had_full = false;
    }
    Ok((finished, capacity_blocked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordinary::{
            AcceptRequest, Config,
            owner::ProductOwner,
            store::{Health, now},
        },
        storage::{
            DeviceRouteRecordRow, PrivateDeviceId, ProviderDispatchSettlement, StorageInitConfig,
            WidgetPushSubscriptionRecord,
        },
    };

    #[tokio::test]
    async fn product_widget_prior_candidate_without_channel_constraint_refuses_startup() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("old-marker.db").display()
        );
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url.clone()),
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut connection = sqlx::SqliteConnection::connect(&url).await.unwrap();
        sqlx::query("CREATE TABLE ordinary_widget_refresh(delivery_id TEXT PRIMARY KEY,channel_id BLOB NOT NULL,coalesce_order INTEGER NOT NULL UNIQUE,accepted_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)")
            .execute(&mut connection).await.unwrap();
        connection.close().await.unwrap();
        let result = storage.initialize_ordinary(Config::default(), health).await;
        assert!(matches!(result, Err(KernelError::Invalid(ref reason))
            if reason.contains("channel coalescing constraint missing")));
        assert!(
            storage.ordinary_handle().is_none(),
            "no initialized ordinary ingress authority"
        );
        let mut connection = sqlx::SqliteConnection::connect(&url).await.unwrap();
        let markers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_widget_refresh")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            markers, 0,
            "startup neither accepts nor migrates prior-candidate markers"
        );
        connection.close().await.unwrap();
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
    }
    use sqlx::Connection;

    async fn open_product_widget(
        url: &str,
    ) -> (ProductOwner, Storage, super::super::OrdinaryStore) {
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url.to_owned()),
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut config = Config::default();
        config.private.enabled = false;
        let ordinary = storage.initialize_ordinary(config, health).await.unwrap();
        (owner, storage, ordinary)
    }

    async fn widget_channel(storage: &Storage, device_key: &str, count: usize) -> [u8; 16] {
        let fixture_auth = crate::util::generate_hex_id_128();
        let channel = storage
            .upsert_private_channel(None, Some("bounded Widget projection"), &fixture_auth)
            .await
            .unwrap()
            .channel_id;
        storage
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: device_key.into(),
                platform: "ios".into(),
                channel_type: "private".into(),
                provider_token: None,
                updated_at: now(),
            })
            .await
            .unwrap();
        storage
            .private_subscribe_channel(channel, PrivateDeviceId::derive(device_key).into())
            .await
            .unwrap();
        for index in 0..count {
            let token = format!("{index:064x}");
            let widget = WidgetPushSubscriptionRecord {
                device_key: device_key.into(),
                platform: "ios".into(),
                token: token.clone(),
                widget_kind: "io.ethan.pushgo.widgets.unread".into(),
                family: "systemSmall".into(),
                schema_version: 1,
                created_at: now(),
                updated_at: now(),
            };
            storage
                .upsert_widget_push_subscriptions(
                    device_key,
                    Platform::IOS,
                    &token,
                    &[widget],
                    1,
                    now(),
                )
                .await
                .unwrap();
        }
        channel
    }

    async fn accept_widget(ordinary: &super::super::OrdinaryStore, channel: [u8; 16], op: &str) {
        ordinary
            .accept(AcceptRequest {
                channel_id: crate::value::ChannelId::from(channel).to_string(),
                authorized_channel: Some(channel),
                op_id: Some(op.into()),
                title: "bounded Widget projection".into(),
                ..AcceptRequest::default()
            })
            .await
            .unwrap();
    }

    // A normal Storage test, with a real new SQLite core/sidecar and shared
    // mutation gate. No fixture ledger or second application server is used.
    #[tokio::test]
    async fn product_widget_projection_limits_a_turn_and_continues_257_targets() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("widget-bounded-product.db").display()
        );
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url),
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut config = Config::default();
        config.private.enabled = false;
        let ordinary = storage.initialize_ordinary(config, health).await.unwrap();
        let channel = widget_channel(&storage, "widget-bounded-owner", 257).await;
        ordinary
            .accept(AcceptRequest {
                channel_id: crate::value::ChannelId::from(channel).to_string(),
                authorized_channel: Some(channel),
                op_id: Some("widget-bounded-257".into()),
                title: "bounded Widget projection".into(),
                ..AcceptRequest::default()
            })
            .await
            .unwrap();
        let (dispatch, _receivers) = DispatchChannels::new();
        for expected in [128, 256, 257] {
            project_pending(&storage, &dispatch, 1).await.unwrap();
            assert_eq!(
                storage
                    .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                    .await
                    .unwrap(),
                expected,
                "one turn must project at most one 128-target page and retain progress"
            );
        }
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        ordinary.health.ensure().unwrap();
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn product_widget_projection_full_pass_keeps_responsibility_and_rotates_channels() {
        use futures_util::FutureExt;
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("widget-full.db").display()
        );
        let (owner, storage, ordinary) = open_product_widget(&url).await;
        let blocked = widget_channel(&storage, "widget-full-owner", 257).await;
        accept_widget(&ordinary, blocked, "widget-full-first").await;
        let first = ordinary.next_widget_refresh().await.unwrap().unwrap();
        let healthy = widget_channel(&storage, "widget-coalesce-owner", 1).await;
        accept_widget(&ordinary, healthy, "widget-coalesce-seed").await;
        let seed = ordinary
            .widget_refresh_after(first.coalesce_order, i64::MAX)
            .await
            .unwrap()
            .unwrap();
        let target = ordinary
            .widget_refresh_targets(healthy, None, 1)
            .await
            .unwrap()
            .remove(0);
        let job = ordinary_widget_job(&seed, target);
        let mut record = DurableProviderJob::from_widget(&job)
            .to_record("pending", seed.accepted_at, seed.expires_at)
            .unwrap();
        record.coalesce_order = seed.coalesce_order;
        storage
            .enqueue_ordinary_widget_refresh(&record)
            .await
            .unwrap();
        ordinary
            .complete_widget_refresh(&seed.delivery_id, seed.coalesce_order)
            .await
            .unwrap();
        accept_widget(&ordinary, healthy, "widget-coalesce-latest").await;
        ordinary
            .widget_projection_gate
            .lock()
            .await
            .test_capacity_full = true;
        let (dispatch, _receivers) = DispatchChannels::new();

        // This is a known-capacity-rollback injection in cfg(test), not a
        // claim that this test creates a million-row native full outbox.
        for last_token in [127, 255] {
            let _ = ordinary.widget_wake.notified().now_or_never();
            assert_eq!(project_pending(&storage, &dispatch, 1).await.unwrap(), 0);
            assert!(
                ordinary.widget_wake.notified().now_or_never().is_none(),
                "full pages must not spin by notifying themselves"
            );
            let state = ordinary.widget_projection_gate.lock().await;
            let pass = state.continuation.as_ref().unwrap();
            assert_eq!(
                pass.cursor.as_ref().unwrap().token,
                format!("{last_token:064x}")
            );
            assert!(pass.had_full);
        }
        assert_eq!(project_pending(&storage, &dispatch, 1).await.unwrap(), 0);
        assert!(
            ordinary
                .widget_projection_gate
                .lock()
                .await
                .continuation
                .is_none()
        );
        assert_eq!(
            ordinary
                .next_widget_refresh()
                .await
                .unwrap()
                .unwrap()
                .delivery_id,
            first.delivery_id
        );
        assert_eq!(
            storage
                .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                .await
                .unwrap(),
            1
        );

        // Full new-job capacity must not prevent a following channel from
        // updating its already existing, target-scoped durable job.
        assert_eq!(project_pending(&storage, &dispatch, 1).await.unwrap(), 1);
        assert!(
            ordinary
                .widget_refresh_job_order(&record.job_id)
                .await
                .unwrap()
                .unwrap()
                > seed.coalesce_order
        );
        let later = widget_channel(&storage, "widget-later-owner", 1).await;
        accept_widget(&ordinary, later, "widget-newer-than-cycle").await;
        assert_eq!(
            project_pending(&storage, &dispatch, 1).await.unwrap(),
            0,
            "the captured cycle must wrap before a newer order is selected"
        );
        ordinary
            .widget_projection_gate
            .lock()
            .await
            .test_capacity_full = false;
        for expected in [129, 257, 258, 259] {
            project_pending(&storage, &dispatch, 1).await.unwrap();
            assert_eq!(
                storage
                    .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                    .await
                    .unwrap(),
                expected
            );
        }
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        ordinary.health.ensure().unwrap();
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn product_widget_projection_caps_pages_across_ten_channels() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("widget-channels.db").display()
        );
        let (owner, storage, ordinary) = open_product_widget(&url).await;
        for index in 0..10 {
            let channel = widget_channel(&storage, &format!("widget-channel-{index}"), 1).await;
            accept_widget(&ordinary, channel, &format!("widget-channel-op-{index}")).await;
        }
        let (dispatch, _receivers) = DispatchChannels::new();
        assert_eq!(
            project_pending(&storage, &dispatch, usize::MAX)
                .await
                .unwrap(),
            8
        );
        assert_eq!(
            storage
                .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                .await
                .unwrap(),
            8
        );
        assert_eq!(
            project_pending(&storage, &dispatch, usize::MAX)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            storage
                .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                .await
                .unwrap(),
            10
        );
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn product_widget_projection_restart_replays_pages_without_reopening_terminal_jobs() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("widget-pages-restart.db").display()
        );
        let (owner, storage, ordinary) = open_product_widget(&url).await;
        let channel = widget_channel(&storage, "widget-pages-restart-owner", 129).await;
        accept_widget(&ordinary, channel, "widget-pages-restart").await;
        let (dispatch, _receivers) = DispatchChannels::new();
        project_pending(&storage, &dispatch, 1).await.unwrap();
        assert_eq!(
            storage
                .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                .await
                .unwrap(),
            128
        );
        let lease = storage
            .claim_provider_dispatch_job(
                "APNS_WIDGETS",
                None,
                "before-pages-restart",
                now(),
                now() + 5000,
            )
            .await
            .unwrap()
            .unwrap();
        storage
            .settle_provider_dispatch_job(
                &lease,
                ProviderDispatchSettlement::Accepted,
                now(),
                200,
                None,
                now(),
            )
            .await
            .unwrap();
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
        let (owner, storage, ordinary) = open_product_widget(&url).await;
        assert!(
            ordinary
                .widget_projection_gate
                .lock()
                .await
                .continuation
                .is_none()
        );
        let (dispatch, _receivers) = DispatchChannels::new();
        // The first page is read again after restart, but its any-state durable
        // orders skip enqueue and leave the accepted target terminal.
        project_pending(&storage, &dispatch, 1).await.unwrap();
        assert_eq!(
            storage
                .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                .await
                .unwrap(),
            127
        );
        project_pending(&storage, &dispatch, 1).await.unwrap();
        assert_eq!(
            storage
                .count_pending_provider_dispatch_jobs("APNS_WIDGETS")
                .await
                .unwrap(),
            128
        );
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn product_widget_projection_recovers_a_terminal_enqueue_without_reviving_it() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("widget-product.db").display()
        );
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url.clone()),
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut config = Config::default();
        config.private.enabled = false;
        let ordinary = storage
            .initialize_ordinary(config.clone(), health)
            .await
            .unwrap();
        let fixture_auth = crate::util::generate_hex_id_128();
        let channel = storage
            .upsert_private_channel(None, Some("widget recovery"), &fixture_auth)
            .await
            .unwrap()
            .channel_id;
        let device_key = "widget-recovery-private-disabled";
        storage
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: device_key.into(),
                platform: "ios".into(),
                channel_type: "private".into(),
                provider_token: None,
                updated_at: now(),
            })
            .await
            .unwrap();
        storage
            .private_subscribe_channel(channel, PrivateDeviceId::derive(device_key).into())
            .await
            .unwrap();
        let widget_token = "ab".repeat(32);
        let widgets = [
            "io.ethan.pushgo.widgets.unread",
            "io.ethan.pushgo.widgets.watch-summary",
        ]
        .map(|kind| WidgetPushSubscriptionRecord {
            device_key: device_key.into(),
            platform: "ios".into(),
            token: widget_token.clone(),
            widget_kind: kind.into(),
            family: "systemSmall".into(),
            schema_version: 1,
            created_at: now(),
            updated_at: now(),
        });
        storage
            .upsert_widget_push_subscriptions(
                device_key,
                Platform::IOS,
                &widget_token,
                &widgets,
                1,
                now(),
            )
            .await
            .unwrap();
        let second_widget_token = "cd".repeat(32);
        storage
            .upsert_widget_push_subscriptions(
                device_key,
                Platform::IOS,
                &second_widget_token,
                &widgets,
                1,
                now(),
            )
            .await
            .unwrap();
        let request = AcceptRequest {
            channel_id: crate::value::ChannelId::from(channel).to_string(),
            authorized_channel: Some(channel),
            op_id: Some("widget-recovery-ordinary".into()),
            title: "ordinary Widget recovery".into(),
            ..AcceptRequest::default()
        };
        let accepted = ordinary.accept(request.clone()).await.unwrap();
        let refresh = ordinary.next_widget_refresh().await.unwrap().unwrap();
        assert_eq!(refresh.delivery_id, accepted.delivery_id);
        // Widget-only invalidation remains valid even with zero active ordinary
        // delivery targets. Two kinds share one target per platform/token,
        // while two tokens on the same device must remain distinct targets.
        let targets = ordinary
            .widget_refresh_targets(channel, None, 1)
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        let second_page = ordinary
            .widget_refresh_targets(
                channel,
                Some(&WidgetRefreshCursor {
                    platform: "ios".into(),
                    token: widget_token.clone(),
                }),
                1,
            )
            .await
            .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].token, second_widget_token);
        let target = targets.into_iter().next().unwrap();
        let job = ordinary_widget_job(&refresh, target);
        let mut record = DurableProviderJob::from_widget(&job)
            .to_record("pending", refresh.accepted_at, refresh.expires_at)
            .unwrap();
        record.coalesce_order = refresh.coalesce_order;
        assert!(record.op_id.is_none() && record.dedupe_key.is_none());
        assert!(
            storage
                .enqueue_ordinary_widget_refresh(&record)
                .await
                .unwrap()
        );
        let lease = storage
            .claim_provider_dispatch_job(
                "APNS_WIDGETS",
                None,
                "widget-recovery",
                now(),
                now() + 5000,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(
            storage
                .settle_provider_dispatch_job(
                    &lease,
                    ProviderDispatchSettlement::Accepted,
                    now(),
                    200,
                    None,
                    now(),
                )
                .await
                .unwrap()
        );
        // Model a crash after the derived terminal COMMIT but before marker
        // completion: recovery must observe any-state order and skip enqueue.
        assert!(
            !storage
                .enqueue_ordinary_widget_refresh(&record)
                .await
                .unwrap()
        );
        // Pending work, including a blocked derived queue, must coalesce as
        // metadata instead of allocating one obligation per request. This test
        // exercises zero ordinary target usage without filling a million rows.
        let mut latest_request = request.clone();
        let mut latest_accepted = accepted.clone();
        for index in 0..32 {
            latest_request.op_id = Some(format!("widget-coalesced-{index}"));
            latest_accepted = ordinary.accept(latest_request.clone()).await.unwrap();
        }
        let mut inspect = sqlx::SqliteConnection::connect(&url).await.unwrap();
        let marker_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_widget_refresh WHERE channel_id=?")
                .bind(channel.as_slice())
                .fetch_one(&mut inspect)
                .await
                .unwrap();
        assert_eq!(marker_count, 1);
        let target_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ordinary_targets")
            .fetch_one(&mut inspect)
            .await
            .unwrap();
        assert_eq!(target_count, 0, "these are Widget-only ordinary accepts");
        inspect.close().await.unwrap();
        let latest = ordinary.next_widget_refresh().await.unwrap().unwrap();
        assert_eq!(latest.delivery_id, latest_accepted.delivery_id);
        assert!(latest.coalesce_order > refresh.coalesce_order);
        assert_eq!(
            ordinary.accept(latest_request).await.unwrap().delivery_id,
            latest_accepted.delivery_id
        );
        assert_eq!(
            ordinary
                .next_widget_refresh()
                .await
                .unwrap()
                .unwrap()
                .coalesce_order,
            latest.coalesce_order,
            "identity replay does not renew the derived obligation"
        );
        let (dispatch, _receivers) = DispatchChannels::new();
        // The first token was already projected before new acceptance replaced
        // the marker. Finishing its old snapshot is a normal supersession: it
        // cannot delete the newer marker or poison process health.
        assert!(
            project_one_page(
                &storage,
                &dispatch,
                &ordinary,
                &mut WidgetProjectionPass::new(refresh.clone())
            )
            .await
            .unwrap()
            .0
        );
        ordinary.health.ensure().unwrap();
        assert_eq!(
            ordinary
                .next_widget_refresh()
                .await
                .unwrap()
                .unwrap()
                .delivery_id,
            latest.delivery_id
        );
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
        let health = Arc::new(Health::default());
        let owner = ProductOwner::acquire(Some(&url), health.clone())
            .await
            .unwrap();
        let storage = Storage::new_with_config(StorageInitConfig {
            db_url: Some(url),
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let ordinary = storage.initialize_ordinary(config, health).await.unwrap();
        let (dispatch, _receivers) = DispatchChannels::new();
        assert_eq!(project_pending(&storage, &dispatch, 1).await.unwrap(), 1);
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        let remaining = storage
            .claim_provider_dispatch_job(
                "APNS_WIDGETS",
                None,
                "after-recovery",
                now(),
                now() + 5000,
            )
            .await
            .unwrap()
            .unwrap();
        // A new accepted refresh legitimately updates the same stable target
        // job. It must use the latest order and preserve both token jobs.
        let restored: DurableProviderJob =
            serde_json::from_slice(&remaining.record.payload_blob).unwrap();
        let restored = restored.into_widget().unwrap();
        assert!(restored.ordinary_target_scoped);
        let first_restored_token = restored.device_token.to_string();
        assert_eq!(remaining.record.delivery_id, latest_accepted.delivery_id);
        assert_eq!(remaining.record.coalesce_order, latest.coalesce_order);
        assert!(
            storage
                .settle_provider_dispatch_job(
                    &remaining,
                    ProviderDispatchSettlement::Accepted,
                    now(),
                    200,
                    None,
                    now()
                )
                .await
                .unwrap()
        );
        let second_remaining = storage
            .claim_provider_dispatch_job(
                "APNS_WIDGETS",
                None,
                "second-token-after-recovery",
                now(),
                now() + 5000,
            )
            .await
            .unwrap()
            .unwrap();
        assert_ne!(second_remaining.record.job_id, remaining.record.job_id);
        assert_eq!(
            second_remaining.record.delivery_id,
            latest_accepted.delivery_id
        );
        let second_restored: DurableProviderJob =
            serde_json::from_slice(&second_remaining.record.payload_blob).unwrap();
        let second_restored = second_restored.into_widget().unwrap();
        let mut recovered_tokens = vec![
            first_restored_token,
            second_restored.device_token.to_string(),
        ];
        recovered_tokens.sort();
        assert_eq!(
            recovered_tokens,
            vec![widget_token.clone(), second_widget_token.clone()]
        );
        assert!(
            storage
                .settle_provider_dispatch_job(
                    &second_remaining,
                    ProviderDispatchSettlement::Accepted,
                    now(),
                    200,
                    None,
                    now()
                )
                .await
                .unwrap()
        );
        assert_eq!(
            storage
                .delete_widget_push_token(Platform::IOS, &widget_token)
                .await
                .unwrap(),
            2
        );
        let remaining_targets = ordinary
            .widget_refresh_targets(channel, None, 128)
            .await
            .unwrap();
        assert_eq!(remaining_targets.len(), 1);
        assert_eq!(
            remaining_targets[0].token, second_widget_token,
            "one invalid token cleanup must preserve another token on the same device"
        );
        assert_eq!(
            ordinary.accept(request).await.unwrap().delivery_id,
            accepted.delivery_id
        );
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        storage.close_ordinary_storage().await.unwrap();
        owner.shutdown().await.unwrap();
    }
}
