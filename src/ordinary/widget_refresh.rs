//! Recoverable ordinary-message Widget invalidation, never a second message
//! identity, body, recipient ledger, Pull source or delivery receipt owner.
use crate::{
    api::handlers::message::widget_push_job,
    dispatch::{DispatchChannels, DurableProviderJob},
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

/// One serial projector is shared by immediate product submission and the
/// existing bounded recovery worker. A page contains metadata only; the
/// ordinary canonical body remains exclusively in its ledger.
pub(crate) async fn project_pending(
    storage: &Storage,
    dispatch: &DispatchChannels,
    max_messages: usize,
) -> Result<usize> {
    let ordinary = storage.ordinary_handle().ok_or(KernelError::Unavailable)?;
    ordinary.health.ensure()?;
    let _projecting = ordinary.widget_projection_gate.lock().await;
    // HTTP cancellation must not silently retry an enqueue whose COMMIT was
    // interrupted. Restart recovery can inspect the durable order safely.
    let mut outcome = ProjectionOutcomeGuard {
        ordinary: ordinary.clone(),
        established: false,
    };
    let mut completed = 0;
    for _ in 0..max_messages.min(8) {
        ordinary.health.ensure()?;
        let Some(refresh) = ordinary.next_widget_refresh().await.inspect_err(|_| {
            ordinary.fail("ordinary Widget marker read did not establish a durable outcome");
        })?
        else {
            break;
        };
        let result = project_one(storage, dispatch, &ordinary, &refresh).await;
        match result {
            Ok(true) => completed += 1,
            // Known durable capacity rollback leaves this marker for the
            // existing recovery worker. It must not reject accepted ordinary
            // content or trigger a restart just because invalidation is queued.
            Ok(false) => break,
            Err(error) => {
                ordinary.fail("ordinary Widget projection did not establish a durable outcome");
                return Err(error);
            }
        }
    }
    outcome.established = true;
    Ok(completed)
}

async fn project_one(
    storage: &Storage,
    dispatch: &DispatchChannels,
    ordinary: &super::OrdinaryStore,
    refresh: &WidgetRefresh,
) -> Result<bool> {
    if refresh.coalesce_order <= 0 {
        return Err(KernelError::Invalid(
            "Widget invalidation has no durable acceptance order".into(),
        ));
    }
    let mut cursor: Option<WidgetRefreshCursor> = None;
    while !super::expiry::is_expired(refresh.expires_at, chrono::Utc::now().timestamp_millis()) {
        let page = ordinary
            .widget_refresh_targets(
                refresh.channel_id,
                cursor.as_ref(),
                WIDGET_REFRESH_PAGE_SIZE,
            )
            .await?;
        if page.is_empty() {
            break;
        }
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
            if cursor.as_ref().is_some_and(|previous| {
                (&next.platform, &next.token) <= (&previous.platform, &previous.token)
            }) {
                return Err(KernelError::Invalid(
                    "Widget selector failed to advance its keyset".into(),
                ));
            }
            if super::expiry::is_expired(refresh.expires_at, chrono::Utc::now().timestamp_millis())
            {
                break;
            }
            let job = widget_push_job(
                refresh.channel_id,
                "message",
                Arc::from(refresh.delivery_id.as_str()),
                Arc::from(refresh.delivery_id.as_str()),
                target.platform,
                target.device_key,
                target.token,
            );
            let mut record = DurableProviderJob::from_widget(&job)
                .to_record("pending", refresh.accepted_at, refresh.expires_at)
                .map_err(|error| KernelError::Invalid(error.to_string()))?;
            record.coalesce_order = refresh.coalesce_order;
            match storage.enqueue_ordinary_widget_refresh(&record).await {
                Ok(true) => {
                    // This is only a bounded hint. The existing APNS_WIDGETS
                    // consumer recovers the same committed derived job.
                    let _ = dispatch.try_send_widget_push(job);
                }
                Ok(false) => {}
                Err(StoreError::ProviderDispatchCapacityExceeded { .. }) => return Ok(false),
                Err(error) => {
                    return Err(KernelError::Invalid(format!(
                        "Widget durable projection: {error}"
                    )));
                }
            }
            cursor = Some(next);
        }
    }
    if !ordinary
        .complete_widget_refresh(&refresh.delivery_id, refresh.coalesce_order)
        .await?
    {
        return Err(KernelError::Invalid(
            "Widget projection marker changed before completion".into(),
        ));
    }
    Ok(true)
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

    // A normal Storage test, with a real new SQLite core/sidecar and shared
    // mutation gate. No fixture ledger or second application server is used.
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
            db_url: Some(url),
            managed_upgrade: false,
            ..StorageInitConfig::default()
        })
        .await
        .unwrap();
        let mut config = Config::default();
        config.private.enabled = false;
        let ordinary = storage.initialize_ordinary(config, health).await.unwrap();
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
        // delivery targets; the two Widget kinds share one bounded target.
        let targets = ordinary
            .widget_refresh_targets(channel, None, 1)
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert!(
            ordinary
                .widget_refresh_targets(
                    channel,
                    Some(&WidgetRefreshCursor {
                        platform: "ios".into(),
                        token: widget_token.clone(),
                    }),
                    1,
                )
                .await
                .unwrap()
                .is_empty()
        );
        let target = targets.into_iter().next().unwrap();
        let job = widget_push_job(
            channel,
            "message",
            Arc::from(refresh.delivery_id.as_str()),
            Arc::from(refresh.delivery_id.as_str()),
            target.platform,
            target.device_key,
            target.token,
        );
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
        let (dispatch, _receivers) = DispatchChannels::new();
        assert_eq!(project_pending(&storage, &dispatch, 1).await.unwrap(), 1);
        assert!(ordinary.next_widget_refresh().await.unwrap().is_none());
        assert!(
            storage
                .claim_provider_dispatch_job(
                    "APNS_WIDGETS",
                    None,
                    "after-recovery",
                    now(),
                    now() + 5000
                )
                .await
                .unwrap()
                .is_none()
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
