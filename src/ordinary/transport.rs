//! Ordinary delivery uses the product's existing Provider clients. This module
//! owns neither credentials, HTTP connections, retries, nor another semaphore.
use std::sync::Arc;

use hashbrown::HashMap;
use serde_json::Value;

use super::{runtime::ProviderTransport, types::Platform};
use crate::{
    delivery_core::{
        execution::provider::{
            ApnsPayloadPreparation, FcmPayloadPreparation, PreparedProviderPayload,
            ProviderPayloadPreparationError, WnsPayloadPreparation, prepare_apns_payload,
            prepare_fcm_payload, prepare_wns_payload,
        },
        payload::{
            ProviderDeliveryPath, ProviderPullTarget, notification::NotificationTextResolver,
            quantize_watch_payload, thread::AppleThreadIdResolver,
        },
    },
    providers::{
        ApnsClient, FcmClient, ProviderFailureKind, WnsClient,
        apns::{ApnsExpirationEpochSeconds, ApnsPayload, WATCH_ALERT_DEADLINE_KEY},
        fcm::FcmPayload,
        wns::{WnsEnvelopeKind, WnsPayload},
    },
    storage::Platform as ProductPlatform,
    value::EntityKind,
};

pub use crate::providers::{BoxFuture, DispatchResult};

pub struct ProductProviders {
    apns: Arc<dyn ApnsClient>,
    fcm: Arc<dyn FcmClient>,
    wns: Arc<dyn WnsClient>,
}

impl ProductProviders {
    pub fn new(
        apns: Arc<dyn ApnsClient>,
        fcm: Arc<dyn FcmClient>,
        wns: Arc<dyn WnsClient>,
    ) -> Self {
        Self { apns, fcm, wns }
    }

    #[allow(clippy::too_many_arguments)]
    async fn request(
        &self,
        provider: &str,
        platform: Platform,
        token: &str,
        payload: Value,
        delivery: &str,
        device: &str,
        accepted: i64,
        expiry: i64,
        watch_alert_deadline: Option<i64>,
    ) -> DispatchResult {
        if super::expiry::is_expired(expiry, super::store::now()) {
            return DispatchResult::delivery_expired();
        }
        let platform = match (provider, platform) {
            ("FCM", Platform::Android) => ProductPlatform::ANDROID,
            ("APNS", Platform::Ios) => ProductPlatform::IOS,
            ("APNS", Platform::Macos) => ProductPlatform::MACOS,
            ("APNS", Platform::Watchos) => ProductPlatform::WATCHOS,
            ("WNS", Platform::Windows) => ProductPlatform::WINDOWS,
            _ => return preparation_failed(),
        };
        let Some(object) = payload.as_object() else {
            return preparation_failed();
        };
        let mut data: HashMap<String, String> = object
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
            .collect();
        // Public URL advertisement is optional in normal product configuration.
        // As in CustomPayloadData::apply_gateway_base_url(None), omission stays
        // omitted; clients retain their configured Gateway as the Pull source.
        if data
            .get("base_url")
            .is_some_and(|base| base.trim().is_empty())
        {
            data.remove("base_url");
        }
        let wakeup_pull_available =
            ProviderPullTarget::for_provider_target(device, platform, token, delivery).is_some();
        // Only target-specific wire projection is changed. The canonical body
        // and receipt's frozen owner remain untouched in the ordinary ledger.
        data.insert("delivery_id".into(), delivery.into());
        data.insert("provider_device_key".into(), device.into());
        data.insert("sent_at".into(), accepted.to_string());
        data.remove(WATCH_ALERT_DEADLINE_KEY);
        let mut wakeup = crate::util::build_provider_wakeup_data(&data);
        wakeup.insert("provider_device_key".into(), device.into());
        let notification =
            NotificationTextResolver::resolve(EntityKind::Message, None, None, &data);
        let severity = data
            .get("severity")
            .map(String::as_str)
            .unwrap_or("normal")
            .to_owned();
        // Ledger recovery retention is not an implicit Provider TTL. Preserve
        // the normal adapter's omitted TTL when the sender omitted that field.
        let ttl = data.contains_key("ttl").then(|| {
            ((expiry.saturating_sub(super::store::now()) / 1_000).clamp(0, 2_592_000)) as u32
        });
        let prepared = match platform {
            ProductPlatform::ANDROID => prepare_fcm_payload(FcmPayloadPreparation {
                platform,
                device_token: token,
                direct_payload: Arc::new(FcmPayload::new(
                    data,
                    FcmPayload::priority_for_level(&severity),
                    ttl,
                )),
                wakeup_payload: Arc::new(FcmPayload::new(wakeup, "HIGH", ttl)),
                inline_allowed: true,
                wakeup_pull_available,
            }),
            ProductPlatform::WINDOWS => prepare_wns_payload(WnsPayloadPreparation {
                platform,
                direct_payload: Arc::new(WnsPayload::new(
                    data,
                    delivery,
                    WnsEnvelopeKind::Notification,
                    &severity,
                    ttl,
                )),
                wakeup_payload: Arc::new(WnsPayload::new(
                    wakeup,
                    delivery,
                    WnsEnvelopeKind::ProviderWakeup,
                    "high",
                    ttl,
                )),
                inline_allowed: true,
                wakeup_pull_available,
            }),
            ProductPlatform::IOS | ProductPlatform::MACOS | ProductPlatform::WATCHOS => {
                let thread = AppleThreadIdResolver::resolve(
                    data.get("channel_id").map(String::as_str).unwrap_or(""),
                    EntityKind::Message,
                    &data,
                )
                .into_inner();
                let expiration = data
                    .contains_key("ttl")
                    .then(|| ApnsExpirationEpochSeconds::from_epoch_millis(expiry));
                let wakeup_body = wakeup.get("body").cloned();
                let data = if platform == ProductPlatform::WATCHOS {
                    quantize_watch_payload(&data)
                } else {
                    data
                };
                let mut direct = ApnsPayload::new(
                    notification.title.clone(),
                    notification.body,
                    wakeup_body.clone(),
                    Some(thread.clone()),
                    severity,
                    expiration,
                    data,
                );
                let mut wakeup = ApnsPayload::wakeup(
                    notification.title,
                    wakeup_body,
                    Some(thread),
                    expiration,
                    wakeup,
                );
                if platform == ProductPlatform::WATCHOS {
                    // Missing/invalid frozen metadata suppresses an alert; it
                    // must never mint a new reminder age at a retry boundary.
                    let deadline = watch_alert_deadline.unwrap_or(-1);
                    direct = direct.with_watch_alert_deadline(deadline);
                    wakeup = wakeup.with_watch_alert_deadline(deadline);
                    let at = super::store::now();
                    let Some(eligible) = direct.watch_alert_for_attempt(accepted, at) else {
                        return DispatchResult::watch_alert_expired();
                    };
                    direct = eligible;
                    let Some(eligible) = wakeup.watch_alert_for_attempt(accepted, at) else {
                        return DispatchResult::watch_alert_expired();
                    };
                    wakeup = eligible;
                }
                prepare_apns_payload(ApnsPayloadPreparation {
                    platform,
                    direct_payload: Arc::new(direct),
                    wakeup_payload: Arc::new(wakeup),
                    inline_allowed: true,
                    wakeup_pull_available,
                })
            }
            ProductPlatform::MQTT => return preparation_failed(),
        };
        drop(payload);
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(ProviderPayloadPreparationError::EncodeFailed { .. }) => {
                return preparation_failed();
            }
            Err(ProviderPayloadPreparationError::PathRejected(_)) => {
                return DispatchResult {
                    success: false,
                    status_code: 0,
                    error: None,
                    failure_kind: Some(ProviderFailureKind::PayloadTooLarge),
                    retry_after_millis: None,
                };
            }
        };
        match prepared {
            PreparedProviderPayload::Apns {
                direct_payload,
                wakeup_payload,
                selection,
            } => {
                let direct = selection.initial_path == ProviderDeliveryPath::Direct;
                let selected = if direct {
                    direct_payload
                } else {
                    Arc::clone(&wakeup_payload)
                };
                let result = self
                    .apns
                    .send_to_device_before(
                        token,
                        platform,
                        selected,
                        Some(Arc::from(delivery)),
                        expiry,
                    )
                    .await;
                if !result.success
                    && direct
                    && result.is_payload_too_large()
                    && selection.wakeup_payload_within_limit
                {
                    self.apns
                        .send_to_device_before(
                            token,
                            platform,
                            wakeup_payload,
                            Some(Arc::from(delivery)),
                            expiry,
                        )
                        .await
                } else {
                    result
                }
            }
            PreparedProviderPayload::Fcm {
                direct_payload,
                direct_body,
                wakeup_payload,
                wakeup_body,
                selection,
            } => {
                let direct = selection.initial_path == ProviderDeliveryPath::Direct;
                let (payload, body) = if direct {
                    (direct_payload, Some(direct_body))
                } else {
                    (Arc::clone(&wakeup_payload), wakeup_body.clone())
                };
                let result = self
                    .fcm
                    .send_to_device_before(token, payload, body, expiry)
                    .await;
                if !result.success
                    && direct
                    && result.is_payload_too_large()
                    && selection.wakeup_payload_within_limit
                {
                    self.fcm
                        .send_to_device_before(token, wakeup_payload, wakeup_body, expiry)
                        .await
                } else {
                    result
                }
            }
            PreparedProviderPayload::Wns {
                direct_payload,
                wakeup_payload,
                selection,
            } => {
                let direct = selection.initial_path == ProviderDeliveryPath::Direct;
                let selected = if direct {
                    direct_payload
                } else {
                    Arc::clone(&wakeup_payload)
                };
                let result = self
                    .wns
                    .send_to_device_before(token, selected, expiry)
                    .await;
                if !result.success
                    && direct
                    && result.is_payload_too_large()
                    && selection.wakeup_payload_within_limit
                {
                    self.wns
                        .send_to_device_before(token, wakeup_payload, expiry)
                        .await
                } else {
                    result
                }
            }
        }
    }
}

fn preparation_failed() -> DispatchResult {
    DispatchResult {
        success: false,
        status_code: 0,
        error: None,
        failure_kind: Some(ProviderFailureKind::Rejected),
        retry_after_millis: None,
    }
}

impl ProviderTransport for ProductProviders {
    fn send<'a>(
        &'a self,
        provider: &'a str,
        platform: Platform,
        token: &'a str,
        payload: Value,
        delivery: &'a str,
        device: &'a str,
        accepted: i64,
        expiry: i64,
        watch_alert_deadline: Option<i64>,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(self.request(
            provider,
            platform,
            token,
            payload,
            delivery,
            device,
            accepted,
            expiry,
            watch_alert_deadline,
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct ExistingClients(
        pub(crate) Mutex<Vec<(ProductPlatform, Value)>>,
        pub(crate) Mutex<Vec<Option<i64>>>,
    );

    impl ApnsClient for ExistingClients {
        fn send_to_device<'a>(
            &'a self,
            _token: &'a str,
            platform: ProductPlatform,
            payload: Arc<ApnsPayload>,
            _collapse: Option<Arc<str>>,
        ) -> BoxFuture<'a, DispatchResult> {
            Box::pin(async move {
                self.1
                    .lock()
                    .unwrap()
                    .push(payload.expiration.map(|expiry| expiry.into_inner()));
                self.0.lock().unwrap().push((
                    platform,
                    serde_json::from_slice(&payload.encoded_body().unwrap()).unwrap(),
                ));
                DispatchResult::success(200)
            })
        }
        fn token_info<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<crate::providers::TokenInfo, crate::Error>> {
            panic!("transport must use the injected client, not another credential owner")
        }
        fn token_info_fresh<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<crate::providers::TokenInfo, crate::Error>> {
            panic!("transport must use the injected client, not another credential owner")
        }
    }
    impl FcmClient for ExistingClients {
        fn send_to_device<'a>(
            &'a self,
            token: &'a str,
            payload: Arc<FcmPayload>,
            body: Option<Arc<[u8]>>,
        ) -> BoxFuture<'a, DispatchResult> {
            Box::pin(async move {
                let body = body.unwrap_or_else(|| payload.encoded_body(token).unwrap());
                self.0.lock().unwrap().push((
                    ProductPlatform::ANDROID,
                    serde_json::from_slice(&body).unwrap(),
                ));
                DispatchResult::success(200)
            })
        }
        fn token_info<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<crate::providers::TokenInfo, crate::Error>> {
            panic!("unexpected credential access")
        }
        fn token_info_fresh<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<crate::providers::TokenInfo, crate::Error>> {
            panic!("unexpected credential access")
        }
    }
    impl WnsClient for ExistingClients {
        fn send_to_device<'a>(
            &'a self,
            _token: &'a str,
            payload: Arc<WnsPayload>,
        ) -> BoxFuture<'a, DispatchResult> {
            Box::pin(async move {
                self.0.lock().unwrap().push((
                    ProductPlatform::WINDOWS,
                    serde_json::from_slice(&payload.encoded_body().unwrap()).unwrap(),
                ));
                DispatchResult::success(200)
            })
        }
        fn token_info<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<crate::providers::TokenInfo, crate::Error>> {
            panic!("unexpected credential access")
        }
        fn token_info_fresh<'a>(
            &'a self,
        ) -> BoxFuture<'a, Result<crate::providers::TokenInfo, crate::Error>> {
            panic!("unexpected credential access")
        }
    }
    fn payload() -> Value {
        serde_json::json!({
            "entity_type":"message", "entity_id":"message-identity", "message_id":"message-identity",
            "channel_id":"channel", "base_url":"https://synthetic.invalid/prefix",
            "body":"ordinary body", "severity":"normal", "thing_id":"association",
            "occurred_at":"1000"
        })
    }

    #[tokio::test]
    async fn optional_public_base_url_does_not_suppress_normal_direct_delivery() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let at = super::super::store::now();
        for advertised in [None, Some("")] {
            let mut input = payload();
            input.as_object_mut().unwrap().remove("base_url");
            if let Some(value) = advertised {
                input["base_url"] = Value::String(value.into());
            }
            for (provider, platform) in [
                ("FCM", Platform::Android),
                ("APNS", Platform::Ios),
                ("WNS", Platform::Windows),
            ] {
                assert!(
                    transport
                        .send(
                            provider,
                            platform,
                            "synthetic-target",
                            input.clone(),
                            "delivery",
                            "frozen-owner",
                            at,
                            at + 60_000,
                            None
                        )
                        .await
                        .success
                );
            }
        }
        let calls = clients.0.lock().unwrap();
        assert_eq!(calls.len(), 6);
        for batch in calls.chunks(3) {
            let fcm = &batch[0].1["message"]["data"];
            assert_eq!(fcm["message_id"], "message-identity");
            assert!(fcm.get("base_url").is_none());
            assert!(fcm.get("provider_mode").is_none());
            let apns = &batch[1].1;
            assert_eq!(apns["message_id"], "message-identity");
            assert!(apns.get("base_url").is_none());
            assert!(apns.get("provider_mode").is_none());
            let wns = &batch[2].1;
            assert_eq!(wns["kind"], "notification");
            assert_eq!(wns["payload"]["message_id"], "message-identity");
            assert!(wns["payload"].get("base_url").is_none());
        }
    }

    #[tokio::test]
    async fn wakeup_without_public_advertisement_keeps_configured_client_pull_path() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let at = super::super::store::now();
        let mut input = payload();
        input.as_object_mut().unwrap().remove("base_url");
        input["body"] = Value::String("x".repeat(48 * 1024));
        assert!(
            transport
                .send(
                    "FCM",
                    Platform::Android,
                    "synthetic-target",
                    input,
                    "delivery",
                    "frozen-owner",
                    at,
                    at + 60_000,
                    None
                )
                .await
                .success
        );
        let calls = clients.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let wire = &calls[0].1["message"]["data"];
        assert_eq!(wire["provider_mode"], "wakeup");
        assert_eq!(wire["delivery_id"], "delivery");
        assert_eq!(wire["provider_device_key"], "frozen-owner");
        assert!(wire.get("base_url").is_none());
    }

    #[tokio::test]
    async fn large_fcm_uses_existing_wakeup_projection_and_same_identity() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let mut payload = payload();
        payload["body"] = Value::String("界".repeat(16 * 1024));
        let at = super::super::store::now();
        let result = transport
            .send(
                "FCM",
                Platform::Android,
                "synthetic-token",
                payload,
                "delivery",
                "frozen-owner",
                at,
                at + 60_000,
                None,
            )
            .await;
        assert!(result.success);
        let calls = clients.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let data = &calls[0].1["message"]["data"];
        assert_eq!(data["delivery_id"], "delivery");
        assert_eq!(data["message_id"], "message-identity");
        assert_eq!(data["provider_device_key"], "frozen-owner");
        assert_eq!(data["provider_mode"], "wakeup");
        assert_eq!(data["base_url"], "https://synthetic.invalid/prefix");
        assert!(calls[0].1["message"]["android"].get("ttl").is_none());
    }

    #[tokio::test]
    async fn explicit_provider_ttl_uses_remaining_absolute_lifetime() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let at = super::super::store::now();
        let mut payload = payload();
        payload["ttl"] = Value::String((at + 60_000).to_string());
        assert!(
            transport
                .send(
                    "FCM",
                    Platform::Android,
                    "synthetic-token",
                    payload,
                    "delivery",
                    "frozen-owner",
                    at - 30_000,
                    at + 60_000,
                    None
                )
                .await
                .success
        );
        let calls = clients.0.lock().unwrap();
        let remaining = calls[0].1["message"]["android"]["ttl"]
            .as_str()
            .unwrap()
            .strip_suffix('s')
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!((1..=60).contains(&remaining));
    }

    #[tokio::test]
    async fn queued_ordinary_work_at_its_deadline_never_enters_provider_client() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let at = super::super::store::now();
        let result = transport
            .send(
                "FCM",
                Platform::Android,
                "synthetic-token",
                payload(),
                "delivery",
                "frozen-owner",
                at - 1_000,
                at,
                None,
            )
            .await;
        assert_eq!(
            result.failure_kind,
            Some(ProviderFailureKind::DeliveryExpired)
        );
        assert!(!result.is_retryable());
        assert!(clients.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wns_uses_product_envelope_and_keeps_routing_out_of_wire_content() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let at = super::super::store::now();
        assert!(
            transport
                .send(
                    "WNS",
                    Platform::Windows,
                    "https://synthetic.invalid/channel",
                    payload(),
                    "delivery",
                    "frozen-owner",
                    at,
                    at + 60_000,
                    None
                )
                .await
                .success
        );
        let calls = clients.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, ProductPlatform::WINDOWS);
        let wire = &calls[0].1;
        assert_eq!(wire["version"], 2);
        assert_eq!(wire["delivery_id"], "delivery");
        assert_eq!(wire["payload"]["message_id"], "message-identity");
        assert_eq!(wire["payload"]["thing_id"], "association");
        assert!(wire["payload"].get("provider_device_key").is_none());
        assert!(wire["payload"].get("base_url").is_none());
    }

    #[tokio::test]
    async fn watch_uses_frozen_reminder_deadline_and_existing_light_projection() {
        let clients = Arc::new(ExistingClients::default());
        let transport = ProductProviders::new(clients.clone(), clients.clone(), clients.clone());
        let at = super::super::store::now();
        let deadline = at + 300_000;
        assert!(
            transport
                .send(
                    "APNS",
                    Platform::Watchos,
                    "synthetic-token",
                    payload(),
                    "delivery",
                    "frozen-owner",
                    at,
                    at + 600_000,
                    Some(deadline)
                )
                .await
                .success
        );
        let calls = clients.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, ProductPlatform::WATCHOS);
        assert_eq!(calls[0].1["watch_light_kind"], "message");
        assert_eq!(calls[0].1["watch_alert_deadline_at"], deadline.to_string());
        drop(calls);
        let result = transport
            .send(
                "APNS",
                Platform::Watchos,
                "synthetic-token",
                payload(),
                "delivery",
                "frozen-owner",
                at - 300_001,
                at + 600_000,
                Some(at - 1),
            )
            .await;
        assert_eq!(
            result.failure_kind,
            Some(ProviderFailureKind::WatchAlertExpired)
        );
        assert_eq!(clients.0.lock().unwrap().len(), 1);
    }
}
