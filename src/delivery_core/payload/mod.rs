mod custom;
pub(crate) mod notification;
pub(crate) mod private_envelope;
mod provider;
pub(crate) mod provider_wakeup;
pub(crate) mod sanitize;
pub(crate) mod standard;
pub(crate) mod target;
pub(crate) mod thread;
pub(crate) mod watch_light;

pub(crate) use crate::value::{EntityKind, NotificationSeverity, OptionalText};
pub(crate) use custom::CustomPayloadData;
pub(crate) use provider::{
    ProviderDeliveryPath, ProviderDeliverySelection, ProviderPullTarget, ProviderStatsDeviceKey,
    ProviderTtl,
};
pub(crate) use standard::StandardFields;
pub(crate) use watch_light::quantize_watch_payload;

pub(crate) const PAYLOAD_VERSION: &str = "1";
pub(crate) const SCHEMA_VERSION: &str = "1";
pub(crate) const MAX_PROVIDER_TTL_SECONDS: i64 = 2_592_000;
pub(crate) const MAX_PROVIDER_TTL_MILLIS: i64 = MAX_PROVIDER_TTL_SECONDS * 1000;
