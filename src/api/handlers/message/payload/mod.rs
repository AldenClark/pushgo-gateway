mod custom;
mod provider;

pub(crate) use crate::value::{EntityKind, NotificationSeverity, OptionalText};
pub(crate) use custom::{CustomPayloadData, StandardFields};
pub(crate) use provider::{ProviderDeliverySelection, ProviderRouteBinding, ProviderTtl};

pub(crate) const PAYLOAD_VERSION: &str = "1";
pub(crate) const SCHEMA_VERSION: &str = "1";
pub(crate) const MAX_PROVIDER_TTL_SECONDS: i64 = 2_592_000;
pub(crate) const MAX_PROVIDER_TTL_MILLIS: i64 = MAX_PROVIDER_TTL_SECONDS * 1000;
