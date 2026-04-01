mod custom;
mod provider;

pub(crate) use custom::{
    CustomPayloadData, EntityKind, OptionalText, PayloadSeverity, StandardFields,
};
pub(crate) use provider::{
    ProviderDeliverySelection, ProviderDeliverySkip, ProviderRouteBinding, ProviderTtl,
};

pub(crate) const PAYLOAD_VERSION: &str = "1";
pub(crate) const SCHEMA_VERSION: &str = "1";
pub(crate) const MAX_PROVIDER_TTL_SECONDS: i64 = 2_592_000;
