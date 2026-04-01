use std::{sync::Arc, time::Duration};

use flume::{Receiver, Sender, TrySendError};
use hashbrown::HashMap;

pub(crate) mod audit;

use self::audit::{DispatchAuditLog, DispatchAuditRecord};

use crate::{
    private::PrivateState,
    providers::{
        ApnsClient, DispatchResult, FcmClient, WnsClient, apns::ApnsPayload, fcm::FcmPayload,
        wns::WnsPayload,
    },
    storage::{Platform, PrivateMessage, Storage},
    util::{build_wakeup_data, encode_crockford_base32_128},
};

#[path = "config.rs"]
mod config;
#[path = "delivery_audit.rs"]
mod delivery_audit;
#[path = "retry.rs"]
mod retry;
#[path = "runtime.rs"]
mod runtime;
#[path = "types.rs"]
mod types;
#[path = "workers.rs"]
mod workers;

use config::{DispatchRuntimeConfig, ProviderPullRetryConfig};
pub(crate) use delivery_audit::{DeliveryAuditCollector, DeliveryAuditMode};
pub(crate) use retry::ProviderPullRetryWorkerDeps;
use runtime::DispatchWorkerRuntime;
pub(crate) use types::{
    ApnsJob, DispatchChannels, DispatchError, DispatchWorkerReceivers, FcmJob,
    PrivateWakeupDelivery, ProviderDeliveryPath, WnsJob,
};
pub(crate) use workers::DispatchWorkerDeps;
