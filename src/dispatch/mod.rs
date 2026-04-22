use std::sync::Arc;

use flume::{Receiver, Sender, TrySendError};

use crate::{
    private::PrivateState,
    providers::{
        ApnsClient, DispatchResult, FcmClient, WnsClient, apns::ApnsPayload, fcm::FcmPayload,
        wns::WnsPayload,
    },
    storage::{Platform, Storage},
    util::encode_crockford_base32_128,
};

#[path = "config.rs"]
mod config;
#[path = "runtime.rs"]
mod runtime;
#[path = "types.rs"]
mod types;
#[path = "workers.rs"]
mod workers;

use config::DispatchRuntimeConfig;
use runtime::DispatchWorkerRuntime;
pub(crate) use types::{
    ApnsJob, DispatchChannels, DispatchError, DispatchWorkerReceivers, FcmJob,
    ProviderDeliveryPath, ProviderPullDelivery, WnsJob,
};
pub(crate) use workers::DispatchWorkerDeps;
