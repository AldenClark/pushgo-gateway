use mqttbytes::v5::{DisconnectReasonCode, PubAckReason, SubscribeReasonCode};

use crate::{api::Error, storage::StoreError};

#[derive(Debug, Clone)]
pub(super) struct MqttError {
    pub(super) message: &'static str,
    pub(super) code: &'static str,
    pub(super) kind: MqttErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MqttErrorKind {
    Auth,
    Topic,
    Payload,
    TopicAlias,
    Qos,
    Retain,
    NotSupported,
    Quota,
    Internal,
}

impl MqttError {
    pub(super) fn new(message: &'static str, code: &'static str, kind: MqttErrorKind) -> Self {
        Self {
            message,
            code,
            kind,
        }
    }
}

pub(super) fn mqtt_error_from_api(err: Error) -> MqttError {
    let text = err.to_string();
    let message = Box::leak(text.into_boxed_str());
    let code = match &err {
        Error::Unauthorized => "not_authorized",
        Error::TooBusy | Error::StoreError(StoreError::PasswordKdfBusy) => "server_busy",
        Error::Validation {
            code: Some(code), ..
        } => Box::leak(code.clone().into_owned().into_boxed_str()),
        Error::StoreError(StoreError::ChannelNotFound) => "channel_not_authorized",
        Error::StoreError(StoreError::ChannelPasswordMismatch) => "channel_not_authorized",
        _ => "implementation_specific",
    };
    let kind = match &err {
        Error::Unauthorized
        | Error::StoreError(StoreError::ChannelNotFound)
        | Error::StoreError(StoreError::ChannelPasswordMismatch) => MqttErrorKind::Auth,
        Error::TooBusy | Error::StoreError(StoreError::PasswordKdfBusy) => MqttErrorKind::Quota,
        Error::Validation {
            code: Some(code), ..
        } if code.contains("topic") || code.as_ref() == "channel_id_invalid" => {
            MqttErrorKind::Topic
        }
        Error::Validation {
            code: Some(code), ..
        } if code.as_ref() == "channel_not_authorized"
            || code.as_ref() == "authentication_failed" =>
        {
            MqttErrorKind::Auth
        }
        Error::Validation { .. } => MqttErrorKind::Payload,
        _ => MqttErrorKind::Internal,
    };
    MqttError {
        message,
        code,
        kind,
    }
}

pub(super) fn subscribe_reason_for_error(err: &MqttError) -> SubscribeReasonCode {
    match err.kind {
        MqttErrorKind::Auth => SubscribeReasonCode::NotAuthorized,
        MqttErrorKind::Topic => {
            if err.code == "mqtt_topic_filter_not_supported" {
                SubscribeReasonCode::WildcardSubscriptionsNotSupported
            } else {
                SubscribeReasonCode::TopicFilterInvalid
            }
        }
        MqttErrorKind::Qos | MqttErrorKind::NotSupported => {
            SubscribeReasonCode::ImplementationSpecific
        }
        MqttErrorKind::Quota => SubscribeReasonCode::QuotaExceeded,
        _ => SubscribeReasonCode::ImplementationSpecific,
    }
}

pub(super) fn puback_reason_for_error(err: &MqttError) -> PubAckReason {
    match err.kind {
        MqttErrorKind::Auth => PubAckReason::NotAuthorized,
        MqttErrorKind::Topic => PubAckReason::TopicNameInvalid,
        MqttErrorKind::Payload => PubAckReason::PayloadFormatInvalid,
        MqttErrorKind::Quota => PubAckReason::QuotaExceeded,
        _ => PubAckReason::ImplementationSpecificError,
    }
}

pub(super) fn publish_disconnect_reason(err: &MqttError) -> Option<DisconnectReasonCode> {
    match err.kind {
        MqttErrorKind::Qos => Some(DisconnectReasonCode::QoSNotSupported),
        MqttErrorKind::Retain => Some(DisconnectReasonCode::RetainNotSupported),
        MqttErrorKind::TopicAlias => Some(DisconnectReasonCode::TopicAliasInvalid),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_kdf_overload_maps_to_mqtt_quota() {
        let mapped = mqtt_error_from_api(Error::StoreError(StoreError::PasswordKdfBusy));
        assert_eq!(mapped.code, "server_busy");
        assert_eq!(mapped.kind, MqttErrorKind::Quota);
        assert_eq!(
            subscribe_reason_for_error(&mapped),
            SubscribeReasonCode::QuotaExceeded
        );
        assert_eq!(
            puback_reason_for_error(&mapped),
            PubAckReason::QuotaExceeded
        );
    }

    #[test]
    fn delivery_core_busy_maps_to_mqtt_quota() {
        let mapped = mqtt_error_from_api(Error::TooBusy);
        assert_eq!(mapped.code, "server_busy");
        assert_eq!(mapped.kind, MqttErrorKind::Quota);
        assert_eq!(
            puback_reason_for_error(&mapped),
            PubAckReason::QuotaExceeded
        );
    }
}
