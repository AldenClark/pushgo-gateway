use std::sync::Arc;

use hashbrown::HashMap;

use crate::value::{EntityKind, OptionalText};

use super::{
    notification::{NotificationTextResolver, ProviderNotificationText},
    private_envelope::{EncodedPrivatePayload, PrivateEnvelopeEncoder},
    provider_wakeup::{ProviderWakeupData, ProviderWakeupProjection},
    sanitize::PayloadFieldSanitizer,
    standard::{StandardFields, StandardPayloadBuilder},
    thread::{AppleThreadId, AppleThreadIdResolver},
};

pub(crate) struct CustomPayloadData {
    data: HashMap<String, String>,
}

pub(crate) struct PreparedCustomPayload {
    pub(crate) custom_data: Arc<HashMap<String, String>>,
    pub(crate) apple_thread_id: AppleThreadId,
    pub(crate) wakeup_data: ProviderWakeupData,
    pub(crate) private_payload: EncodedPrivatePayload,
}

impl CustomPayloadData {
    pub(crate) fn new(data: HashMap<String, String>) -> Self {
        let data = PayloadFieldSanitizer::sanitize(data);
        Self { data }
    }

    pub(crate) fn apply_standard_fields(&mut self, fields: StandardFields<'_>) {
        StandardPayloadBuilder::apply(&mut self.data, fields);
    }

    pub(crate) fn insert_extra_fields(&mut self, extra_fields: HashMap<String, String>) {
        for (key, value) in extra_fields {
            self.data.insert(key, value);
        }
    }

    pub(crate) fn apply_gateway_base_url(&mut self, base_url: Option<&str>) {
        let normalized = base_url
            .map(str::trim)
            .map(|value| value.trim_end_matches('/'))
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        if let Some(value) = normalized {
            self.data.insert("base_url".to_string(), value);
        }
    }

    pub(crate) fn resolve_notification_text(
        &self,
        entity_kind: EntityKind,
        explicit_title: Option<&str>,
        explicit_body: Option<&str>,
    ) -> ProviderNotificationText {
        NotificationTextResolver::resolve(entity_kind, explicit_title, explicit_body, &self.data)
    }

    pub(crate) fn ensure_notification_title(&mut self, title: Option<&str>) {
        if let Some(title) = OptionalText::normalize(title) {
            self.data.entry("title".to_string()).or_insert(title);
        }
    }

    pub(crate) fn into_shared(self) -> Arc<HashMap<String, String>> {
        Arc::new(self.data)
    }

    pub(crate) fn prepare_dispatch(
        self,
        channel_id: &str,
        entity_kind: EntityKind,
    ) -> Result<PreparedCustomPayload, postcard::Error> {
        let apple_thread_id = AppleThreadIdResolver::resolve(channel_id, entity_kind, &self.data);
        let wakeup_data = ProviderWakeupProjection::project_shared(&self.data);
        let private_payload = PrivateEnvelopeEncoder::encode_ref(&self.data)?;
        let custom_data = self.into_shared();
        Ok(PreparedCustomPayload {
            custom_data,
            apple_thread_id,
            wakeup_data,
            private_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    #[test]
    fn ensure_notification_title_promotes_derived_title_into_payload() {
        let body_text = "Body is present but should not be promoted as title";
        let mut payload = super::CustomPayloadData::new(HashMap::new());
        payload.apply_standard_fields(super::StandardFields {
            channel_id: "channel-1",
            title: None,
            body: Some(body_text),
            severity: None,
            schema_version: "1",
            payload_version: "1",
            op_id: "op-1",
            delivery_id: "delivery-1",
            ingested_at: 1,
            occurred_at: 1,
            sent_at: 1,
            ttl: None,
            entity_type: "message",
            entity_id: "message-1",
        });
        let title = payload.resolve_notification_text(super::EntityKind::Message, None, None);
        payload.ensure_notification_title(title.title.as_deref());
        let prepared = payload
            .prepare_dispatch("channel-1", super::EntityKind::Message)
            .expect("payload should encode");

        let wakeup = prepared.wakeup_data.into_inner();
        assert_ne!(
            wakeup.get("title").map(String::as_str),
            Some(body_text),
            "message wakeup title must not come from body preview"
        );
    }
}
