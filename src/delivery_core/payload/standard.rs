use hashbrown::HashMap;

use crate::value::OptionalText;

pub(crate) struct StandardFields<'a> {
    pub channel_id: &'a str,
    pub title: Option<&'a str>,
    pub body: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub schema_version: &'a str,
    pub payload_version: &'a str,
    pub op_id: &'a str,
    pub delivery_id: &'a str,
    pub ingested_at: i64,
    pub occurred_at: i64,
    pub sent_at: i64,
    pub ttl: Option<i64>,
    pub entity_type: &'a str,
    pub entity_id: &'a str,
}

pub(crate) struct StandardPayloadBuilder;

impl StandardFields<'_> {
    pub(crate) fn apply_to(self, data: &mut HashMap<String, String>) {
        StandardPayloadBuilder::apply(data, self);
    }
}

impl StandardPayloadBuilder {
    pub(crate) fn apply(data: &mut HashMap<String, String>, fields: StandardFields<'_>) {
        data.insert("channel_id".to_string(), fields.channel_id.to_string());
        if let Some(value) = OptionalText::normalize(fields.title) {
            data.insert("title".to_string(), value.to_string());
        }
        if let Some(value) = OptionalText::normalize(fields.body) {
            data.insert("body".to_string(), value.to_string());
        }
        if let Some(value) = OptionalText::normalize(fields.severity) {
            data.insert("severity".to_string(), value.to_string());
        }
        data.insert(
            "schema_version".to_string(),
            fields.schema_version.to_string(),
        );
        data.insert(
            "payload_version".to_string(),
            fields.payload_version.to_string(),
        );
        data.insert("op_id".to_string(), fields.op_id.to_string());
        data.insert("delivery_id".to_string(), fields.delivery_id.to_string());
        data.insert("ingested_at".to_string(), fields.ingested_at.to_string());
        data.insert("occurred_at".to_string(), fields.occurred_at.to_string());
        data.insert("sent_at".to_string(), fields.sent_at.to_string());
        data.insert("entity_type".to_string(), fields.entity_type.to_string());
        data.insert("entity_id".to_string(), fields.entity_id.to_string());
        if let Some(ttl) = fields.ttl {
            data.insert("ttl".to_string(), ttl.to_string());
        }
    }
}
