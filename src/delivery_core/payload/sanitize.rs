use hashbrown::HashMap;

pub(crate) struct PayloadFieldSanitizer;

const RESERVED_FIELDS: &[&str] = &[
    "title",
    "body",
    "channel_id",
    "level",
    "schema_version",
    "payload_version",
    "op_id",
    "delivery_id",
    "ingested_at",
    "message_id",
    "occurred_at",
    "sent_at",
    "ttl",
    "entity_type",
    "entity_id",
    "event_id",
    "event_state",
    "event_time",
    "event_title",
    "event_description",
    "event_unset_json",
    "severity",
    "tags",
    "attachments",
    "started_at",
    "ended_at",
    "thing_id",
    "thing_unset_json",
    "image",
    "primary_image",
    "attachments",
    "created_at",
    "state",
    "deleted_at",
    "external_ids",
    "location_type",
    "location_value",
    "observed_at",
    "notify_user",
    "local_notify",
    "provider_mode",
    "provider_wakeup",
    "provider_wakeup_handled",
    "_skip_persist",
];

impl PayloadFieldSanitizer {
    pub(crate) fn sanitize(mut data: HashMap<String, String>) -> HashMap<String, String> {
        Self::sanitize_in_place(&mut data);
        data
    }

    pub(crate) fn sanitize_in_place(data: &mut HashMap<String, String>) {
        for key in RESERVED_FIELDS {
            data.remove(*key);
        }
    }
}
