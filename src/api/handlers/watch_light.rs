use hashbrown::HashMap;

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct WatchProfile {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

fn non_empty_owned(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
}

fn payload_field(payload: &HashMap<String, String>, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(|value| non_empty_owned(Some(value)))
}

fn parse_profile(raw: Option<&String>) -> Option<WatchProfile> {
    raw.and_then(|text| serde_json::from_str::<WatchProfile>(text).ok())
}

fn profile_field(value: Option<&String>) -> Option<String> {
    non_empty_owned(value.map(String::as_str))
}

fn insert_if_present(
    output: &mut HashMap<String, String>,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        output.insert(key.to_string(), value);
    }
}

pub(crate) fn quantize_watch_payload(payload: &HashMap<String, String>) -> HashMap<String, String> {
    let entity_type = payload
        .get("entity_type")
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "message".to_string());

    let mut output = match entity_type.as_str() {
        "event" => {
            let profile = parse_profile(payload.get("event_profile_json"));
            let event_id =
                payload_field(payload, "event_id").or_else(|| payload_field(payload, "entity_id"));
            let Some(event_id) = event_id else {
                return HashMap::new();
            };
            let mut output = HashMap::with_capacity(8);
            output.insert("watch_light_kind".to_string(), "event".to_string());
            output.insert("event_id".to_string(), event_id.clone());
            output.insert(
                "title".to_string(),
                profile_field(profile.as_ref().and_then(|value| value.title.as_ref()))
                    .or_else(|| payload_field(payload, "title"))
                    .unwrap_or(event_id),
            );
            insert_if_present(
                &mut output,
                "body",
                profile_field(
                    profile
                        .as_ref()
                        .and_then(|value| value.description.as_ref()),
                )
                .or_else(|| payload_field(payload, "body")),
            );
            insert_if_present(
                &mut output,
                "event_state",
                payload_field(payload, "event_state"),
            );
            insert_if_present(
                &mut output,
                "image",
                profile_field(profile.as_ref().and_then(|value| value.image.as_ref()))
                    .or_else(|| payload_field(payload, "image")),
            );
            insert_if_present(
                &mut output,
                "severity",
                profile_field(profile.as_ref().and_then(|value| value.severity.as_ref()))
                    .or_else(|| payload_field(payload, "severity")),
            );
            output
        }
        "thing" => {
            let profile = parse_profile(payload.get("thing_profile_json"));
            let thing_id =
                payload_field(payload, "thing_id").or_else(|| payload_field(payload, "entity_id"));
            let Some(thing_id) = thing_id else {
                return HashMap::new();
            };
            let mut output = HashMap::with_capacity(8);
            output.insert("watch_light_kind".to_string(), "thing".to_string());
            output.insert("thing_id".to_string(), thing_id.clone());
            output.insert(
                "title".to_string(),
                profile_field(profile.as_ref().and_then(|value| value.title.as_ref()))
                    .or_else(|| payload_field(payload, "title"))
                    .unwrap_or(thing_id),
            );
            insert_if_present(
                &mut output,
                "body",
                profile_field(
                    profile
                        .as_ref()
                        .and_then(|value| value.description.as_ref()),
                )
                .or_else(|| payload_field(payload, "body")),
            );
            insert_if_present(
                &mut output,
                "thing_attrs_json",
                payload_field(payload, "thing_attrs_json"),
            );
            insert_if_present(
                &mut output,
                "image",
                profile_field(profile.as_ref().and_then(|value| value.image.as_ref()))
                    .or_else(|| payload_field(payload, "image"))
                    .or_else(|| payload_field(payload, "primary_image")),
            );
            insert_if_present(
                &mut output,
                "observed_at",
                payload_field(payload, "observed_at").or_else(|| payload_field(payload, "sent_at")),
            );
            output
        }
        _ => {
            let Some(message_id) = payload_field(payload, "message_id") else {
                return HashMap::new();
            };
            let mut output = HashMap::with_capacity(6);
            output.insert("watch_light_kind".to_string(), "message".to_string());
            output.insert("message_id".to_string(), message_id.clone());
            output.insert(
                "title".to_string(),
                payload_field(payload, "title").unwrap_or(message_id),
            );
            insert_if_present(&mut output, "body", payload_field(payload, "body"));
            insert_if_present(&mut output, "image", payload_field(payload, "image"));
            insert_if_present(&mut output, "url", payload_field(payload, "url"));
            output
        }
    };

    if output.is_empty() {
        return output;
    }

    for key in [
        "channel_id",
        "delivery_id",
        "sent_at",
        "occurred_at",
        "severity",
        "entity_type",
        "entity_id",
    ] {
        if let Some(value) = payload_field(payload, key) {
            output.insert(key.to_string(), value);
        }
    }

    output
}
