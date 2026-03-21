use std::collections::HashMap;

use serde_json::Value;

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
}

fn parse_profile(raw: Option<&String>) -> Option<Value> {
    raw.and_then(|text| serde_json::from_str::<Value>(text).ok())
}

fn profile_field(profile: &Option<Value>, key: &str) -> Option<String> {
    profile
        .as_ref()
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .and_then(|value| non_empty(Some(value)))
}

pub(crate) fn quantize_watch_payload(payload: &HashMap<String, String>) -> HashMap<String, String> {
    let entity_type = payload
        .get("entity_type")
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "message".to_string());

    let mut output = match entity_type.as_str() {
        "event" => {
            let profile = parse_profile(payload.get("event_profile_json"));
            if let Some(event_id) = payload
                .get("event_id")
                .and_then(|value| non_empty(Some(value)))
                .or_else(|| {
                    payload
                        .get("entity_id")
                        .and_then(|value| non_empty(Some(value)))
                })
            {
                let mut output = HashMap::new();
                output.insert("watch_light_kind".to_string(), "event".to_string());
                output.insert("event_id".to_string(), event_id.clone());
                output.insert(
                    "title".to_string(),
                    profile_field(&profile, "title")
                        .or_else(|| {
                            payload
                                .get("title")
                                .and_then(|value| non_empty(Some(value)))
                        })
                        .unwrap_or(event_id),
                );
                if let Some(summary) = profile_field(&profile, "description")
                    .or_else(|| payload.get("body").and_then(|value| non_empty(Some(value))))
                {
                    output.insert("body".to_string(), summary);
                }
                if let Some(state) = payload
                    .get("event_state")
                    .and_then(|value| non_empty(Some(value)))
                {
                    output.insert("event_state".to_string(), state);
                }
                if let Some(image) = profile_field(&profile, "image").or_else(|| {
                    payload
                        .get("image")
                        .and_then(|value| non_empty(Some(value)))
                }) {
                    output.insert("image".to_string(), image);
                }
                if let Some(severity) = profile_field(&profile, "severity").or_else(|| {
                    payload
                        .get("severity")
                        .and_then(|value| non_empty(Some(value)))
                }) {
                    output.insert("severity".to_string(), severity);
                }
                output
            } else {
                HashMap::new()
            }
        }
        "thing" => {
            let profile = parse_profile(payload.get("thing_profile_json"));
            if let Some(thing_id) = payload
                .get("thing_id")
                .and_then(|value| non_empty(Some(value)))
                .or_else(|| {
                    payload
                        .get("entity_id")
                        .and_then(|value| non_empty(Some(value)))
                })
            {
                let mut output = HashMap::new();
                output.insert("watch_light_kind".to_string(), "thing".to_string());
                output.insert("thing_id".to_string(), thing_id.clone());
                output.insert(
                    "title".to_string(),
                    profile_field(&profile, "title")
                        .or_else(|| {
                            payload
                                .get("title")
                                .and_then(|value| non_empty(Some(value)))
                        })
                        .unwrap_or(thing_id),
                );
                if let Some(summary) = profile_field(&profile, "description")
                    .or_else(|| payload.get("body").and_then(|value| non_empty(Some(value))))
                {
                    output.insert("body".to_string(), summary);
                }
                if let Some(attrs_json) = payload
                    .get("thing_attrs_json")
                    .and_then(|value| non_empty(Some(value)))
                {
                    output.insert("thing_attrs_json".to_string(), attrs_json);
                }
                if let Some(image) = profile_field(&profile, "image")
                    .or_else(|| {
                        payload
                            .get("image")
                            .and_then(|value| non_empty(Some(value)))
                    })
                    .or_else(|| {
                        payload
                            .get("primary_image")
                            .and_then(|value| non_empty(Some(value)))
                    })
                {
                    output.insert("image".to_string(), image);
                }
                if let Some(observed_at) = payload
                    .get("observed_at")
                    .and_then(|value| non_empty(Some(value)))
                    .or_else(|| {
                        payload
                            .get("sent_at")
                            .and_then(|value| non_empty(Some(value)))
                    })
                {
                    output.insert("observed_at".to_string(), observed_at);
                }
                output
            } else {
                HashMap::new()
            }
        }
        _ => {
            if let Some(message_id) = payload
                .get("message_id")
                .and_then(|value| non_empty(Some(value)))
            {
                let mut output = HashMap::new();
                output.insert("watch_light_kind".to_string(), "message".to_string());
                output.insert("message_id".to_string(), message_id.clone());
                output.insert(
                    "title".to_string(),
                    payload
                        .get("title")
                        .and_then(|value| non_empty(Some(value)))
                        .unwrap_or(message_id),
                );
                if let Some(body) = payload.get("body").and_then(|value| non_empty(Some(value))) {
                    output.insert("body".to_string(), body);
                }
                if let Some(image) = payload
                    .get("image")
                    .and_then(|value| non_empty(Some(value)))
                {
                    output.insert("image".to_string(), image);
                }
                if let Some(url) = payload.get("url").and_then(|value| non_empty(Some(value))) {
                    output.insert("url".to_string(), url);
                }
                output
            } else {
                HashMap::new()
            }
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
        if let Some(value) = payload.get(key).and_then(|value| non_empty(Some(value))) {
            output.insert(key.to_string(), value);
        }
    }

    output
}
