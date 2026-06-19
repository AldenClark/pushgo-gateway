use hashbrown::HashMap;
use serde_json::Value as JsonValue;

use crate::value::{EntityKind, OptionalText};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderNotificationText {
    pub(crate) title: Option<String>,
    pub(crate) body: Option<String>,
}

pub(crate) use ProviderNotificationText as ResolvedNotificationText;

pub(crate) struct NotificationTextResolver;

impl NotificationTextResolver {
    pub(crate) fn resolve(
        entity_kind: crate::value::EntityKind,
        title: Option<&str>,
        body: Option<&str>,
        payload: &HashMap<String, String>,
    ) -> ResolvedNotificationText {
        match entity_kind {
            EntityKind::Event => ProviderNotificationText {
                title: normalize_optional_text(title).or_else(|| {
                    map_text(payload, "title")
                        .or_else(|| map_text(payload, "event_title"))
                        .or_else(|| {
                            map_text(payload, "event_id")
                                .or_else(|| map_text(payload, "entity_id"))
                                .map(|id| format!("Event {id}"))
                        })
                }),
                body: normalize_optional_text(body).or_else(|| {
                    map_text(payload, "message")
                        .or_else(|| map_text(payload, "description"))
                        .or_else(|| gateway_fallback_body(payload, "event"))
                }),
            },
            EntityKind::Thing => ProviderNotificationText {
                title: normalize_optional_text(title).or_else(|| {
                    thing_name_from_attrs(payload)
                        .or_else(|| map_text(payload, "title"))
                        .or_else(|| {
                            map_text(payload, "thing_id")
                                .or_else(|| map_text(payload, "entity_id"))
                                .map(|id| format!("Object {id}"))
                        })
                }),
                body: normalize_optional_text(body).or_else(|| {
                    map_text(payload, "message")
                        .or_else(|| map_text(payload, "description"))
                        .or_else(|| gateway_fallback_body(payload, "thing"))
                }),
            },
            EntityKind::Message => {
                let explicit_or_payload_body =
                    normalize_optional_text(body).or_else(|| map_text(payload, "body"));
                ProviderNotificationText {
                    title: normalize_optional_text(title)
                        .or_else(|| map_text(payload, "title"))
                        .or_else(|| map_text(payload, "url"))
                        .or_else(|| first_image_url(payload))
                        .or_else(|| {
                            map_text(payload, "message_id").map(|id| format!("Message {id}"))
                        })
                        .or_else(|| {
                            map_text(payload, "entity_id").map(|id| format!("Message {id}"))
                        }),
                    body: explicit_or_payload_body,
                }
            }
        }
    }
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    OptionalText::normalize(value)
}

fn map_text(data: &HashMap<String, String>, key: &str) -> Option<String> {
    data.get(key)
        .map(String::as_str)
        .and_then(OptionalText::normalize_value)
}

fn thing_name_from_attrs(data: &HashMap<String, String>) -> Option<String> {
    let raw = data.get("attrs")?;
    let object = serde_json::from_str::<serde_json::Map<String, JsonValue>>(raw).ok()?;
    for key in ["name", "thing_name", "名称"] {
        if let Some(value) = object.get(key)
            && let Some(text) = json_scalar_text(value)
        {
            return Some(text);
        }
    }
    None
}

fn gateway_fallback_body(data: &HashMap<String, String>, entity_type: &str) -> Option<String> {
    let action = map_text(data, "domain_action").unwrap_or_else(|| "update".to_string());
    Some(format!(
        "Gateway generated {entity_type} {action} notification"
    ))
}

fn json_scalar_text(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(text) => normalize_optional_text(Some(text)),
        JsonValue::Number(number) => Some(number.to_string()),
        JsonValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn first_image_url(data: &HashMap<String, String>) -> Option<String> {
    let raw = data.get("images")?;
    let values = serde_json::from_str::<Vec<String>>(raw).ok()?;
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}
