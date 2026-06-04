use std::collections::BTreeMap;

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{api::Error, storage::ThingState, value::ExternalIdKey};

use super::{ThingCommandKind, ThingPatchFields, ThingProfile};

impl ThingCommandKind {
    pub(super) fn state_patch(self) -> Option<ThingState> {
        match self {
            ThingCommandKind::Create => Some(ThingState::Active),
            ThingCommandKind::Update => None,
            ThingCommandKind::Archive => Some(ThingState::Inactive),
            ThingCommandKind::Delete => Some(ThingState::Decommissioned),
        }
    }

    pub(super) fn notification_label(self) -> &'static str {
        match self {
            ThingCommandKind::Create => "创建",
            ThingCommandKind::Update => "更新",
            ThingCommandKind::Archive => "存档",
            ThingCommandKind::Delete => "删除",
        }
    }

    pub(super) fn build_notification_content(
        self,
        patch: &ThingPatchFields,
        profile: Option<&ThingProfile>,
        normalized_description: Option<String>,
    ) -> (Option<String>, Option<String>) {
        let requested_title = patch
            .title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let requested_body = normalized_description;
        let fallback_title = profile
            .and_then(|current| current.title.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        let title_raw = match self {
            ThingCommandKind::Create => requested_title,
            ThingCommandKind::Update | ThingCommandKind::Archive | ThingCommandKind::Delete => {
                requested_title.or(fallback_title)
            }
        };
        let title = title_raw.map(|value| format!("{}: {value}", self.notification_label()));
        let body = match self {
            ThingCommandKind::Create => requested_body,
            ThingCommandKind::Update | ThingCommandKind::Archive | ThingCommandKind::Delete => {
                requested_body.or_else(|| patch.attrs.as_ref().and_then(attrs_summary_lines))
            }
        };
        (title, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thing_update_does_not_patch_state() {
        assert_eq!(ThingCommandKind::Update.state_patch(), None);
        assert_eq!(
            ThingCommandKind::Create.state_patch(),
            Some(ThingState::Active)
        );
        assert_eq!(
            ThingCommandKind::Archive.state_patch(),
            Some(ThingState::Inactive)
        );
        assert_eq!(
            ThingCommandKind::Delete.state_patch(),
            Some(ThingState::Decommissioned)
        );
    }
}

impl ThingProfile {
    pub(super) fn push_unique_image(&mut self, value: &str) {
        if self.primary_image.as_deref() == Some(value) {
            return;
        }
        if !self.images.iter().any(|item| item == value) {
            self.images.push(value.to_string());
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.description.is_none()
            && self.tags.is_empty()
            && self.primary_image.is_none()
            && self.images.is_empty()
            && self.created_at.is_none()
            && self.state.is_none()
            && self.deleted_at.is_none()
            && self.external_ids.is_empty()
            && self.location.is_none()
    }
}

pub(super) struct ExternalIdPatchRef<'a>(&'a JsonMap<String, JsonValue>);

impl<'a> ExternalIdPatchRef<'a> {
    pub(super) fn new(patch: &'a JsonMap<String, JsonValue>) -> Self {
        Self(patch)
    }

    pub(super) fn validate(&self) -> Result<(), Error> {
        for (key, value) in self.0 {
            Self::normalize_key(key)?;
            match value {
                JsonValue::Null => {}
                JsonValue::String(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        return Err(Error::validation_code(
                            "external_ids contains empty value",
                            "external_ids_value_required",
                        ));
                    }
                    if trimmed.len() > 256 {
                        return Err(Error::validation_code(
                            "external_ids contains oversized value",
                            "external_ids_value_too_long",
                        ));
                    }
                }
                _ => {
                    return Err(Error::validation_code(
                        "external_ids only supports string or null values",
                        "external_ids_value_invalid",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply_to(&self, target: &mut BTreeMap<String, String>) -> Result<(), Error> {
        for (key, value) in self.0 {
            let normalized_key = Self::normalize_key(key)?;
            match value {
                JsonValue::Null => {
                    target.remove(&normalized_key);
                }
                JsonValue::String(raw) => {
                    target.insert(normalized_key, raw.trim().to_string());
                }
                _ => {
                    return Err(Error::validation_code(
                        "external_ids only supports string or null values",
                        "external_ids_value_invalid",
                    ));
                }
            }
        }
        Ok(())
    }

    fn normalize_key(raw: &str) -> Result<String, Error> {
        Ok(ExternalIdKey::parse(raw)?.into_inner())
    }
}

pub(super) fn thing_state_api_text(state: ThingState) -> &'static str {
    match state {
        ThingState::Active => "active",
        ThingState::Inactive => "archived",
        ThingState::Decommissioned => "deleted",
    }
}

pub(super) fn validate_manufacturer_attrs(
    object: &JsonMap<String, JsonValue>,
) -> Result<(), Error> {
    let Some(value) = object.get("manufacturer") else {
        return Ok(());
    };
    match value {
        JsonValue::Null => Ok(()),
        JsonValue::Object(inner) => {
            for key in inner.keys() {
                let trimmed = key.trim();
                if trimmed.is_empty() {
                    return Err(Error::validation_code(
                        "attrs.manufacturer contains empty key",
                        "manufacturer_attr_key_required",
                    ));
                }
                if trimmed.len() > 64 {
                    return Err(Error::validation_code(
                        "attrs.manufacturer contains oversized key",
                        "manufacturer_attr_key_too_long",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(Error::validation_code(
            "attrs.manufacturer must be object or null",
            "manufacturer_attr_invalid",
        )),
    }
}

fn attrs_summary_lines(attrs: &JsonMap<String, JsonValue>) -> Option<String> {
    if attrs.is_empty() {
        return None;
    }
    let mut keys: Vec<&String> = attrs.keys().collect();
    keys.sort();
    let mut lines = Vec::with_capacity(attrs.len());
    for key in keys {
        let Some(value) = attrs.get(key) else {
            continue;
        };
        lines.push(format!("{key}={}", attr_value_text(value)));
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn attr_value_text(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(v) => v.to_string(),
        JsonValue::Number(v) => v.to_string(),
        JsonValue::String(v) => v.to_string(),
        JsonValue::Object(_) | JsonValue::Array(_) => {
            serde_json::to_string(value).unwrap_or_default()
        }
    }
}
