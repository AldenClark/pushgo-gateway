use std::collections::BTreeMap;

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{api::Error, storage::ThingState};

use super::{ThingIntent, ThingLocation, ThingProfile, ThingRouteAction};

impl ThingRouteAction {
    pub(super) fn resolved_state(self) -> ThingState {
        match self {
            ThingRouteAction::Create | ThingRouteAction::Update => ThingState::Active,
            ThingRouteAction::Archive => ThingState::Inactive,
            ThingRouteAction::Delete => ThingState::Decommissioned,
        }
    }

    pub(super) fn notification_label(self) -> &'static str {
        match self {
            ThingRouteAction::Create => "创建",
            ThingRouteAction::Update => "更新",
            ThingRouteAction::Archive => "存档",
            ThingRouteAction::Delete => "删除",
        }
    }

    pub(super) fn build_notification_content(
        self,
        payload: &ThingIntent,
        profile: Option<&ThingProfile>,
        normalized_description: Option<String>,
    ) -> (Option<String>, Option<String>) {
        let requested_title = payload
            .payload
            .mutable
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
            ThingRouteAction::Create => requested_title,
            ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete => {
                requested_title.or(fallback_title)
            }
        };
        let title = title_raw.map(|value| format!("{}: {value}", self.notification_label()));
        let body = match self {
            ThingRouteAction::Create => requested_body,
            ThingRouteAction::Update | ThingRouteAction::Archive | ThingRouteAction::Delete => {
                requested_body.or_else(|| attrs_summary_lines(&payload.payload.mutable.attrs))
            }
        };
        (title, body)
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
                        return Err(Error::validation("external_ids contains empty value"));
                    }
                    if trimmed.len() > 256 {
                        return Err(Error::validation("external_ids contains oversized value"));
                    }
                }
                _ => {
                    return Err(Error::validation(
                        "external_ids only supports string or null values",
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
                    return Err(Error::validation(
                        "external_ids only supports string or null values",
                    ));
                }
            }
        }
        Ok(())
    }

    fn normalize_key(raw: &str) -> Result<String, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("external_ids contains empty key"));
        }
        if trimmed.len() > 64 {
            return Err(Error::validation("external_ids contains oversized key"));
        }
        if !trimmed.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == ':' || ch == '.'
        }) {
            return Err(Error::validation("external_ids key format is invalid"));
        }
        Ok(trimmed.to_ascii_lowercase())
    }
}

impl ThingLocation {
    pub(super) fn normalize_patch(
        location_type: Option<&str>,
        location_value: Option<&str>,
    ) -> Result<Option<Self>, Error> {
        match (location_type, location_value) {
            (None, None) => Ok(None),
            (Some(_), None) | (None, Some(_)) => Err(Error::validation(
                "location_type and location_value must be provided together",
            )),
            (Some(raw_type), Some(raw_value)) => {
                let normalized_type = raw_type.trim().to_ascii_lowercase();
                let normalized_value = match normalized_type.as_str() {
                    "physical" => Self::normalize_physical(raw_value)?,
                    "geo" => Self::normalize_geo(raw_value)?,
                    "cloud" => Self::normalize_cloud(raw_value)?,
                    "datacenter" => Self::normalize_datacenter(raw_value)?,
                    "logical" => Self::normalize_logical(raw_value)?,
                    _ => {
                        return Err(Error::validation(
                            "location_type must be one of physical|geo|cloud|datacenter|logical",
                        ));
                    }
                };
                Ok(Some(Self {
                    location_type: normalized_type,
                    value: normalized_value,
                }))
            }
        }
    }

    fn normalize_physical(raw: &str) -> Result<String, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("location_value must not be empty"));
        }
        if trimmed.len() > 256 {
            return Err(Error::validation("location_value is too long"));
        }
        Ok(trimmed.to_string())
    }

    fn normalize_geo(raw: &str) -> Result<String, Error> {
        let trimmed = raw.trim();
        let Some((raw_lat, raw_lng)) = trimmed.split_once(',') else {
            return Err(Error::validation(
                "geo location_value must be formatted as <lat>,<lng>",
            ));
        };
        let lat = raw_lat
            .trim()
            .parse::<f64>()
            .map_err(|_| Error::validation("geo lat must be a number"))?;
        let lng = raw_lng
            .trim()
            .parse::<f64>()
            .map_err(|_| Error::validation("geo lng must be a number"))?;
        if !((-90.0)..=90.0).contains(&lat) {
            return Err(Error::validation("geo lat out of range"));
        }
        if !((-180.0)..=180.0).contains(&lng) {
            return Err(Error::validation("geo lng out of range"));
        }
        Ok(format!("{lat:.6},{lng:.6}"))
    }

    fn normalize_cloud(raw: &str) -> Result<String, Error> {
        let trimmed = raw.trim();
        let parts: Vec<&str> = trimmed.split(':').collect();
        if !(2..=3).contains(&parts.len()) {
            return Err(Error::validation(
                "cloud location_value must be provider:region[:zone]",
            ));
        }
        if parts.iter().any(|part| !Self::is_token(part)) {
            return Err(Error::validation(
                "cloud location_value token format is invalid",
            ));
        }
        Ok(parts.join(":").to_ascii_lowercase())
    }

    fn normalize_datacenter(raw: &str) -> Result<String, Error> {
        let trimmed = raw.trim();
        let parts: Vec<&str> = trimmed.split(':').collect();
        if !(1..=3).contains(&parts.len()) {
            return Err(Error::validation(
                "datacenter location_value must be site[:room[:rack]]",
            ));
        }
        if parts.iter().any(|part| !Self::is_token(part)) {
            return Err(Error::validation(
                "datacenter location_value token format is invalid",
            ));
        }
        Ok(parts.join(":").to_ascii_lowercase())
    }

    fn normalize_logical(raw: &str) -> Result<String, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("location_value must not be empty"));
        }
        if trimmed.len() > 256 {
            return Err(Error::validation("location_value is too long"));
        }
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.iter().any(|part| !Self::is_token(part)) {
            return Err(Error::validation(
                "logical location_value must be slash-separated tokens",
            ));
        }
        Ok(parts.join("/").to_ascii_lowercase())
    }

    fn is_token(raw: &str) -> bool {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return false;
        }
        trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
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
                    return Err(Error::validation("attrs.manufacturer contains empty key"));
                }
                if trimmed.len() > 64 {
                    return Err(Error::validation(
                        "attrs.manufacturer contains oversized key",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(Error::validation(
            "attrs.manufacturer must be object or null",
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
