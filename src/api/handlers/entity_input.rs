use crate::api::Error;
use serde_json::{Map as JsonMap, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntityId(String);

impl EntityId {
    pub(crate) fn parse(raw: &str, field: &str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation(format!("{field} must not be empty")));
        }
        if trimmed.len() > 64 {
            return Err(Error::validation(format!("{field} is too long")));
        }
        if !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
        {
            return Err(Error::validation(format!("{field} format is invalid")));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedTags(Vec<String>);

impl NormalizedTags {
    pub(crate) fn parse(values: &[String], field: &str) -> Result<Self, Error> {
        Ok(Self(normalize_text_list(values, field, 32, 64, "tag")?))
    }

    pub(crate) fn into_inner(self) -> Vec<String> {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedImageUrls(Vec<String>);

impl NormalizedImageUrls {
    pub(crate) fn parse(values: &[String], field: &str) -> Result<Self, Error> {
        Ok(Self(normalize_text_list(values, field, 32, 2048, "url")?))
    }

    pub(crate) fn into_inner(self) -> Vec<String> {
        self.0
    }
}

pub(crate) struct MetadataEntries<'a>(&'a JsonMap<String, Value>);

impl<'a> MetadataEntries<'a> {
    pub(crate) fn new(metadata: &'a JsonMap<String, Value>) -> Self {
        Self(metadata)
    }

    pub(crate) fn parse_value(raw: Value) -> Result<JsonMap<String, Value>, String> {
        match raw {
            Value::Null => Ok(JsonMap::new()),
            Value::Object(object) => parse_metadata_object(object),
            _ => Err("metadata must be a JSON object".to_string()),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        let mut dedupe = std::collections::HashSet::new();
        for (raw_key, raw_value) in self.0 {
            let key = raw_key.trim();
            if key.is_empty() {
                return Err(Error::validation("metadata key must not be empty"));
            }
            if key.len() > 64 {
                return Err(Error::validation("metadata key is too long"));
            }
            if !dedupe.insert(key.to_string()) {
                return Err(Error::validation("metadata key must be unique"));
            }

            let value = metadata_scalar_text(raw_value)
                .ok_or_else(|| Error::validation("metadata value must be scalar"))?;
            if value.is_empty() {
                return Err(Error::validation("metadata value must not be empty"));
            }
            if value.len() > 512 {
                return Err(Error::validation("metadata value is too long"));
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<String, Error> {
        serde_json::to_string(self.0).map_err(|_| Error::validation("metadata format is invalid"))
    }
}

pub(crate) struct OptionalText;

impl OptionalText {
    pub(crate) fn normalize(raw: Option<&str>) -> Option<String> {
        raw.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        })
    }
}

pub(crate) struct OptionalUrl;

impl OptionalUrl {
    pub(crate) fn normalize(raw: Option<&str>, field: &str) -> Result<Option<String>, Error> {
        const MAX_URL_LEN: usize = 2048;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if trimmed.len() > MAX_URL_LEN {
            return Err(Error::validation(format!("{field} contains oversized url")));
        }
        Ok(Some(trimmed.to_string()))
    }
}

pub(crate) struct ExtensionObjectRef<'a> {
    object: &'a JsonMap<String, Value>,
    field: &'a str,
}

impl<'a> ExtensionObjectRef<'a> {
    pub(crate) fn new(object: &'a JsonMap<String, Value>, field: &'a str) -> Self {
        Self { object, field }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        for (key, value) in self.object {
            if key.trim().is_empty() {
                return Err(Error::validation(format!(
                    "{} contains empty key",
                    self.field
                )));
            }
            match value {
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
                Value::Object(inner) => {
                    for inner_value in inner.values() {
                        match inner_value {
                            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
                            _ => {
                                return Err(Error::validation(format!(
                                    "{} only supports one-level objects",
                                    self.field
                                )));
                            }
                        }
                    }
                }
                Value::Array(_) => {
                    return Err(Error::validation(format!(
                        "{} does not support arrays",
                        self.field
                    )));
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct ObjectPatchRef<'a>(&'a JsonMap<String, Value>);

impl<'a> ObjectPatchRef<'a> {
    pub(crate) fn new(patch: &'a JsonMap<String, Value>) -> Self {
        Self(patch)
    }

    pub(crate) fn apply_to(&self, target: &mut JsonMap<String, Value>) {
        for (key, value) in self.0 {
            if value.is_null() {
                target.remove(key);
            } else {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

fn parse_metadata_object(object: JsonMap<String, Value>) -> Result<JsonMap<String, Value>, String> {
    let mut out = JsonMap::new();
    for (raw_key, raw_value) in object {
        let key = raw_key.trim();
        if key.is_empty() {
            return Err("metadata key must not be empty".to_string());
        }
        if metadata_scalar_text(&raw_value).is_none() {
            return Err(format!("metadata.{key} must be a scalar"));
        }
        if out.insert(key.to_string(), raw_value).is_some() {
            return Err("metadata key must be unique".to_string());
        }
    }
    Ok(out)
}

fn metadata_scalar_text(raw: &Value) -> Option<String> {
    match raw {
        Value::String(value) => {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        }
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn normalize_text_list(
    values: &[String],
    field: &str,
    max_items: usize,
    max_len: usize,
    item_label: &str,
) -> Result<Vec<String>, Error> {
    if values.len() > max_items {
        return Err(Error::validation(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(Error::validation(format!(
                "{field} contains empty {item_label}"
            )));
        }
        if trimmed.len() > max_len {
            return Err(Error::validation(format!(
                "{field} contains oversized {item_label}"
            )));
        }
        if !out.iter().any(|item| item == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entity_id_rejects_invalid_characters() {
        let err = EntityId::parse("thing with spaces", "thing_id")
            .expect_err("entity id should reject whitespace");
        assert!(err.to_string().contains("thing_id format is invalid"));
    }

    #[test]
    fn normalized_tags_deduplicates_values() {
        let tags = NormalizedTags::parse(
            &["a".to_string(), " a ".to_string(), "b".to_string()],
            "tags",
        )
        .expect("tags should parse");
        assert_eq!(tags.into_inner(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn metadata_rejects_nested_values() {
        let metadata = JsonMap::from_iter([("nested".to_string(), json!({"a": 1}))]);
        let err = MetadataEntries::new(&metadata)
            .validate()
            .expect_err("nested metadata should be rejected");
        assert!(err.to_string().contains("metadata value must be scalar"));
    }

    #[test]
    fn extension_object_rejects_arrays() {
        let attrs = JsonMap::from_iter([("bad".to_string(), json!(["x"]))]);
        let err = ExtensionObjectRef::new(&attrs, "attrs")
            .validate()
            .expect_err("arrays should be rejected");
        assert!(err.to_string().contains("attrs does not support arrays"));
    }
}
