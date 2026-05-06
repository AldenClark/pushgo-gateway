use crate::util::generate_hex_id_128;

use super::{ValueError, ValueResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntityId(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpId(String);

impl EntityId {
    pub(crate) fn parse(raw: &str, field: &'static str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new(format!("{field} must not be empty")));
        }
        if trimmed.len() > 64 {
            return Err(ValueError::new(format!("{field} is too long")));
        }
        if !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
        {
            return Err(ValueError::new(format!("{field} format is invalid")));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl OpId {
    pub(crate) fn parse(raw: &str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new("op_id must not be empty"));
        }
        if trimmed.len() > 128 {
            return Err(ValueError::new("op_id is too long"));
        }
        if !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
        {
            return Err(ValueError::new("op_id format is invalid"));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub(crate) fn resolve(raw: Option<&str>) -> ValueResult<Self> {
        match raw {
            Some(value) => Self::parse(value),
            None => Ok(Self(generate_hex_id_128())),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}
