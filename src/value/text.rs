use super::{ValueError, ValueResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedTags(Vec<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedImageUrls(Vec<String>);

pub(crate) struct OptionalText;

pub(crate) struct OptionalUrl;

impl NormalizedTags {
    pub(crate) fn parse(values: &[String], field: &'static str) -> ValueResult<Self> {
        Ok(Self(normalize_text_list(values, field, 32, 64, "tag")?))
    }

    pub(crate) fn into_inner(self) -> Vec<String> {
        self.0
    }
}

impl NormalizedImageUrls {
    pub(crate) fn parse(values: &[String], field: &'static str) -> ValueResult<Self> {
        Ok(Self(normalize_text_list(values, field, 32, 2048, "url")?))
    }

    pub(crate) fn into_inner(self) -> Vec<String> {
        self.0
    }
}

impl OptionalUrl {
    pub(crate) fn normalize(raw: Option<&str>, field: &'static str) -> ValueResult<Option<String>> {
        const MAX_URL_LEN: usize = 2048;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if trimmed.len() > MAX_URL_LEN {
            return Err(ValueError::new(format!("{field} contains oversized url")));
        }
        Ok(Some(trimmed.to_string()))
    }
}

impl OptionalText {
    pub(crate) fn normalize(raw: Option<&str>) -> Option<String> {
        raw.and_then(Self::normalize_value)
    }

    pub(crate) fn normalize_owned(raw: Option<String>) -> Option<String> {
        raw.as_deref().and_then(Self::normalize_value)
    }

    pub(crate) fn normalize_value(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

fn normalize_text_list(
    values: &[String],
    field: &'static str,
    max_items: usize,
    max_len: usize,
    item_label: &'static str,
) -> ValueResult<Vec<String>> {
    if values.len() > max_items {
        return Err(ValueError::new(format!("{field} exceeds max length")));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new(format!(
                "{field} contains empty {item_label}"
            )));
        }
        if trimmed.len() > max_len {
            return Err(ValueError::new(format!(
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
    use super::OptionalText;

    #[test]
    fn optional_text_trims_and_drops_blank_values() {
        assert_eq!(
            OptionalText::normalize(Some("  body  ")),
            Some("body".to_string())
        );
        assert_eq!(
            OptionalText::normalize_owned(Some("  body  ".to_string())),
            Some("body".to_string())
        );
        assert_eq!(OptionalText::normalize(Some("   ")), None);
        assert_eq!(OptionalText::normalize_owned(Some("   ".to_string())), None);
        assert_eq!(OptionalText::normalize(None), None);
        assert_eq!(OptionalText::normalize_owned(None), None);
    }
}
