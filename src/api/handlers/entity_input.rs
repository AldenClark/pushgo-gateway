pub(crate) use crate::value::{EntityId, MetadataEntries};

#[cfg(test)]
pub(crate) use crate::value::{ExtensionObjectRef, NormalizedTags};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map as JsonMap, json};

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
