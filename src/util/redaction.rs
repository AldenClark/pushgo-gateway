use std::fmt;

use super::runtime_flags::is_sandbox_mode;

pub fn redact_text(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if is_sandbox_mode() {
        return value.to_string();
    }
    mask_middle(value, 4, 4)
}

pub fn redact_debug<T: ?Sized + fmt::Debug>(value: &T) -> String {
    if is_sandbox_mode() {
        return format!("{value:?}");
    }
    "<redacted>".to_string()
}

fn mask_middle(value: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    if value.is_empty() {
        return "<empty>".to_string();
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= keep_prefix + keep_suffix {
        return "<redacted>".to_string();
    }
    let prefix: String = chars.iter().take(keep_prefix).collect();
    let suffix: String = chars
        .iter()
        .rev()
        .take(keep_suffix)
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn redact_text_masks_sensitive_values_by_default() {
        crate::util::set_sandbox_mode(false);
        let raw = "secret-token-value-1234567890";
        let redacted = super::redact_text(raw);

        assert_ne!(redacted, raw);
        assert!(redacted.starts_with("secr"));
        assert!(redacted.ends_with("7890"));
        assert!(!redacted.contains("token-value-123456"));
    }

    #[test]
    fn redact_text_does_not_expose_short_values() {
        crate::util::set_sandbox_mode(false);
        assert_eq!(super::redact_text("short"), "<redacted>");
        assert_eq!(super::redact_text(""), "<empty>");
    }
}
