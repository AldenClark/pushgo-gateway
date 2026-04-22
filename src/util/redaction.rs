use std::fmt;

use super::runtime_flags::is_sandbox_mode;

pub fn redact_text(value: &str) -> String {
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
