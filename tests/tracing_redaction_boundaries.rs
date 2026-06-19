use std::{fs, path::Path};

const SOURCE_ROOTS: &[&str] = &[
    "src/api",
    "src/delivery_core",
    "src/dispatch",
    "src/mcp",
    "src/mqtt",
    "src/private",
    "src/services",
    "src/storage",
    "src/token_providers",
    "src/util",
];

const TRACE_MACROS: &[&str] = &[
    "::tracing::event!",
    "tracing::event!",
    "::tracing::info_span!",
    "tracing::info_span!",
    "::tracing::debug!",
    "tracing::debug!",
    "::tracing::warn!",
    "tracing::warn!",
    "::tracing::error!",
    "tracing::error!",
];

const SENSITIVE_FIELD_FRAGMENTS: &[&str] = &[
    "password",
    "token",
    "secret",
    "ciphertext",
    "metadata",
    "payload",
    "body",
    "title",
];

#[test]
fn tracing_calls_do_not_emit_sensitive_values_directly() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for root in SOURCE_ROOTS {
        scan_rust_files(&manifest_dir.join(root), &mut |path, contents| {
            for invocation in trace_invocations(contents) {
                inspect_trace_invocation(path, invocation, &mut violations);
            }
        });
    }

    assert!(
        violations.is_empty(),
        "tracing redaction boundary violations:\n{}",
        violations.join("\n")
    );
}

fn inspect_trace_invocation(path: &Path, invocation: &str, violations: &mut Vec<String>) {
    for line in invocation.lines() {
        let Some((field, expression)) = line.split_once('=') else {
            continue;
        };
        let field = field
            .trim()
            .trim_start_matches(',')
            .trim_start_matches('?')
            .trim_start_matches('%')
            .trim();
        let expression = expression.trim();
        if !is_sensitive_field(field) {
            continue;
        }
        if is_safe_sensitive_trace_expression(field, expression) {
            continue;
        }
        violations.push(format!(
            "{} logs sensitive field `{field}` without an explicit redaction/hash/presence guard: {}",
            path.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap_or(path)
                .display(),
            line.trim()
        ));
    }
}

fn is_sensitive_field(field: &str) -> bool {
    SENSITIVE_FIELD_FRAGMENTS
        .iter()
        .any(|fragment| field.contains(fragment))
}

fn is_safe_sensitive_trace_expression(field: &str, expression: &str) -> bool {
    if field == "event" || field.starts_with("has_") || field.starts_with("is_") {
        return true;
    }
    if expression.contains("redact_text")
        || expression.contains("redact_debug")
        || expression.contains("token_hash")
        || expression.contains("ProviderTokenSnapshot")
        || expression.contains("<redacted>")
    {
        return true;
    }
    let normalized = expression.trim_end_matches(',').trim();
    matches!(normalized, "true" | "false")
        || normalized.contains(".is_")
        || normalized.ends_with(".is_some())")
        || normalized.ends_with(".is_none())")
}

fn scan_rust_files(dir: &Path, visit: &mut impl FnMut(&Path, &str)) {
    for entry in fs::read_dir(dir).expect("source directory should be readable") {
        let entry = entry.expect("source entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            scan_rust_files(&path, visit);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let contents = fs::read_to_string(&path).expect("rust source should be utf-8");
            visit(&path, &contents);
        }
    }
}

fn trace_invocations(contents: &str) -> Vec<&str> {
    let mut invocations = Vec::new();
    let mut offset = 0;
    while offset < contents.len() {
        let Some((macro_offset, macro_name)) = next_trace_macro(&contents[offset..]) else {
            break;
        };
        let start = offset + macro_offset;
        let after_macro = start + macro_name.len();
        let Some(open_relative) = contents[after_macro..].find('(') else {
            break;
        };
        let open = after_macro + open_relative;
        let Some(close) = matching_paren(contents, open) else {
            break;
        };
        invocations.push(&contents[start..=close]);
        offset = close + 1;
    }
    invocations
}

fn next_trace_macro(contents: &str) -> Option<(usize, &'static str)> {
    TRACE_MACROS
        .iter()
        .filter_map(|macro_name| contents.find(macro_name).map(|index| (index, *macro_name)))
        .min_by_key(|(index, _)| *index)
}

fn matching_paren(contents: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (relative, ch) in contents[open..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + relative);
                }
            }
            _ => {}
        }
    }
    None
}
