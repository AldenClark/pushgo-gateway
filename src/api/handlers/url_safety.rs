use std::net::IpAddr;

use reqwest::Url;

const MAX_URL_LEN: usize = 2048;

pub(crate) fn sanitize_open_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN || trimmed.chars().any(char::is_control) {
        return None;
    }
    if contains_blocked_encoded_scheme(trimmed) {
        return None;
    }

    if let Ok(parsed) = Url::parse(trimmed) {
        return is_allowed_open_url(&parsed).then(|| parsed.to_string());
    }

    let host_candidate = trimmed
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    if !looks_like_host(host_candidate) {
        return None;
    }
    let upgraded = format!("https://{trimmed}");
    let parsed = Url::parse(upgraded.as_str()).ok()?;
    is_allowed_open_url(&parsed).then(|| parsed.to_string())
}

pub(crate) fn sanitize_image_url(raw: &str) -> Option<String> {
    let normalized = sanitize_open_url(raw)?;
    let parsed = Url::parse(normalized.as_str()).ok()?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return None;
    }
    let host = parsed.host_str()?;
    if is_blocked_remote_host(host) {
        return None;
    }
    Some(parsed.to_string())
}

pub(crate) fn sanitize_image_urls(values: &[String], field: &str) -> Result<Vec<String>, String> {
    const MAX_IMAGES: usize = 32;
    if values.len() > MAX_IMAGES {
        return Err(format!("{field} exceeds max length"));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(format!("{field} contains empty url"));
        }
        if trimmed.len() > MAX_URL_LEN {
            return Err(format!("{field} contains oversized url"));
        }
        let Some(safe) = sanitize_image_url(trimmed) else {
            return Err(format!("{field} contains invalid or unsafe url"));
        };
        if !out.iter().any(|item| item == &safe) {
            out.push(safe);
        }
    }
    Ok(out)
}

pub(crate) fn sanitize_optional_open_url(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_URL_LEN {
        return Err(format!("{field} contains oversized url"));
    }
    let Some(safe) = sanitize_open_url(trimmed) else {
        return Err(format!("{field} contains invalid or unsafe url"));
    };
    Ok(Some(safe))
}

pub(crate) fn rewrite_visible_urls_in_text(raw: &str) -> String {
    if raw.is_empty() || !raw.contains("](") {
        return raw.to_string();
    }

    let bytes = raw.as_bytes();
    let mut cursor = 0usize;
    let mut copy_start = 0usize;
    let mut out = String::with_capacity(raw.len());

    while cursor + 1 < bytes.len() {
        if bytes[cursor] == b']' && bytes[cursor + 1] == b'(' {
            let destination_start = cursor + 2;
            let mut end = destination_start;
            let mut paren_depth = 0usize;
            while end < bytes.len() {
                match bytes[end] {
                    b'(' => paren_depth += 1,
                    b')' if paren_depth == 0 => break,
                    b')' => paren_depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            if end >= bytes.len() {
                break;
            }
            out.push_str(&raw[copy_start..destination_start]);
            let destination = &raw[destination_start..end];
            out.push_str(&rewrite_markdown_destination(destination));
            out.push(')');
            cursor = end + 1;
            copy_start = cursor;
            continue;
        }
        cursor += 1;
    }

    if copy_start == 0 {
        return raw.to_string();
    }
    out.push_str(&raw[copy_start..]);
    out
}

fn rewrite_markdown_destination(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return raw.to_string();
    }

    let leading = raw.find(|ch: char| !ch.is_whitespace()).unwrap_or(0);
    let trailing_exclusive = raw
        .rfind(|ch: char| !ch.is_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(raw.len());
    let inner = &raw[leading..trailing_exclusive];
    let token_end = inner.find(char::is_whitespace).unwrap_or(inner.len());
    let token = &inner[..token_end];
    let suffix = &inner[token_end..];
    let unwrapped = token
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(token);

    let rewritten = if let Some(safe) = sanitize_open_url(unwrapped) {
        if token.starts_with('<') && token.ends_with('>') {
            format!("<{safe}>")
        } else {
            safe
        }
    } else if looks_like_url_token(unwrapped) {
        "#".to_string()
    } else {
        token.to_string()
    };

    let mut result = String::with_capacity(raw.len() + 8);
    result.push_str(&raw[..leading]);
    result.push_str(&rewritten);
    result.push_str(suffix);
    result.push_str(&raw[trailing_exclusive..]);
    result
}

fn looks_like_url_token(raw: &str) -> bool {
    raw.contains(':') || raw.starts_with("www.")
}

fn is_allowed_open_url(url: &Url) -> bool {
    let scheme = url.scheme().to_ascii_lowercase();
    if matches!(
        scheme.as_str(),
        "javascript" | "data" | "file" | "content" | "intent" | "vbscript"
    ) {
        return false;
    }
    if !matches!(
        scheme.as_str(),
        "http" | "https" | "ftp" | "ftps" | "mailto" | "tel" | "sms" | "app" | "pushgo"
    ) {
        return false;
    }
    if matches!(scheme.as_str(), "http" | "https" | "ftp" | "ftps") {
        if url.host_str().is_none() {
            return false;
        }
        if !url.username().is_empty() || url.password().is_some() {
            return false;
        }
    }
    true
}

fn looks_like_host(value: &str) -> bool {
    value.contains('.')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')
}

fn contains_blocked_encoded_scheme(raw: &str) -> bool {
    let mut candidate = raw.to_string();
    for _ in 0..3 {
        if starts_with_blocked_scheme(candidate.as_str()) {
            return true;
        }
        let decoded = percent_decode_once(candidate.as_str());
        if decoded == candidate {
            break;
        }
        candidate = decoded;
    }
    starts_with_blocked_scheme(candidate.as_str())
}

fn starts_with_blocked_scheme(raw: &str) -> bool {
    let Some(scheme) = leading_scheme_token(raw) else {
        return false;
    };
    matches!(
        scheme.as_str(),
        "javascript" | "data" | "file" | "content" | "intent" | "vbscript"
    )
}

fn leading_scheme_token(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let mut token = String::new();
    let mut saw_colon = false;
    for ch in trimmed.chars() {
        if ch == ':' {
            saw_colon = true;
            break;
        }
        if ch.is_whitespace() || ch.is_control() {
            continue;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.') {
            token.push(ch.to_ascii_lowercase());
            if token.len() > 32 {
                return None;
            }
            continue;
        }
        return None;
    }
    if !saw_colon || token.is_empty() {
        return None;
    }
    Some(token)
}

fn percent_decode_once(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'%'
            && idx + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[idx + 1]), hex_value(bytes[idx + 2]))
        {
            out.push((hi << 4) | lo);
            idx += 3;
            continue;
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    String::from_utf8_lossy(out.as_slice()).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_blocked_remote_host(host: &str) -> bool {
    let normalized = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if normalized.is_empty() {
        return true;
    }
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return true;
    }
    match normalized.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => is_blocked_ipv4(ip.octets()),
        Ok(IpAddr::V6(ip)) => is_blocked_ipv6(ip.octets()),
        Err(_) => false,
    }
}

fn is_blocked_ipv4(octets: [u8; 4]) -> bool {
    let b0 = octets[0];
    let b1 = octets[1];
    if b0 == 0 || b0 == 10 || b0 == 127 {
        return true;
    }
    if b0 == 169 && b1 == 254 {
        return true;
    }
    if b0 == 172 && (16..=31).contains(&b1) {
        return true;
    }
    if b0 == 192 && b1 == 168 {
        return true;
    }
    if b0 == 100 && (64..=127).contains(&b1) {
        return true;
    }
    if b0 >= 224 {
        return true;
    }
    false
}

fn is_blocked_ipv6(octets: [u8; 16]) -> bool {
    if octets.iter().all(|byte| *byte == 0) {
        return true;
    }
    if octets[..15].iter().all(|byte| *byte == 0) && octets[15] == 1 {
        return true;
    }
    let b0 = octets[0];
    let b1 = octets[1];
    if b0 == 0xFE && (b1 & 0xC0) == 0x80 {
        return true;
    }
    if (b0 & 0xFE) == 0xFC {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{rewrite_visible_urls_in_text, sanitize_image_url, sanitize_open_url};

    #[test]
    fn sanitize_open_url_blocks_encoded_schemes() {
        assert!(sanitize_open_url("javascript:alert(1)").is_none());
        assert!(sanitize_open_url("%6a%61%76%61%73%63%72%69%70%74:alert(1)").is_none());
        assert!(sanitize_open_url("intent://scan/#Intent;scheme=zxing;end").is_none());
    }

    #[test]
    fn sanitize_image_url_blocks_localhost() {
        assert!(sanitize_image_url("https://localhost/a.png").is_none());
        assert!(sanitize_image_url("https://127.0.0.1/a.png").is_none());
        assert!(sanitize_image_url("https://cdn.example.com/a.png").is_some());
    }

    #[test]
    fn rewrite_markdown_destinations() {
        let rewritten = rewrite_visible_urls_in_text("[x](javascript:alert(1)) ok");
        assert_eq!(rewritten, "[x](#) ok");
    }

    #[test]
    fn sanitize_open_url_allows_expected_protocols() {
        assert_eq!(
            sanitize_open_url("https://example.com/path?q=1"),
            Some("https://example.com/path?q=1".to_string())
        );
        assert_eq!(
            sanitize_open_url("example.com/path"),
            Some("https://example.com/path".to_string())
        );
        assert_eq!(
            sanitize_open_url("ftp://example.com/file.txt"),
            Some("ftp://example.com/file.txt".to_string())
        );
        assert_eq!(
            sanitize_open_url("pushgo://message/123"),
            Some("pushgo://message/123".to_string())
        );
    }

    #[test]
    fn sanitize_open_url_rejects_unsafe_or_invalid_inputs() {
        assert!(sanitize_open_url("data:text/html;base64,PHNj").is_none());
        assert!(sanitize_open_url("https://user:pass@example.com").is_none());
        assert!(sanitize_open_url("http://").is_none());
        assert!(sanitize_open_url("not-a-link").is_none());
        assert!(sanitize_open_url(" ").is_none());
    }

    #[test]
    fn sanitize_image_url_rejects_non_remote_or_unsafe_hosts() {
        assert!(sanitize_image_url("ftp://cdn.example.com/a.png").is_none());
        assert!(sanitize_image_url("http://192.168.1.10/a.png").is_none());
        assert!(sanitize_image_url("http://[::1]/a.png").is_none());
        assert_eq!(
            sanitize_image_url("https://cdn.example.com/a.png"),
            Some("https://cdn.example.com/a.png".to_string())
        );
    }

    #[test]
    fn rewrite_markdown_destinations_keeps_safe_and_blocks_unsafe() {
        let rewritten = rewrite_visible_urls_in_text(
            "[ok](https://example.com) [bad](javascript:alert(1)) [raw](www.example.com)",
        );
        assert_eq!(
            rewritten,
            "[ok](https://example.com/) [bad](#) [raw](https://www.example.com/)"
        );
    }

    #[test]
    fn rewrite_markdown_destinations_handles_nested_parentheses() {
        let rewritten = rewrite_visible_urls_in_text("[x](javascript:alert(1)) trailing");
        assert_eq!(rewritten, "[x](#) trailing");
    }

    #[test]
    fn rewrite_markdown_destinations_keeps_angle_wrapped_safe_link() {
        let rewritten = rewrite_visible_urls_in_text("[ok](<https://example.com/path>)");
        assert_eq!(rewritten, "[ok](<https://example.com/path>)");
    }
}
