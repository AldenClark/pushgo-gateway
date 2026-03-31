fn parse_channel_bindings(raw: Option<&str>) -> Vec<ChannelBindingInput> {
    let mut out = Vec::new();
    let Some(raw) = raw else {
        return out;
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, ',');
        let Some(channel_id) = parts.next().map(str::trim) else {
            continue;
        };
        let Some(password) = parts.next().map(str::trim) else {
            continue;
        };
        if channel_id.is_empty() || password.is_empty() {
            continue;
        }
        out.push(ChannelBindingInput {
            channel_id: channel_id.to_string(),
            password: password.to_string(),
        });
    }
    out
}

struct ChannelBindingInput {
    channel_id: String,
    password: String,
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn ensure_scope(auth: &McpAuthContext, required_scope: &str) -> Result<(), String> {
    let McpAuthContext::OAuth { scope, .. } = auth else {
        return Ok(());
    };
    let ok = scope
        .split_whitespace()
        .any(|value| value.trim() == required_scope);
    if ok {
        Ok(())
    } else {
        Err("auth_forbidden_scope".to_string())
    }
}

pub(crate) fn is_mcp_or_oauth_path(path: &str) -> bool {
    path == "/mcp"
        || path.starts_with("/mcp/")
        || path.starts_with("/oauth/")
        || path == "/.well-known/oauth-authorization-server"
}

#[cfg(test)]
mod tests {
    use super::verify_pkce;

    #[test]
    fn verify_pkce_plain() {
        assert!(verify_pkce("abc", "plain", "abc"));
        assert!(!verify_pkce("abc", "plain", "def"));
    }

    #[test]
    fn verify_pkce_s256() {
        // RFC 7636 example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(challenge, "S256", verifier));
    }
}
