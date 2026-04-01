use crate::api::{ChannelId, ChannelPassword};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChannelBinding {
    channel_id: ChannelId,
    channel_id_text: String,
    password: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ChannelBindingList(Vec<ChannelBinding>);

impl ChannelBinding {
    fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let mut parts = trimmed.splitn(2, ',');
        let channel_id = parts.next().map(str::trim)?;
        let password = parts.next().map(str::trim)?;
        if channel_id.is_empty() || password.is_empty() {
            return None;
        }
        let channel_id = ChannelId::parse(channel_id).ok()?;
        let password = ChannelPassword::parse(password).ok()?;
        Some(Self {
            channel_id,
            channel_id_text: channel_id.to_string(),
            password: password.as_str().to_string(),
        })
    }
}

impl ChannelBindingList {
    fn parse(raw: Option<&str>) -> Self {
        let mut out = Vec::new();
        let Some(raw) = raw else {
            return Self(out);
        };
        for line in raw.lines() {
            if let Some(binding) = ChannelBinding::parse(line) {
                out.push(binding);
            }
        }
        Self(out)
    }

    fn iter(&self) -> impl Iterator<Item = &ChannelBinding> {
        self.0.iter()
    }

    fn into_vec(self) -> Vec<ChannelBinding> {
        self.0
    }
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn ensure_scope(auth: &McpAuthContext, required_scope: McpScope) -> Result<(), String> {
    let McpAuthContext::OAuth { scope, .. } = auth else {
        return Ok(());
    };
    if scope.contains(required_scope) {
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
        || path == "/.well-known/oauth-authorization-server/oauth"
        || path == "/oauth/.well-known/oauth-authorization-server"
        || path == "/.well-known/openid-configuration"
        || path == "/.well-known/openid-configuration/oauth"
        || path == "/oauth/.well-known/openid-configuration"
        || path == "/.well-known/oauth-protected-resource"
        || path == "/.well-known/oauth-protected-resource/mcp"
}

#[cfg(test)]
mod tests {
    use super::{ChannelBindingList, McpScope, McpScopeSet, ensure_scope};
    use crate::mcp::core_auth::McpAuthContext;
    use crate::mcp::core_types::PkceMethod;

    #[test]
    fn verify_pkce_plain() {
        assert!(PkceMethod::Plain.verify("abc", "abc"));
        assert!(!PkceMethod::Plain.verify("abc", "def"));
    }

    #[test]
    fn verify_pkce_s256() {
        // RFC 7636 example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(PkceMethod::S256.verify(challenge, verifier));
    }

    #[test]
    fn channel_binding_list_ignores_invalid_lines() {
        let bindings = ChannelBindingList::parse(Some("ch1,pw1\ninvalid\nch2,pw2\n,pw3\n"));
        assert_eq!(bindings.into_vec().len(), 0);
    }

    #[test]
    fn channel_binding_list_keeps_valid_typed_bindings() {
        let bindings = ChannelBindingList::parse(Some(
            "06J0FZG1Y8XGG14VTQ4Y3G10MR,pass-1234\n06J0FZG1Y8XGG14VTQ4Y3G10MR,pass-9999",
        ));
        let bindings = bindings.into_vec();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].channel_id_text, "06J0FZG1Y8XGG14VTQ4Y3G10MR");
        assert_eq!(bindings[0].password, "pass-1234");
    }

    #[test]
    fn ensure_scope_uses_typed_scope_set() {
        let auth = McpAuthContext::OAuth {
            principal_id: "pr-1".to_string(),
            scope: McpScopeSet::parse("mcp:tools").expect("scope should parse"),
        };
        assert!(ensure_scope(&auth, McpScope::Tools).is_ok());
        assert!(ensure_scope(&auth, McpScope::ChannelsManage).is_err());
    }
}
