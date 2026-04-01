const MCP_UI_LOCALES_SUPPORTED: [&str; 2] = ["en", "zh-CN"];
const MCP_UI_DEFAULT_LOCALE: &str = "en";
const MCP_UI_LOCALE_QUERY_PARAMETER: &str = "lang";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpLocale {
    En,
    ZhCn,
}

impl McpLocale {
    fn from_request(lang: Option<&str>, ui_locales: Option<&str>) -> Self {
        if let Some(locale) = lang.and_then(Self::parse) {
            return locale;
        }
        ui_locales
            .and_then(|value| value.split_whitespace().find_map(Self::parse))
            .unwrap_or(Self::En)
    }

    fn parse(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "en" | "en-us" | "en-gb" => Some(Self::En),
            "zh" | "zh-cn" | "zh_hans" | "zh-hans" | "zh-sg" => Some(Self::ZhCn),
            _ => None,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }

    fn html_lang(self) -> &'static str {
        self.code()
    }
}

struct OAuthAuthorizeText {
    title: &'static str,
    subtitle: &'static str,
    channel_bindings_label: &'static str,
    channel_id_label: &'static str,
    password_label: &'static str,
    status_label: &'static str,
    channel_name_label: &'static str,
    action_label: &'static str,
    hint: &'static str,
    add_row: &'static str,
    submit: &'static str,
    channel_placeholder: &'static str,
    password_placeholder: &'static str,
    status_unvalidated: &'static str,
    status_incomplete: &'static str,
    status_validating: &'static str,
    status_ok: &'static str,
    status_failed: &'static str,
    status_network_error: &'static str,
    channel_name_empty: &'static str,
    remove: &'static str,
    alert_missing_rows: &'static str,
}

fn oauth_authorize_text(locale: McpLocale) -> OAuthAuthorizeText {
    match locale {
        McpLocale::En => OAuthAuthorizeText {
            title: "PushGo MCP Authorization",
            subtitle: "After approval, the MCP client can access the channels you bind here.",
            channel_bindings_label: "Channel Bindings",
            channel_id_label: "Channel ID",
            password_label: "Password",
            status_label: "Validation",
            channel_name_label: "Channel Name",
            action_label: "Action",
            hint: "Validation runs after the channel ID or password field loses focus. A successful check will also display the channel name.",
            add_row: "+ Add Row",
            submit: "Authorize",
            channel_placeholder: "06J0FZG1Y8XGG14VTQ4Y3G10MR",
            password_placeholder: "password-1234",
            status_unvalidated: "Not validated",
            status_incomplete: "Channel ID and password are both required",
            status_validating: "Validating...",
            status_ok: "Validated",
            status_failed: "Validation failed",
            status_network_error: "Network error",
            channel_name_empty: "-",
            remove: "Remove",
            alert_missing_rows: "Enter at least one valid channel binding row before submitting.",
        },
        McpLocale::ZhCn => OAuthAuthorizeText {
            title: "PushGo MCP 授权",
            subtitle: "授权后，MCP 客户端可以访问你在这里绑定的频道。",
            channel_bindings_label: "频道绑定",
            channel_id_label: "频道 ID",
            password_label: "密码",
            status_label: "校验状态",
            channel_name_label: "频道名",
            action_label: "操作",
            hint: "频道 ID 或密码输入框失焦后会自动校验；校验通过时会同步显示频道名。",
            add_row: "+ 新增一行",
            submit: "确认授权",
            channel_placeholder: "06J0FZG1Y8XGG14VTQ4Y3G10MR",
            password_placeholder: "password-1234",
            status_unvalidated: "未校验",
            status_incomplete: "请完整填写频道 ID 和密码",
            status_validating: "校验中...",
            status_ok: "校验通过",
            status_failed: "校验失败",
            status_network_error: "网络错误",
            channel_name_empty: "-",
            remove: "删除",
            alert_missing_rows: "请至少填写一行有效的频道信息后再提交。",
        },
    }
}

struct BindPageText {
    title: &'static str,
    subtitle: &'static str,
    submit: &'static str,
    completed: &'static str,
    channel_id_label: &'static str,
    password_label: &'static str,
    finished: &'static str,
}

fn bind_page_text(locale: McpLocale, action: BindAction) -> BindPageText {
    match (locale, action) {
        (McpLocale::En, BindAction::Bind) => BindPageText {
            title: "Bind Channel",
            subtitle: "Confirm the channel credentials and submit. This page only works for the current MCP session.",
            submit: "Submit",
            completed: "This session is already finished. Return to the MCP client.",
            channel_id_label: "Channel ID",
            password_label: "Password",
            finished: "Done. You can return to the MCP client.",
        },
        (McpLocale::En, BindAction::Revoke) => BindPageText {
            title: "Revoke Channel",
            subtitle: "Confirm the channel credentials and submit. This page only works for the current MCP session.",
            submit: "Submit",
            completed: "This session is already finished. Return to the MCP client.",
            channel_id_label: "Channel ID",
            password_label: "Password",
            finished: "Done. You can return to the MCP client.",
        },
        (McpLocale::ZhCn, BindAction::Bind) => BindPageText {
            title: "绑定频道",
            subtitle: "请确认频道凭据后提交。该页面仅在当前 MCP 会话内有效。",
            submit: "提交",
            completed: "当前会话已经完成，请返回 MCP 客户端。",
            channel_id_label: "频道 ID",
            password_label: "密码",
            finished: "操作完成。你可以返回 MCP 客户端继续。",
        },
        (McpLocale::ZhCn, BindAction::Revoke) => BindPageText {
            title: "撤销频道授权",
            subtitle: "请确认频道凭据后提交。该页面仅在当前 MCP 会话内有效。",
            submit: "提交",
            completed: "当前会话已经完成，请返回 MCP 客户端。",
            channel_id_label: "频道 ID",
            password_label: "密码",
            finished: "操作完成。你可以返回 MCP 客户端继续。",
        },
    }
}

fn channel_validate_invalid_channel_id(locale: McpLocale) -> &'static str {
    match locale {
        McpLocale::En => "Invalid channel_id format",
        McpLocale::ZhCn => "channel_id 格式错误",
    }
}

fn channel_validate_invalid_password(locale: McpLocale) -> &'static str {
    match locale {
        McpLocale::En => "Invalid password format",
        McpLocale::ZhCn => "password 格式错误",
    }
}

fn channel_validate_mismatch(locale: McpLocale) -> &'static str {
    match locale {
        McpLocale::En => "Channel not found or password incorrect",
        McpLocale::ZhCn => "频道不存在或密码错误",
    }
}
