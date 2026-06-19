#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IngressSource {
    HttpMessage,
    HttpCompatNtfy,
    HttpCompatBark,
    HttpCompatServerChan,
    HttpEvent,
    HttpThing,
    MqttPublish,
    MqttWill,
    McpTool,
}

impl IngressSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HttpMessage => "http_message",
            Self::HttpCompatNtfy => "http_compat_ntfy",
            Self::HttpCompatBark => "http_compat_bark",
            Self::HttpCompatServerChan => "http_compat_server_chan",
            Self::HttpEvent => "http_event",
            Self::HttpThing => "http_thing",
            Self::MqttPublish => "mqtt_publish",
            Self::MqttWill => "mqtt_will",
            Self::McpTool => "mcp_tool",
        }
    }
}
