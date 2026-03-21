use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    pub apns: ApnsConfig,
    pub fcm: FcmConfig,
    pub wns: WnsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApnsConfig {
    pub team_id: String,
    pub key_id: String,
    pub key_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FcmConfig {
    pub project_id: String,
    pub client_email: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WnsConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_wns_scope")]
    pub scope: String,
}

fn default_wns_scope() -> String {
    "https://wns.windows.com/.default".to_string()
}
