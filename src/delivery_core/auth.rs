#[derive(Debug, Clone)]
pub(crate) enum SubmitAuth {
    ChannelPassword { password: String },
    AuthorizedChannel(AuthorizedChannelContext),
}

#[derive(Debug, Clone)]
pub(crate) struct AuthorizedChannelContext {
    pub(crate) channel_id: [u8; 16],
    pub(crate) channel_id_text: String,
    pub(crate) channel_name: Option<String>,
    pub(crate) channel_display: Option<String>,
}
