use crate::{
    api::handlers::channel_auth::AuthorizedChannel, delivery_core::auth::AuthorizedChannelContext,
};

pub(crate) use crate::delivery_core::execution::submit_runtime::core_error_to_api_error;

pub(crate) fn authorized_channel_context(value: AuthorizedChannel) -> AuthorizedChannelContext {
    AuthorizedChannelContext {
        channel_id: value.channel_id,
        channel_id_text: value.channel_scope,
        channel_name: None,
        channel_display: None,
    }
}
