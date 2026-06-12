use crate::{
    api::{
        Error,
        handlers::{
            channel_auth::authorize_channel_by_password,
            message::{MessageDispatchIntent, OpId, dispatch_message_authorized_summary},
        },
    },
    app::AppState,
};

#[derive(Debug, Clone)]
pub(crate) struct MessageSendCommand {
    pub channel_id: String,
    pub password: String,
    pub op_id: Option<String>,
    pub thing_id: Option<String>,
    pub occurred_at: Option<i64>,
    pub title: String,
    pub body: Option<String>,
    pub severity: Option<String>,
    pub ttl: Option<i64>,
    pub url: Option<String>,
    pub images: Vec<String>,
    pub ciphertext: Option<String>,
    pub tags: Vec<String>,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub source: &'static str,
}

pub(crate) struct MessageSendOutcome {
    pub summary: crate::api::handlers::dispatch_lifecycle::NotificationDispatchSummary,
    pub message_id: String,
}

pub(crate) async fn send_message(
    state: &AppState,
    command: MessageSendCommand,
) -> Result<MessageSendOutcome, Error> {
    validate_message_command(&command)?;
    let scoped_thing_id = command
        .thing_id
        .as_deref()
        .map(|raw| {
            crate::api::handlers::entity_input::EntityId::parse(raw, "thing_id")
                .map(crate::api::handlers::entity_input::EntityId::into_inner)
        })
        .transpose()?;
    let authorized =
        authorize_channel_by_password(state, &command.channel_id, &command.password).await?;
    let (summary, message_id) = dispatch_message_authorized_summary(
        state,
        authorized,
        MessageDispatchIntent {
            op_id: command.op_id,
            occurred_at: command.occurred_at,
            title: command.title,
            body: command.body,
            severity: command.severity,
            ttl: command.ttl,
            url: command.url,
            images: command.images,
            ciphertext: command.ciphertext,
            tags: command.tags,
            metadata: command.metadata,
        },
        scoped_thing_id,
    )
    .await?;
    Ok(MessageSendOutcome {
        summary,
        message_id,
    })
}

fn validate_message_command(command: &MessageSendCommand) -> Result<(), Error> {
    if command.channel_id.trim().is_empty() {
        return Err(Error::validation_code(
            "channel id must not be empty",
            "channel_id_required",
        ));
    }
    crate::api::validate_channel_password(&command.password)?;
    if let Some(op_id) = command.op_id.as_deref() {
        OpId::parse(op_id)?;
    }
    if command.title.trim().is_empty() {
        return Err(Error::validation_code(
            "title must not be empty",
            "title_required",
        ));
    }
    crate::api::handlers::entity_input::MetadataEntries::new(&command.metadata).validate()?;
    let _source = command.source;
    Ok(())
}
