use chrono::Utc;

use crate::{
    api::{Error, handlers::delivery_core_adapter::core_error_to_api_error},
    app::AppState,
    delivery_core::{
        auth::SubmitAuth,
        response::{DeliverySummary, EntityRef},
        source::IngressSource,
        submit::{
            ChannelSelector, DomainCommandInput, ResponseMode, SubmitCommand, SubmitContext,
            submit_command,
        },
    },
    domain_model::message::MessageInput,
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
    pub source: IngressSource,
}

pub(crate) struct MessageSendOutcome {
    pub summary: DeliverySummary,
    pub message_id: String,
}

pub(crate) async fn send_message(
    state: &AppState,
    command: MessageSendCommand,
) -> Result<MessageSendOutcome, Error> {
    validate_message_command(&command)?;
    let response_mode = match command.source {
        IngressSource::MqttPublish | IngressSource::MqttWill => ResponseMode::MqttAck,
        _ => ResponseMode::HttpJson,
    };
    let result = submit_command(
        SubmitContext {
            runtime: state,
            now_millis: Utc::now().timestamp_millis(),
        },
        SubmitCommand {
            source: command.source,
            auth: SubmitAuth::ChannelPassword {
                password: command.password,
            },
            channel: ChannelSelector::ChannelId(command.channel_id),
            command: DomainCommandInput::Message(Box::new(MessageInput {
                op_id: command.op_id,
                thing_id: command.thing_id,
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
            })),
            response_mode,
        },
    )
    .await
    .map_err(core_error_to_api_error)?;
    let EntityRef::Message { message_id, .. } = result.entity else {
        return Err(Error::Internal(
            "message submit returned non-message entity".into(),
        ));
    };
    Ok(MessageSendOutcome {
        summary: result.summary,
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
    if command.title.trim().is_empty() {
        return Err(Error::validation_code(
            "title must not be empty",
            "title_required",
        ));
    }
    crate::api::handlers::entity_input::MetadataEntries::new(&command.metadata).validate()?;
    Ok(())
}
