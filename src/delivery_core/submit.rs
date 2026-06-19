use async_trait::async_trait;

use super::{
    auth::{AuthorizedChannelContext, SubmitAuth},
    domain::{
        event::{EventCommand, EventPatch},
        message::{MessageInput, MessageSend},
        projection::EntityRef as DomainEntityRef,
        thing::{ThingCommand, ThingPatch},
    },
    error::CoreError,
    execution::request::{DispatchEventInput, DispatchMessageInput, DispatchThingInput},
    response::{DeliverySummary, EntityRef, SubmitResult},
    source::IngressSource,
    store::idempotency::IdempotencyStore,
};

pub(crate) struct SubmitContext<'a> {
    pub(crate) runtime: &'a dyn SubmitRuntime,
    pub(crate) now_millis: i64,
}

pub(crate) struct SubmitCommand {
    pub(crate) source: IngressSource,
    pub(crate) auth: SubmitAuth,
    pub(crate) channel: ChannelSelector,
    pub(crate) command: DomainCommandInput,
    pub(crate) response_mode: ResponseMode,
}

pub(crate) enum ChannelSelector {
    ChannelId(String),
    Authorized(AuthorizedChannelContext),
}

pub(crate) enum DomainCommandInput {
    Message(Box<MessageInput>),
    Event(Box<EventInput>),
    Thing(Box<ThingInput>),
}

#[derive(Debug, Clone)]
pub(crate) struct AuthorizedSubmitChannel {
    pub(crate) channel_id: [u8; 16],
    pub(crate) channel_id_text: String,
}

#[async_trait]
pub(crate) trait SubmitRuntime: Send + Sync {
    fn idempotency_store(&self) -> &(dyn IdempotencyStore + Send + Sync);

    async fn authorize_channel_by_password(
        &self,
        channel_id: &str,
        password: &str,
    ) -> Result<AuthorizedSubmitChannel, CoreError>;

    async fn dispatch_message(
        &self,
        input: DispatchMessageInput,
    ) -> Result<DeliverySummary, CoreError>;

    async fn dispatch_event(&self, input: DispatchEventInput)
    -> Result<DeliverySummary, CoreError>;

    async fn dispatch_thing(&self, input: DispatchThingInput)
    -> Result<DeliverySummary, CoreError>;
}

#[derive(Debug, Clone)]
pub(crate) struct EventInput {
    pub(crate) command: EventCommand<EventPatch>,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingInput {
    pub(crate) command: ThingCommand<ThingPatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseMode {
    HttpJson,
    MqttAck,
    McpJson,
}

impl ResponseMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::HttpJson => "http_json",
            Self::MqttAck => "mqtt_ack",
            Self::McpJson => "mcp_json",
        }
    }
}

pub(crate) async fn submit_command(
    ctx: SubmitContext<'_>,
    command: SubmitCommand,
) -> Result<SubmitResult, CoreError> {
    validate_submit_context(command.source, command.response_mode)?;
    match command.command {
        DomainCommandInput::Message(message) => {
            submit_message(
                ctx.runtime,
                ctx.now_millis,
                command.channel,
                command.auth,
                *message,
            )
            .await
        }
        DomainCommandInput::Event(event) => {
            submit_event(ctx.runtime, command.channel, command.auth, *event).await
        }
        DomainCommandInput::Thing(thing) => {
            submit_thing(ctx.runtime, command.channel, command.auth, *thing).await
        }
    }
}

fn validate_submit_context(
    source: IngressSource,
    response_mode: ResponseMode,
) -> Result<(), CoreError> {
    let valid = match source {
        IngressSource::HttpMessage
        | IngressSource::HttpCompatNtfy
        | IngressSource::HttpCompatBark
        | IngressSource::HttpCompatServerChan
        | IngressSource::HttpEvent
        | IngressSource::HttpThing => response_mode == ResponseMode::HttpJson,
        IngressSource::MqttPublish | IngressSource::MqttWill => {
            response_mode == ResponseMode::MqttAck
        }
        IngressSource::McpTool => response_mode == ResponseMode::McpJson,
    };
    if valid {
        return Ok(());
    }
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "submit.context_rejected",
        source = %(source.as_str()),
        response_mode = %(response_mode.as_str()),
        reason = %("source_response_mode_mismatch")
    );
    Err(CoreError::validation_code(
        "submit source and response mode are incompatible",
        "source_response_mode_mismatch",
    ))
}

async fn submit_message(
    runtime: &dyn SubmitRuntime,
    now_millis: i64,
    channel: ChannelSelector,
    auth: SubmitAuth,
    message: MessageInput,
) -> Result<SubmitResult, CoreError> {
    let authorized_channel = resolve_authorized_channel(runtime, channel, auth).await?;
    let normalized = MessageSend::new(message)
        .normalize(
            runtime.idempotency_store(),
            authorized_channel.channel_id,
            authorized_channel.channel_id_text.clone(),
            now_millis,
        )
        .await?;
    let projection = normalized.command.projection;
    let DomainEntityRef::Message {
        message_id,
        thing_id: scoped_thing_id,
    } = projection.entity
    else {
        return Err(CoreError::internal(
            "message normalization returned non-message projection",
        ));
    };
    let alert = projection.alert;
    let delivery_policy = projection.delivery_policy;
    let output = runtime
        .dispatch_message(DispatchMessageInput {
            authorized_channel: authorized_channel.clone(),
            op_id: Some(normalized.op_id),
            thing_id: scoped_thing_id.clone(),
            occurred_at: Some(normalized.occurred_at),
            title: alert.title.unwrap_or_default(),
            body: alert.body,
            severity: alert.severity,
            ttl: alert.ttl,
            custom_data: projection.custom_data,
            extra_fields: projection.extra_fields,
            delivery_policy,
            message_id: message_id.clone(),
        })
        .await?;
    let delivery = output;
    let delivery_id = delivery.delivery_id.clone();
    let acceptance = delivery.submit_acceptance();
    let result = SubmitResult {
        channel_id: delivery.channel_id.clone(),
        op_id: delivery.op_id.clone(),
        entity: EntityRef::Message {
            message_id,
            thing_id: scoped_thing_id,
        },
        delivery_id,
        acceptance,
        summary: delivery,
    };
    Ok(result)
}

async fn submit_event(
    runtime: &dyn SubmitRuntime,
    channel: ChannelSelector,
    auth: SubmitAuth,
    input: EventInput,
) -> Result<SubmitResult, CoreError> {
    let authorized_channel = resolve_authorized_channel(runtime, channel, auth).await?;
    let normalized = input
        .command
        .normalize(
            runtime.idempotency_store(),
            authorized_channel.channel_id,
            authorized_channel.channel_id_text.clone(),
        )
        .await?;
    let projection = normalized.command.projection;
    let DomainEntityRef::Event { event_id, thing_id } = projection.entity else {
        return Err(CoreError::internal(
            "event normalization returned non-event projection",
        ));
    };
    let alert = projection.alert;
    let delivery_policy = projection.delivery_policy;
    let delivery = runtime
        .dispatch_event(DispatchEventInput {
            authorized_channel: authorized_channel.clone(),
            op_id: normalized.op_id.clone(),
            occurred_at: normalized.occurred_at,
            title: alert.title,
            body: alert.body,
            custom_data: projection.custom_data,
            extra_fields: projection.extra_fields,
            delivery_policy,
            event_id: event_id.clone(),
        })
        .await?;
    let delivery_id = delivery.delivery_id.clone();
    let acceptance = delivery.submit_acceptance();
    Ok(SubmitResult {
        channel_id: delivery.channel_id.clone(),
        op_id: delivery.op_id.clone(),
        entity: EntityRef::Event { event_id, thing_id },
        delivery_id,
        acceptance,
        summary: delivery,
    })
}

async fn submit_thing(
    runtime: &dyn SubmitRuntime,
    channel: ChannelSelector,
    auth: SubmitAuth,
    input: ThingInput,
) -> Result<SubmitResult, CoreError> {
    let authorized_channel = resolve_authorized_channel(runtime, channel, auth).await?;
    let normalized = input
        .command
        .normalize(
            runtime.idempotency_store(),
            authorized_channel.channel_id,
            authorized_channel.channel_id_text.clone(),
        )
        .await?;
    let projection = normalized.command.projection;
    let DomainEntityRef::Thing { thing_id } = projection.entity else {
        return Err(CoreError::internal(
            "thing normalization returned non-thing projection",
        ));
    };
    let alert = projection.alert;
    let delivery_policy = projection.delivery_policy;
    let delivery = runtime
        .dispatch_thing(DispatchThingInput {
            authorized_channel: authorized_channel.clone(),
            op_id: normalized.op_id.clone(),
            occurred_at: normalized.occurred_at,
            title: alert.title,
            body: alert.body,
            custom_data: projection.custom_data,
            extra_fields: projection.extra_fields,
            delivery_policy,
            thing_id: thing_id.clone(),
        })
        .await?;
    let delivery_id = delivery.delivery_id.clone();
    let acceptance = delivery.submit_acceptance();
    Ok(SubmitResult {
        channel_id: delivery.channel_id.clone(),
        op_id: delivery.op_id.clone(),
        entity: EntityRef::Thing { thing_id },
        delivery_id,
        acceptance,
        summary: delivery,
    })
}

async fn resolve_authorized_channel(
    runtime: &dyn SubmitRuntime,
    channel: ChannelSelector,
    auth: SubmitAuth,
) -> Result<AuthorizedSubmitChannel, CoreError> {
    match (channel, auth) {
        (ChannelSelector::ChannelId(channel_id), SubmitAuth::ChannelPassword { password }) => {
            runtime
                .authorize_channel_by_password(&channel_id, &password)
                .await
        }
        (
            ChannelSelector::Authorized(selector_context),
            SubmitAuth::AuthorizedChannel(auth_context),
        ) => {
            let context = if selector_context.channel_id == auth_context.channel_id {
                selector_context
            } else {
                return Err(CoreError::validation_code(
                    "authorized channel selector and auth context differ",
                    "authorized_channel_context_mismatch",
                ));
            };
            Ok(AuthorizedSubmitChannel {
                channel_id: context.channel_id,
                channel_id_text: context.channel_id_text,
            })
        }
        _ => Err(CoreError::validation_code(
            "channel selector and auth mode are incompatible",
            "submit_auth_channel_mismatch",
        )),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use serde_json::Map as JsonMap;

    use super::*;
    use crate::{
        delivery_core::{
            execution::request::{DispatchEventInput, DispatchMessageInput, DispatchThingInput},
            response::{DeliveryDedupeStatus, DeliveryDispatchStatus, SubmitAcceptance},
        },
        storage::{OpDedupeReservation, SemanticIdReservation, StoreResult},
    };

    struct FakeIdempotencyStore;

    #[async_trait]
    impl IdempotencyStore for FakeIdempotencyStore {
        async fn reserve_semantic_id(
            &self,
            _key: &str,
            semantic_id: &str,
            _created_at: i64,
        ) -> StoreResult<SemanticIdReservation> {
            Ok(SemanticIdReservation::Existing {
                semantic_id: semantic_id.to_string(),
            })
        }

        async fn reserve_op_pending(
            &self,
            _key: &str,
            _delivery_id: &str,
            _created_at: i64,
        ) -> StoreResult<OpDedupeReservation> {
            unreachable!("submit normalization should not reserve op pending in fake runtime")
        }

        async fn mark_op_sent(&self, _key: &str, _delivery_id: &str) -> StoreResult<bool> {
            unreachable!("submit normalization should not mark op sent in fake runtime")
        }

        async fn clear_op_pending(&self, _key: &str, _delivery_id: &str) -> StoreResult<()> {
            unreachable!("submit normalization should not clear op pending in fake runtime")
        }
    }

    struct PendingDuplicateRuntime;

    #[async_trait]
    impl SubmitRuntime for PendingDuplicateRuntime {
        fn idempotency_store(&self) -> &(dyn IdempotencyStore + Send + Sync) {
            &FakeIdempotencyStore
        }

        async fn authorize_channel_by_password(
            &self,
            _channel_id: &str,
            _password: &str,
        ) -> Result<AuthorizedSubmitChannel, CoreError> {
            Ok(AuthorizedSubmitChannel {
                channel_id: [3; 16],
                channel_id_text: "channel".to_string(),
            })
        }

        async fn dispatch_message(
            &self,
            input: DispatchMessageInput,
        ) -> Result<DeliverySummary, CoreError> {
            Ok(DeliverySummary::new(
                input.authorized_channel.channel_id_text,
                input.op_id.unwrap_or_else(|| "op".to_string()),
                "pending-delivery".to_string(),
                DeliveryDedupeStatus::DuplicatePending,
                DeliveryDispatchStatus::NotAttempted,
            ))
        }

        async fn dispatch_event(
            &self,
            _input: DispatchEventInput,
        ) -> Result<DeliverySummary, CoreError> {
            unreachable!("message submit test should not dispatch event")
        }

        async fn dispatch_thing(
            &self,
            _input: DispatchThingInput,
        ) -> Result<DeliverySummary, CoreError> {
            unreachable!("message submit test should not dispatch thing")
        }
    }

    #[test]
    fn submit_context_accepts_matching_source_and_response_mode() {
        for (source, response_mode) in [
            (IngressSource::HttpMessage, ResponseMode::HttpJson),
            (IngressSource::HttpCompatNtfy, ResponseMode::HttpJson),
            (IngressSource::HttpCompatBark, ResponseMode::HttpJson),
            (IngressSource::HttpCompatServerChan, ResponseMode::HttpJson),
            (IngressSource::HttpEvent, ResponseMode::HttpJson),
            (IngressSource::HttpThing, ResponseMode::HttpJson),
            (IngressSource::MqttPublish, ResponseMode::MqttAck),
            (IngressSource::MqttWill, ResponseMode::MqttAck),
            (IngressSource::McpTool, ResponseMode::McpJson),
        ] {
            validate_submit_context(source, response_mode)
                .expect("matching source/response mode should be accepted");
        }
    }

    #[test]
    fn submit_context_rejects_mismatched_source_and_response_mode() {
        for (source, response_mode) in [
            (IngressSource::HttpMessage, ResponseMode::MqttAck),
            (IngressSource::MqttPublish, ResponseMode::HttpJson),
            (IngressSource::MqttWill, ResponseMode::McpJson),
            (IngressSource::McpTool, ResponseMode::HttpJson),
        ] {
            let err = validate_submit_context(source, response_mode)
                .expect_err("mismatched source/response mode should be rejected");
            match err {
                CoreError::Validation { code, .. } => {
                    assert_eq!(code, "source_response_mode_mismatch");
                }
                other => panic!("unexpected error: {other}"),
            }
        }
    }

    #[tokio::test]
    async fn submit_result_preserves_duplicate_pending_outcome() {
        let result = submit_command(
            SubmitContext {
                runtime: &PendingDuplicateRuntime,
                now_millis: 10,
            },
            SubmitCommand {
                source: IngressSource::HttpMessage,
                auth: SubmitAuth::ChannelPassword {
                    password: "password".to_string(),
                },
                channel: ChannelSelector::ChannelId("channel".to_string()),
                command: DomainCommandInput::Message(Box::new(MessageInput {
                    op_id: Some("pending-op".to_string()),
                    thing_id: None,
                    occurred_at: None,
                    title: "pending title".to_string(),
                    body: None,
                    severity: None,
                    ttl: None,
                    url: None,
                    images: Vec::new(),
                    ciphertext: None,
                    tags: Vec::new(),
                    metadata: JsonMap::new(),
                })),
                response_mode: ResponseMode::HttpJson,
            },
        )
        .await
        .expect("pending duplicate summary should remain a submit result");

        assert_eq!(result.acceptance, SubmitAcceptance::DuplicatePending);
        assert_eq!(
            result.summary.failure_error_message(),
            Some("notification dispatch is already pending")
        );
    }
}
