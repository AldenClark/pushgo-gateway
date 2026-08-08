use serde_json::{Map as JsonMap, Value as JsonValue};

use super::rpc_message::mcp_send_ack_value;
use super::*;

use crate::{
    api::handlers::{
        delivery_core_adapter::{authorized_channel_context, core_error_to_api_error},
        event::{EventCloseCommand, EventCommand, EventCreateCommand, EventUpdateCommand},
        thing::{
            ThingArchiveCommand, ThingCommand, ThingCreateCommand, ThingDeleteCommand,
            ThingUpdateCommand,
        },
    },
    delivery_core::{
        auth::SubmitAuth,
        domain::{event::EventPatch, thing::ThingPatch},
        source::IngressSource,
        submit::{
            ChannelSelector, DomainCommandInput, EventInput, ResponseMode, SubmitCommand,
            SubmitContext, ThingInput, submit_command,
        },
    },
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventPatchArgs {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    images: Option<Vec<String>>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    attrs: Option<JsonMap<String, JsonValue>>,
    #[serde(default)]
    metadata: Option<JsonMap<String, JsonValue>>,
}

impl EventPatchArgs {
    fn into_patch(self) -> EventPatch {
        EventPatch {
            title: self.title,
            description: self.description,
            status: self.status,
            message: self.message,
            severity: self.severity,
            tags: self.tags,
            images: self.images,
            ciphertext: self.ciphertext,
            attrs: self.attrs,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventCreateArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    event_time: Option<i64>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    started_at: Option<i64>,
    #[serde(flatten)]
    patch: EventPatchArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventUpdateArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    event_id: String,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    event_time: Option<i64>,
    #[serde(flatten)]
    patch: EventPatchArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventCloseArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    event_id: String,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    event_time: Option<i64>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    ended_at: Option<i64>,
    #[serde(flatten)]
    patch: EventPatchArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingPatchArgs {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    external_ids: Option<JsonMap<String, JsonValue>>,
    #[serde(default)]
    location_type: Option<String>,
    #[serde(default)]
    location_value: Option<String>,
    #[serde(default)]
    primary_image: Option<String>,
    #[serde(default)]
    images: Option<Vec<String>>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    observed_at: Option<i64>,
    #[serde(default)]
    attrs: Option<JsonMap<String, JsonValue>>,
    #[serde(default)]
    metadata: Option<JsonMap<String, JsonValue>>,
}

impl ThingPatchArgs {
    fn into_patch(self) -> ThingPatch {
        ThingPatch {
            title: self.title,
            description: self.description,
            tags: self.tags,
            external_ids: self.external_ids,
            location_type: self.location_type,
            location_value: self.location_value,
            primary_image: self.primary_image,
            images: self.images,
            ciphertext: self.ciphertext,
            observed_at: self.observed_at,
            attrs: self.attrs,
            metadata: self.metadata,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingCreateArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    created_at: Option<i64>,
    #[serde(flatten)]
    patch: ThingPatchArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingUpdateArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    thing_id: String,
    #[serde(flatten)]
    patch: ThingPatchArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingArchiveArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    thing_id: String,
    #[serde(flatten)]
    patch: ThingPatchArgs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingDeleteArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    thing_id: String,
    #[serde(
        default,
        deserialize_with = "crate::api::deserialize_unix_ts_millis_lenient"
    )]
    deleted_at: Option<i64>,
    #[serde(flatten)]
    patch: ThingPatchArgs,
}

fn reject_empty_id(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} required"));
    }
    Ok(())
}

async fn submit_mcp_event_command(
    service: &McpRpcService<'_>,
    channel_id: &str,
    password: Option<String>,
    command: EventCommand,
) -> Result<Value, String> {
    let authorized_channel = service.authorize_channel(channel_id, password).await?;
    let authorized_context = authorized_channel_context(authorized_channel);
    submit_command(
        SubmitContext {
            runtime: service.state,
            now_millis: chrono::Utc::now().timestamp_millis(),
        },
        SubmitCommand {
            source: IngressSource::McpTool,
            auth: SubmitAuth::AuthorizedChannel(authorized_context.clone()),
            channel: ChannelSelector::Authorized(authorized_context),
            command: DomainCommandInput::Event(Box::new(EventInput { command })),
            response_mode: ResponseMode::McpJson,
        },
    )
    .await
    .map_err(core_error_to_api_error)
    .map_err(|err| err.client_safe_message().into_owned())
    .and_then(mcp_send_ack_value)
}

async fn submit_mcp_thing_command(
    service: &McpRpcService<'_>,
    channel_id: &str,
    password: Option<String>,
    command: ThingCommand,
) -> Result<Value, String> {
    let authorized_channel = service.authorize_channel(channel_id, password).await?;
    let authorized_context = authorized_channel_context(authorized_channel);
    submit_command(
        SubmitContext {
            runtime: service.state,
            now_millis: chrono::Utc::now().timestamp_millis(),
        },
        SubmitCommand {
            source: IngressSource::McpTool,
            auth: SubmitAuth::AuthorizedChannel(authorized_context.clone()),
            channel: ChannelSelector::Authorized(authorized_context),
            command: DomainCommandInput::Thing(Box::new(ThingInput { command })),
            response_mode: ResponseMode::McpJson,
        },
    )
    .await
    .map_err(core_error_to_api_error)
    .map_err(|err| err.client_safe_message().into_owned())
    .and_then(mcp_send_ack_value)
}

impl McpRpcService<'_> {
    #[tracing::instrument(name = "gateway.mcp.rpc.event_create", skip_all)]
    pub(super) async fn call_event_create(&self, args: Value) -> Result<Value, String> {
        let parsed: EventCreateArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("event_create_parse_args", &err.to_string());
            err.to_string()
        })?;
        let channel_id = parsed.channel_id.clone();
        let command = EventCommand::Create(EventCreateCommand {
            op_id: parsed.op_id,
            thing_id: parsed.thing_id,
            event_time: parsed.event_time,
            started_at: parsed.started_at,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_event_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("event_create");
        Ok(value)
    }

    #[tracing::instrument(name = "gateway.mcp.rpc.event_update", skip_all)]
    pub(super) async fn call_event_update(&self, args: Value) -> Result<Value, String> {
        let parsed: EventUpdateArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("event_update_parse_args", &err.to_string());
            err.to_string()
        })?;
        if let Err(err) = reject_empty_id(&parsed.event_id, "event_id") {
            self.emit_rpc_rejected("event_id_required");
            return Err(err);
        }
        let channel_id = parsed.channel_id.clone();
        let command = EventCommand::Update(EventUpdateCommand {
            op_id: parsed.op_id,
            event_id: parsed.event_id,
            thing_id: parsed.thing_id,
            event_time: parsed.event_time,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_event_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("event_update");
        Ok(value)
    }

    #[tracing::instrument(name = "gateway.mcp.rpc.event_close", skip_all)]
    pub(super) async fn call_event_close(&self, args: Value) -> Result<Value, String> {
        let parsed: EventCloseArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("event_close_parse_args", &err.to_string());
            err.to_string()
        })?;
        if let Err(err) = reject_empty_id(&parsed.event_id, "event_id") {
            self.emit_rpc_rejected("event_id_required");
            return Err(err);
        }
        let channel_id = parsed.channel_id.clone();
        let command = EventCommand::Close(EventCloseCommand {
            op_id: parsed.op_id,
            event_id: parsed.event_id,
            thing_id: parsed.thing_id,
            event_time: parsed.event_time,
            ended_at: parsed.ended_at,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_event_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("event_close");
        Ok(value)
    }

    #[tracing::instrument(name = "gateway.mcp.rpc.thing_create", skip_all)]
    pub(super) async fn call_thing_create(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingCreateArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("thing_create_parse_args", &err.to_string());
            err.to_string()
        })?;
        let channel_id = parsed.channel_id.clone();
        let command = ThingCommand::Create(ThingCreateCommand {
            op_id: parsed.op_id,
            created_at: parsed.created_at,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_thing_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("thing_create");
        Ok(value)
    }

    #[tracing::instrument(name = "gateway.mcp.rpc.thing_update", skip_all)]
    pub(super) async fn call_thing_update(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingUpdateArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("thing_update_parse_args", &err.to_string());
            err.to_string()
        })?;
        if let Err(err) = reject_empty_id(&parsed.thing_id, "thing_id") {
            self.emit_rpc_rejected("thing_id_required");
            return Err(err);
        }
        let channel_id = parsed.channel_id.clone();
        let command = ThingCommand::Update(ThingUpdateCommand {
            op_id: parsed.op_id,
            thing_id: parsed.thing_id,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_thing_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("thing_update");
        Ok(value)
    }

    #[tracing::instrument(name = "gateway.mcp.rpc.thing_archive", skip_all)]
    pub(super) async fn call_thing_archive(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingArchiveArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("thing_archive_parse_args", &err.to_string());
            err.to_string()
        })?;
        if let Err(err) = reject_empty_id(&parsed.thing_id, "thing_id") {
            self.emit_rpc_rejected("thing_id_required");
            return Err(err);
        }
        let channel_id = parsed.channel_id.clone();
        let command = ThingCommand::Archive(ThingArchiveCommand {
            op_id: parsed.op_id,
            thing_id: parsed.thing_id,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_thing_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("thing_archive");
        Ok(value)
    }

    #[tracing::instrument(name = "gateway.mcp.rpc.thing_delete", skip_all)]
    pub(super) async fn call_thing_delete(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingDeleteArgs = serde_json::from_value(args).map_err(|err| {
            self.emit_rpc_failed("thing_delete_parse_args", &err.to_string());
            err.to_string()
        })?;
        if let Err(err) = reject_empty_id(&parsed.thing_id, "thing_id") {
            self.emit_rpc_rejected("thing_id_required");
            return Err(err);
        }
        let channel_id = parsed.channel_id.clone();
        let command = ThingCommand::Delete(ThingDeleteCommand {
            op_id: parsed.op_id,
            thing_id: parsed.thing_id,
            deleted_at: parsed.deleted_at,
            patch: parsed.patch.into_patch(),
        });
        let value = submit_mcp_thing_command(self, &channel_id, parsed.password, command).await?;
        self.emit_rpc_completed("thing_delete");
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        EventCloseArgs, EventCreateArgs, EventUpdateArgs, ThingCreateArgs, ThingUpdateArgs,
    };

    #[test]
    fn thing_update_args_preserve_missing_patch_field_presence() {
        let args: ThingUpdateArgs = serde_json::from_value(json!({
            "channel_id": "channel",
            "thing_id": "thing-1",
            "observed_at": 1_700_000_000_000i64,
            "metadata": { "source": "mcp" }
        }))
        .expect("thing update args should parse");

        assert!(args.patch.images.is_none());
        assert!(args.patch.attrs.is_none());
        assert!(args.patch.external_ids.is_none());
        assert_eq!(
            args.patch
                .metadata
                .as_ref()
                .and_then(|value| value.get("source"))
                .and_then(|value| value.as_str()),
            Some("mcp")
        );
    }

    #[test]
    fn entity_args_normalize_time_fields_to_millis() {
        let event: EventCreateArgs = serde_json::from_value(json!({
            "channel_id": "channel",
            "event_time": 1_700_000_000,
            "started_at": "1700000001"
        }))
        .expect("event create args should parse");
        assert_eq!(event.event_time, Some(1_700_000_000_000));
        assert_eq!(event.started_at, Some(1_700_000_001_000));

        let thing: ThingCreateArgs = serde_json::from_value(json!({
            "channel_id": "channel",
            "created_at": 1_700_000_002,
            "observed_at": "1700000003"
        }))
        .expect("thing create args should parse");
        assert_eq!(thing.created_at, Some(1_700_000_002_000));
        assert_eq!(thing.patch.observed_at, Some(1_700_000_003_000));
    }

    #[test]
    fn event_update_args_reject_close_only_time_fields() {
        let parsed = serde_json::from_value::<EventUpdateArgs>(json!({
            "channel_id": "channel",
            "event_id": "event-1",
            "event_time": 1_700_000_000_000i64,
            "ended_at": 1_700_000_000_001i64
        }));

        assert!(parsed.is_err(), "event update should reject ended_at");
    }

    #[test]
    fn event_create_args_reject_update_and_close_only_fields() {
        let with_event_id = serde_json::from_value::<EventCreateArgs>(json!({
            "channel_id": "channel",
            "event_id": "event-1"
        }));
        let with_ended_at = serde_json::from_value::<EventCreateArgs>(json!({
            "channel_id": "channel",
            "ended_at": 1_700_000_000_001i64
        }));

        assert!(
            with_event_id.is_err(),
            "event create should reject event_id"
        );
        assert!(
            with_ended_at.is_err(),
            "event create should reject ended_at"
        );
    }

    #[test]
    fn event_close_args_reject_create_only_time_fields() {
        let parsed = serde_json::from_value::<EventCloseArgs>(json!({
            "channel_id": "channel",
            "event_id": "event-1",
            "started_at": 1_700_000_000_001i64
        }));

        assert!(parsed.is_err(), "event close should reject started_at");
    }

    #[test]
    fn thing_create_args_reject_id_and_delete_fields() {
        let with_thing_id = serde_json::from_value::<ThingCreateArgs>(json!({
            "channel_id": "channel",
            "thing_id": "thing-1"
        }));
        let with_deleted_at = serde_json::from_value::<ThingCreateArgs>(json!({
            "channel_id": "channel",
            "deleted_at": 1_700_000_000_001i64
        }));

        assert!(
            with_thing_id.is_err(),
            "thing create should reject thing_id"
        );
        assert!(
            with_deleted_at.is_err(),
            "thing create should reject deleted_at"
        );
    }

    #[test]
    fn thing_update_args_reject_create_and_delete_fields() {
        let with_created_at = serde_json::from_value::<ThingUpdateArgs>(json!({
            "channel_id": "channel",
            "thing_id": "thing-1",
            "created_at": 1_700_000_000_001i64
        }));
        let with_deleted_at = serde_json::from_value::<ThingUpdateArgs>(json!({
            "channel_id": "channel",
            "thing_id": "thing-1",
            "deleted_at": 1_700_000_000_001i64
        }));

        assert!(
            with_created_at.is_err(),
            "thing update should reject created_at"
        );
        assert!(
            with_deleted_at.is_err(),
            "thing update should reject deleted_at"
        );
    }
}
