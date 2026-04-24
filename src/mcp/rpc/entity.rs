use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(default)]
    event_time: Option<i64>,
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
    images: Vec<String>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    started_at: Option<i64>,
    #[serde(default)]
    ended_at: Option<i64>,
    #[serde(default)]
    attrs: serde_json::Map<String, Value>,
    #[serde(default)]
    metadata: serde_json::Map<String, Value>,
}

impl EventArgs {
    fn into_payload_json(self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "password": self.password,
            "op_id": self.op_id,
            "event_id": self.event_id,
            "thing_id": self.thing_id,
            "event_time": self.event_time,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "message": self.message,
            "severity": self.severity,
            "tags": self.tags,
            "images": self.images,
            "ciphertext": self.ciphertext,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "attrs": self.attrs,
            "metadata": self.metadata,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThingArgs {
    channel_id: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    thing_id: Option<String>,
    #[serde(default)]
    created_at: Option<i64>,
    #[serde(default)]
    deleted_at: Option<i64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    external_ids: serde_json::Map<String, Value>,
    #[serde(default)]
    location_type: Option<String>,
    #[serde(default)]
    location_value: Option<String>,
    #[serde(default)]
    primary_image: Option<String>,
    #[serde(default)]
    images: Vec<String>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    observed_at: Option<i64>,
    #[serde(default)]
    attrs: serde_json::Map<String, Value>,
    #[serde(default)]
    metadata: serde_json::Map<String, Value>,
}

impl ThingArgs {
    fn into_payload_json(self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "password": self.password,
            "op_id": self.op_id,
            "thing_id": self.thing_id,
            "created_at": self.created_at,
            "deleted_at": self.deleted_at,
            "title": self.title,
            "description": self.description,
            "tags": self.tags,
            "external_ids": self.external_ids,
            "location_type": self.location_type,
            "location_value": self.location_value,
            "primary_image": self.primary_image,
            "images": self.images,
            "ciphertext": self.ciphertext,
            "observed_at": self.observed_at,
            "attrs": self.attrs,
            "metadata": self.metadata,
        })
    }
}

impl McpRpcService<'_> {
    pub(super) async fn call_event_create(&self, args: Value) -> Result<Value, String> {
        let parsed: EventArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        let mut payload = parsed.into_payload_json();
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("event_id");
        }
        let req: crate::api::handlers::event::EventCreateRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response =
            crate::api::handlers::event::event_create_authorized(self.state, req, authorized_channel)
                .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }

    pub(super) async fn call_event_update(&self, args: Value) -> Result<Value, String> {
        let parsed: EventArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        if parsed.event_id.as_deref().is_none_or(|v| v.trim().is_empty()) {
            return Err("event_id required".to_string());
        }
        let payload = parsed.into_payload_json();
        let req: crate::api::handlers::event::EventUpdateRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response =
            crate::api::handlers::event::event_update_authorized(self.state, req, authorized_channel)
                .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }

    pub(super) async fn call_event_close(&self, args: Value) -> Result<Value, String> {
        let parsed: EventArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        if parsed.event_id.as_deref().is_none_or(|v| v.trim().is_empty()) {
            return Err("event_id required".to_string());
        }
        let payload = parsed.into_payload_json();
        let req: crate::api::handlers::event::EventCloseRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response =
            crate::api::handlers::event::event_close_authorized(self.state, req, authorized_channel)
                .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }

    pub(super) async fn call_thing_create(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        let mut payload = parsed.into_payload_json();
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("thing_id");
            obj.remove("deleted_at");
        }
        let req: crate::api::handlers::thing::ThingCreateRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response =
            crate::api::handlers::thing::thing_create_authorized(self.state, req, authorized_channel)
                .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }

    pub(super) async fn call_thing_update(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        if parsed.thing_id.as_deref().is_none_or(|v| v.trim().is_empty()) {
            return Err("thing_id required".to_string());
        }
        let mut payload = parsed.into_payload_json();
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("created_at");
            obj.remove("deleted_at");
        }
        let req: crate::api::handlers::thing::ThingUpdateRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response =
            crate::api::handlers::thing::thing_update_authorized(self.state, req, authorized_channel)
                .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }

    pub(super) async fn call_thing_archive(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        if parsed.thing_id.as_deref().is_none_or(|v| v.trim().is_empty()) {
            return Err("thing_id required".to_string());
        }
        let mut payload = parsed.into_payload_json();
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("created_at");
            obj.remove("deleted_at");
        }
        let req: crate::api::handlers::thing::ThingArchiveRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response = crate::api::handlers::thing::thing_archive_authorized(
            self.state,
            req,
            authorized_channel,
        )
        .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }

    pub(super) async fn call_thing_delete(&self, args: Value) -> Result<Value, String> {
        let parsed: ThingArgs = serde_json::from_value(args).map_err(|err| err.to_string())?;
        let channel_id = parsed.channel_id.clone();
        let authorized_channel = self
            .authorize_channel(&channel_id, parsed.password.clone())
            .await?;
        if parsed.thing_id.as_deref().is_none_or(|v| v.trim().is_empty()) {
            return Err("thing_id required".to_string());
        }
        let mut payload = parsed.into_payload_json();
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("created_at");
        }
        let req: crate::api::handlers::thing::ThingDeleteRequest =
            serde_json::from_value(payload).map_err(|err| err.to_string())?;
        let response =
            crate::api::handlers::thing::thing_delete_authorized(self.state, req, authorized_channel)
                .await;
        let mut value = self.http_result_to_value(response).await?;
        value["auth_mode"] = Value::String(self.auth_mode_name().to_string());
        self.attach_channel_context(&mut value, &channel_id).await;
        Ok(value)
    }
}
