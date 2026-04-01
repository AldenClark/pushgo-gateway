use std::{
    collections::HashMap,
    fmt::Write as _,
};

use axum::{
    Json,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod core_auth;
mod core_snapshot;
mod core_state;
mod core_types;

pub(crate) use self::core_types::{
    AuthorizationQuery, AuthorizeSubmit, McpConfig, McpPredefinedClientConfig, McpState,
    OAuthClient,
};
use self::{
    core_auth::{AccessClaims, McpAuthContext},
    core_snapshot::McpSnapshot,
    core_types::{
        AuthCode, BindAction, BindSession, BindStatus, ChannelGrant, McpScope, McpScopeSet,
        OAuthGrantType, PkceMethod, Principal, RefreshToken,
    },
};

use crate::{
    api::{HttpResult, parse_channel_id, validate_channel_password},
    app::AppState,
};
