#[path = "rpc/channel.rs"]
mod rpc_channel;
#[path = "rpc/core.rs"]
mod rpc_core;
#[path = "rpc/entity.rs"]
mod rpc_entity;
#[path = "rpc/message.rs"]
mod rpc_message;

use self::rpc_core::McpRpcService;
