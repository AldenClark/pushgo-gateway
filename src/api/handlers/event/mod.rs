mod intent;
mod routes;
mod types;

mod validation;

use intent::EventIntent;
pub(crate) use routes::{
    event_close_authorized, event_close_to_channel, event_create_authorized,
    event_create_to_channel, event_update_authorized, event_update_to_channel,
};
pub(crate) use types::{EventCloseRequest, EventCreateRequest, EventSummary, EventUpdateRequest};
use types::{EventProfile, EventRouteAction};

#[cfg(test)]
mod tests;
