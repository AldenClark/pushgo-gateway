mod intent;
mod routes;
mod types;

mod helpers;

use intent::ThingIntent;
pub(crate) use routes::{
    thing_archive_authorized, thing_archive_to_channel, thing_create_authorized,
    thing_create_to_channel, thing_delete_authorized, thing_delete_to_channel,
    thing_update_authorized, thing_update_to_channel,
};
pub(crate) use types::{
    ThingArchiveRequest, ThingCreateRequest, ThingDeleteRequest, ThingSummary, ThingUpdateRequest,
};
use types::{ThingLocation, ThingProfile, ThingRouteAction};

#[cfg(test)]
mod tests;
