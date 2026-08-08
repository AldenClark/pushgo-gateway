use crate::{api::Error, app::AppState, storage::StoreError, util::generate_hex_id_128};

pub(crate) use crate::domain_model::ids::SemanticScope;
pub(crate) use crate::value::OpId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeliveryId(String);

impl DeliveryId {
    pub(crate) async fn reserve(state: &AppState, created_at: i64) -> Result<Self, Error> {
        const MAX_ATTEMPTS: usize = 4;
        let mut collisions = 0usize;
        for _ in 0..MAX_ATTEMPTS {
            let delivery_id = generate_hex_id_128();
            let dedupe_key = format!("delivery:{delivery_id}");
            let inserted = state
                .store
                .reserve_delivery_dedupe(dedupe_key.as_str(), &delivery_id, created_at)
                .await
                .map_err(internal_store_error)?;
            if inserted {
                if collisions > 0 {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::INFO,
                        event = "dispatch.delivery_id_reserved_after_collision",
                        collisions = (collisions as u64)
                    );
                }
                return Ok(Self(delivery_id));
            }
            collisions = collisions.saturating_add(1);
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::ERROR,
            event = "dispatch.delivery_id_reserve_exhausted",
            max_attempts = (MAX_ATTEMPTS as u64),
            collisions = (collisions as u64)
        );
        Err(Error::Internal(
            "unable to reserve unique delivery id".to_string(),
        ))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

fn internal_store_error(error: StoreError) -> Error {
    Error::Internal(error.to_string())
}
