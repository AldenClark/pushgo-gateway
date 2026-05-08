use super::*;

impl PrivateState {
    pub async fn start_or_resume_session(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> ResumeHandshake {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.session_resume_started",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            has_resume_token = (client_resume_token.is_some()),
            last_acked_seq = (last_acked_seq)
        );
        self.stats
            .record_private_connected(format!("private:{}", encode_lower_hex_128(&device_id)));
        let resume = self
            .hub
            .start_or_resume_session(device_id, client_resume_token, last_acked_seq)
            .await;
        self.settle_resume_acked_deliveries(device_id, &resume.acked_delivery_ids)
            .await;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.session_resume_completed",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            acked_delivery_ids = (resume.acked_delivery_ids.len() as u64)
        );
        resume
    }

    pub(crate) async fn prepare_session_bootstrap(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> Result<PreparedSessionBootstrap, crate::Error> {
        let resume = self
            .start_or_resume_session(device_id, client_resume_token, last_acked_seq)
            .await;
        let bootstrap = self
            .hub
            .build_bootstrap_queues(device_id, self.config.pull_limit)
            .await?;
        Ok(PreparedSessionBootstrap { resume, bootstrap })
    }

    async fn settle_resume_acked_deliveries(&self, device_id: DeviceId, delivery_ids: &[String]) {
        if delivery_ids.is_empty() {
            return;
        }
        for delivery_id in delivery_ids {
            match self
                .complete_terminal_delivery(device_id, delivery_id.as_str(), None)
                .await
            {
                Ok(true) | Ok(false) => {}
                Err(err) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "private.session_resume_settle_failed",
                        device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                        delivery_id = %(crate::util::redact_text(delivery_id.as_str())),
                        error = %(err.to_string())
                    );
                }
            }
        }
    }
}
