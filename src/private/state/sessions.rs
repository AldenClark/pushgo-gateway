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
        self.runtime_counters
            .record_private_connected(format!("private:{}", encode_lower_hex_128(&device_id)));
        let resume = self
            .hub
            .start_or_resume_session(device_id, client_resume_token, last_acked_seq)
            .await;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.session_resume_completed",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id)))
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
}
