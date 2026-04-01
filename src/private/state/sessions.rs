use super::*;

impl PrivateState {
    pub async fn start_or_resume_session(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> ResumeHandshake {
        self.stats
            .record_private_connected(format!("private:{}", encode_lower_hex_128(&device_id)));
        let resume = self
            .hub
            .start_or_resume_session(device_id, client_resume_token, last_acked_seq)
            .await;
        self.settle_resume_acked_deliveries(device_id, &resume.acked_delivery_ids)
            .await;
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
        for delivery_id in delivery_ids {
            match self
                .complete_terminal_delivery(device_id, delivery_id.as_str(), None)
                .await
            {
                Ok(true) | Ok(false) => {}
                Err(_err) => {}
            }
        }
    }
}
