impl PrivateState {
    pub fn spawn_configured_transports(self: &Arc<Self>) -> Result<(), crate::Error> {
        self.spawn_quic_if_configured()?;
        self.spawn_tcp_if_configured()?;
        Ok(())
    }

    pub fn spawn_quic_if_configured(self: &Arc<Self>) -> Result<(), crate::Error> {
        let Some(bind_addr) = self.config.private_quic_bind.clone() else {
            return Ok(());
        };
        let (cert_path, key_path) = self.config.require_tls_identity(
            "PUSHGO_PRIVATE_TLS_CERT is required when QUIC is enabled",
            "PUSHGO_PRIVATE_TLS_KEY is required when QUIC is enabled",
        )?;
        self.spawn_with_restart_loop(move |state| {
            let bind_addr = bind_addr.clone();
            let cert_path = cert_path.clone();
            let key_path = key_path.clone();
            async move {
                let _ = quic::serve_quic(&bind_addr, &cert_path, &key_path, state).await;
            }
        });
        Ok(())
    }

    pub fn spawn_tcp_if_configured(self: &Arc<Self>) -> Result<(), crate::Error> {
        let Some(bind_addr) = self.config.private_tcp_bind.clone() else {
            return Ok(());
        };
        let proxy_protocol_enabled = self.config.tcp_proxy_protocol;
        if self.config.tcp_tls_offload {
            self.spawn_with_restart_loop(move |state| {
                let bind_addr = bind_addr.clone();
                async move {
                    let _ = tcp::serve_tcp_plain(&bind_addr, state, proxy_protocol_enabled).await;
                }
            });
            return Ok(());
        }

        let (cert_path, key_path) = self.config.require_tls_identity(
            "PUSHGO_PRIVATE_TLS_CERT is required when private TCP is enabled",
            "PUSHGO_PRIVATE_TLS_KEY is required when private TCP is enabled",
        )?;
        self.spawn_with_restart_loop(move |state| {
            let bind_addr = bind_addr.clone();
            let cert_path = cert_path.clone();
            let key_path = key_path.clone();
            async move {
                let _ = tcp::serve_tcp_tls(
                    &bind_addr,
                    &cert_path,
                    &key_path,
                    state,
                    proxy_protocol_enabled,
                )
                .await;
            }
        });
        Ok(())
    }

    fn spawn_with_restart_loop<F, Fut>(self: &Arc<Self>, mut serve: F)
    where
        F: FnMut(Arc<PrivateState>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut restart_delay_secs = 1u64;
            loop {
                serve(Arc::clone(&state)).await;
                if state.is_shutting_down() {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(restart_delay_secs)) => {}
                    _ = state.wait_for_shutdown() => break,
                }
                restart_delay_secs = restart_delay_secs.saturating_mul(2).min(30);
            }
        });
    }
}
