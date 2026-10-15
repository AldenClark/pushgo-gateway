//! Structured transport adapters around locked Warp's public session engine.
//! Framing/heartbeat/version negotiation remain Warp-owned. No detached sessions.
use crate::private_runtime::PrivateRuntime;
use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use warp_link::{
    ServerSessionIo, WsUpgradeIo, run_server_session,
    warp_link_core::{
        AckMsg, AuthError, AuthRequest, AuthResponse, DisconnectReason, OutboundMsg, PeerMeta,
        ServerApp, ServerConfig, SessionControl, SessionCtx, TlsMode, TransportKind, WarpLinkError,
        WireProfile,
    },
    warp_link_transport::{FramedReader, write_prefixed_frame},
};

pub struct PrivateListener {
    stop: watch::Sender<bool>,
    join: Option<JoinHandle<Result<(), WarpLinkError>>>,
    runtime: PrivateRuntime,
    pub local_addr: SocketAddr,
}
impl PrivateListener {
    pub fn stop_accepting(&self) {
        self.stop.send_replace(true);
    }
    /// Stops acceptance, then joins every handshake/session. A timeout retains the
    /// join handle; callers must not release the database owner on this error.
    pub async fn shutdown(&mut self) -> Result<(), WarpLinkError> {
        self.runtime.begin_shutdown();
        self.stop_accepting();
        if let Some(join) = self.join.as_mut() {
            timeout(Duration::from_secs(30), join)
                .await
                .map_err(|_| {
                    WarpLinkError::Timeout("Private listener sessions have not joined".into())
                })?
                .map_err(|_| WarpLinkError::Internal("Private listener owner panicked".into()))??;
        }
        self.join.take();
        Ok(())
    }
}
impl Drop for PrivateListener {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.runtime
                .fence("Private listener dropped without joined shutdown");
            let _ = self.stop.send(true);
        }
    }
}
fn error(e: impl std::fmt::Display) -> WarpLinkError {
    WarpLinkError::Transport(e.to_string())
}
pub fn server_config() -> ServerConfig {
    ServerConfig {
        max_concurrent_sessions: 8192,
        write_timeout_ms: 10_000,
        max_outbound_wait_ms: 15_000,
        ..ServerConfig::default()
    }
}
fn tls(config: &ServerConfig, alpn: &str) -> Result<rustls::ServerConfig, WarpLinkError> {
    let cert = config
        .tls_cert_path
        .as_deref()
        .ok_or_else(|| error("certificate required"))?;
    let key = config
        .tls_key_path
        .as_deref()
        .ok_or_else(|| error("private key required"))?;
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    if certs.is_empty() {
        return Err(error("empty certificate chain"));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(error)?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(error)?;
    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Ok(tls)
}
struct StreamIo<R, W> {
    reader: FramedReader<R>,
    writer: W,
    write_ms: u64,
}
#[async_trait]
impl<R, W> ServerSessionIo for StreamIo<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_ms),
            write_prefixed_frame(&mut self.writer, frame),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("Private frame write timeout".into()))?
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        timeout(Duration::from_millis(timeout_ms), self.reader.read_frame())
            .await
            .map_err(|_| WarpLinkError::Timeout("Private frame read timeout".into()))?
    }
}
/// Tracks successful business auth even when transport fails before WELCOME.
/// The final cleanup runs in the owning session task, never from Drop/spawn.
struct ScopedApp {
    base: Arc<dyn ServerApp>,
    runtime: PrivateRuntime,
    session: Mutex<Option<SessionCtx>>,
}
impl ScopedApp {
    fn new(runtime: PrivateRuntime) -> Arc<Self> {
        Arc::new(Self {
            base: runtime.app(),
            runtime,
            session: Mutex::new(None),
        })
    }
    async fn finish(&self) {
        let session = self.session.lock().unwrap().take();
        if let Some(session) = session {
            self.runtime.disconnect(&session).await;
        }
    }
}
#[async_trait]
impl ServerApp for ScopedApp {
    fn wire_profile(&self) -> Arc<dyn WireProfile> {
        self.base.wire_profile()
    }
    async fn auth(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        let response = self.base.auth(request).await?;
        if let AuthResponse::ConnectAccepted(s) = &response {
            *self.session.lock().unwrap() = Some(s.clone());
        }
        Ok(response)
    }
    async fn wait_outbound(&self, s: &SessionCtx, ms: u64) -> Option<OutboundMsg> {
        self.base.wait_outbound(s, ms).await
    }
    async fn on_ack(&self, s: &SessionCtx, a: AckMsg) {
        self.base.on_ack(s, a).await;
    }
    async fn on_disconnect(&self, s: &SessionCtx, r: DisconnectReason) {
        self.base.on_disconnect(s, r).await;
        self.session.lock().unwrap().take();
    }
    fn on_session_control(&self, s: &SessionCtx, c: SessionControl) {
        self.base.on_session_control(s, c);
    }
}
async fn stream_session<S>(runtime: PrivateRuntime, config: ServerConfig, stream: S, peer: PeerMeta)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut io = StreamIo {
        reader: FramedReader::new(reader),
        writer,
        write_ms: config.write_timeout_ms,
    };
    let app = ScopedApp::new(runtime);
    let base: Arc<dyn ServerApp> = app.clone();
    let _ = run_server_session(&config, base, &mut io, peer).await;
    app.finish().await;
}
pub async fn start_tcp(
    runtime: PrivateRuntime,
    config: ServerConfig,
) -> Result<PrivateListener, WarpLinkError> {
    let addr: SocketAddr = config
        .tcp_listen_addr
        .as_deref()
        .ok_or_else(|| error("tcp_listen_addr required"))?
        .parse()
        .map_err(error)?;
    let acceptor = if config.tcp_tls_mode == TlsMode::TerminateInWarp {
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls(
            &config,
            &config.tcp_alpn,
        )?)))
    } else {
        None
    };
    let listener = TcpListener::bind(addr).await.map_err(error)?;
    let local_addr = listener.local_addr().map_err(error)?;
    let (stop, mut stopped) = watch::channel(false);
    let owned = runtime.clone();
    let join = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        let mut failed = false;
        loop {
            tokio::select! {
                changed=stopped.changed()=> { if changed.is_err() || *stopped.borrow() { break; } },
                completed=sessions.join_next(),if !sessions.is_empty()=> { if completed.is_some_and(|v|v.is_err()) { failed=true;owned.fence("Private TCP session task panicked"); } },
                accepted=listener.accept()=> {
                    let (stream,remote)=match accepted { Ok(value)=>value,Err(_)=> { failed=true;owned.fence("Private TCP accept failed");break; } };let permit=match owned.try_io_permit() { Ok(permit)=>permit,Err(_)=>continue };let runtime=owned.clone();let cfg=config.clone();let tls=acceptor.clone();
                    sessions.spawn(async move { let _permit=permit;let peer=PeerMeta { transport:TransportKind::Tcp,remote_addr:Some(remote.to_string()) };if let Some(acceptor)=tls { if let Ok(Ok(stream))=timeout(Duration::from_millis(cfg.hello_timeout_ms),acceptor.accept(stream)).await { stream_session(runtime,cfg,stream,peer).await; } } else { stream_session(runtime,cfg,stream,peer).await; } });
                },
            }
        }
        drop(listener);
        while let Some(result) = sessions.join_next().await {
            if result.is_err() {
                owned.fence("Private TCP session join failed");
                failed = true;
            }
        }
        if failed {
            Err(error("Private listener session failure; all tasks joined"))
        } else {
            Ok(())
        }
    });
    Ok(PrivateListener {
        stop,
        join: Some(join),
        runtime,
        local_addr,
    })
}
pub async fn start_quic(
    runtime: PrivateRuntime,
    config: ServerConfig,
) -> Result<PrivateListener, WarpLinkError> {
    if config.quic_tls_mode != TlsMode::TerminateInWarp {
        return Err(error("QUIC requires TLS termination or L4 passthrough"));
    }
    let addr: SocketAddr = config
        .quic_listen_addr
        .as_deref()
        .ok_or_else(|| error("quic_listen_addr required"))?
        .parse()
        .map_err(error)?;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls(&config, &config.quic_alpn)?)
            .map_err(error)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // Apply budgets before Quinn creates application session tasks. Stream
    // windows exert flow control; they do not reduce the legal frame size.
    server.max_incoming(config.max_concurrent_sessions);
    server.incoming_buffer_size(64 * 1024);
    server.incoming_buffer_size_total(16 * 1024 * 1024);
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.stream_receive_window((64u32 * 1024).into());
    transport.receive_window((64u32 * 1024).into());
    transport.send_window(64 * 1024);
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(72)).map_err(error)?,
    ));
    server.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server, addr).map_err(error)?;
    let local_addr = endpoint.local_addr().map_err(error)?;
    let (stop, mut stopped) = watch::channel(false);
    let owned = runtime.clone();
    let join = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        let mut failed = false;
        loop {
            tokio::select! {
                changed=stopped.changed()=> { if changed.is_err() || *stopped.borrow() { break; } },
                completed=sessions.join_next(),if !sessions.is_empty()=> { if completed.is_some_and(|v|v.is_err()) { failed=true;owned.fence("Private QUIC session task panicked"); } },
                incoming=endpoint.accept()=> {
                    let Some(incoming)=incoming else { break; };let remote=incoming.remote_address();let permit=match owned.try_io_permit() { Ok(permit)=>permit,Err(_)=> { incoming.refuse();continue; } };let runtime=owned.clone();let cfg=config.clone();
                    sessions.spawn(async move {
                        let _permit=permit;let Ok(Ok(connection))=timeout(Duration::from_millis(cfg.hello_timeout_ms),incoming).await else { return; };
                        let Ok(Ok((send,recv)))=timeout(Duration::from_millis(cfg.hello_timeout_ms),connection.accept_bi()).await else { connection.close(0u32.into(),b"stream timeout");return; };
                        let mut io=StreamIo { reader:FramedReader::new(recv),writer:send,write_ms:cfg.write_timeout_ms };let app=ScopedApp::new(runtime);let base:Arc<dyn ServerApp>=app.clone();let peer=PeerMeta { transport:TransportKind::Quic,remote_addr:Some(remote.to_string()) };let _=run_server_session(&cfg,base,&mut io,peer).await;app.finish().await;connection.close(0u32.into(),b"session ended");
                    });
                },
            }
        }
        endpoint.close(0u32.into(), b"server shutdown");
        while let Some(result) = sessions.join_next().await {
            if result.is_err() {
                owned.fence("Private QUIC session join failed");
                failed = true;
            }
        }
        endpoint.wait_idle().await;
        if failed {
            Err(error("Private listener session failure; all tasks joined"))
        } else {
            Ok(())
        }
    });
    Ok(PrivateListener {
        stop,
        join: Some(join),
        runtime,
        local_addr,
    })
}
/// HTTP owner must validate pushgo-private.v1 before upgrading and join this
/// future before runtime.shutdown()/database owner release.
pub async fn serve_wss<I: WsUpgradeIo>(
    runtime: PrivateRuntime,
    config: ServerConfig,
    io: I,
) -> Result<(), WarpLinkError> {
    let _permit = runtime.try_io_permit().map_err(error)?;
    let app = ScopedApp::new(runtime);
    let base: Arc<dyn ServerApp> = app.clone();
    let result = warp_link::serve_wss_embedded_with_app(config, base, io).await;
    app.finish().await;
    result
}
