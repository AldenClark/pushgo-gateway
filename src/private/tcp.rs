use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::OwnedSemaphorePermit,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;
use warp_link::warp_link_core::{PeerMeta, ServerApp, TlsMode, TransportKind, WarpLinkError};
use warp_link::warp_link_transport::FramedReader;
use warp_link::{ServerSessionIo, run_server_session};

use crate::private::{
    PrivateState,
    tls::ServerTlsIdentity,
    warp_engine::{PushgoServerApp, default_server_config},
};

const MAX_FRAME_LEN: usize = (32 * 1024) + 2;
const MAX_PROXY_LINE_BYTES: usize = 108;

#[derive(Clone)]
struct TcpServerRuntime {
    config: warp_link::warp_link_core::ServerConfig,
    app: Arc<dyn ServerApp>,
    state: Arc<PrivateState>,
    tls_acceptor: Option<TlsAcceptor>,
    proxy_protocol: ProxyProtocolConfig,
}

#[derive(Clone, Copy)]
struct ProxyProtocolConfig {
    enabled: bool,
}

struct ProxyProtocolV1;

pub async fn serve_tcp_tls(
    bind_addr: &str,
    cert_path: &str,
    key_path: &str,
    state: Arc<PrivateState>,
    proxy_protocol_enabled: bool,
) -> Result<(), String> {
    let app: Arc<dyn ServerApp> = Arc::new(PushgoServerApp::new(Arc::clone(&state)));
    let mut config = default_server_config();
    config.tcp_listen_addr = Some(bind_addr.to_string());
    config.tls_cert_path = Some(cert_path.to_string());
    config.tls_key_path = Some(key_path.to_string());
    config.tcp_alpn = "pushgo-tcp".to_string();
    config.tcp_tls_mode = TlsMode::TerminateInWarp;
    let tls_acceptor = ServerTlsIdentity::load(cert_path, key_path)?
        .into_acceptor(config.tcp_alpn.as_str(), "tcp")?;
    TcpServerRuntime::new(
        config,
        app,
        state,
        Some(tls_acceptor),
        proxy_protocol_enabled,
    )
    .serve()
    .await
}

pub async fn serve_tcp_plain(
    bind_addr: &str,
    state: Arc<PrivateState>,
    proxy_protocol_enabled: bool,
) -> Result<(), String> {
    let app: Arc<dyn ServerApp> = Arc::new(PushgoServerApp::new(Arc::clone(&state)));
    let mut config = default_server_config();
    config.tcp_listen_addr = Some(bind_addr.to_string());
    config.tcp_alpn = "pushgo-tcp".to_string();
    config.tcp_tls_mode = TlsMode::OffloadAtEdge;
    config.tls_cert_path = None;
    config.tls_key_path = None;
    TcpServerRuntime::new(config, app, state, None, proxy_protocol_enabled)
        .serve()
        .await
}

impl TcpServerRuntime {
    fn new(
        config: warp_link::warp_link_core::ServerConfig,
        app: Arc<dyn ServerApp>,
        state: Arc<PrivateState>,
        tls_acceptor: Option<TlsAcceptor>,
        proxy_protocol_enabled: bool,
    ) -> Self {
        let proxy_protocol = ProxyProtocolConfig {
            enabled: proxy_protocol_enabled,
        };
        Self {
            config,
            app,
            state,
            tls_acceptor,
            proxy_protocol,
        }
    }

    async fn serve(self) -> Result<(), String> {
        let listen_addr: SocketAddr = self
            .config
            .tcp_listen_addr
            .as_deref()
            .ok_or_else(|| "tcp_listen_addr is required".to_string())?
            .parse()
            .map_err(|err| format!("invalid tcp listen addr: {err}"))?;
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|err| format!("bind tcp listener failed: {err}"))?;
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.tcp_listener_started",
            listen_addr = %(listen_addr.to_string()),
            proxy_protocol_enabled = (self.proxy_protocol.enabled),
            tls_enabled = (self.tls_acceptor.is_some())
        );
        let mut sessions = JoinSet::new();

        loop {
            let accepted = tokio::select! {
                biased;
                _ = self.state.wait_for_shutdown() => break,
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    if let Some(Err(join_error)) = joined {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::ERROR,
                            event = "private.tcp_connection_task_failed",
                            cancelled = (join_error.is_cancelled()),
                            panicked = (join_error.is_panic())
                        );
                    }
                    continue;
                }
                accepted = listener.accept() => accepted,
            };
            let (socket, remote_addr) =
                accepted.map_err(|err| format!("accept tcp connection failed: {err}"))?;
            let permit = match self.state.try_acquire_session_admission() {
                Some(permit) => permit,
                None => {
                    let peer = PeerMeta {
                        transport: TransportKind::Tcp,
                        remote_addr: Some(remote_addr.to_string()),
                    };
                    let error = WarpLinkError::Transport(
                        "server busy: concurrent session limit reached".to_string(),
                    );
                    self.app.on_handshake_failure(peer, &error).await;
                    continue;
                }
            };
            let handshake_permit = match self.state.try_acquire_handshake_admission() {
                Some(permit) => permit,
                None => {
                    let peer = PeerMeta {
                        transport: TransportKind::Tcp,
                        remote_addr: Some(remote_addr.to_string()),
                    };
                    let error = WarpLinkError::Transport(
                        "server busy: concurrent handshake limit reached".to_string(),
                    );
                    self.app.on_handshake_failure(peer, &error).await;
                    continue;
                }
            };

            let span = tracing::info_span!(
                "private.tcp.connection",
                remote_addr = %remote_addr,
                tls_enabled = self.tls_acceptor.is_some()
            );
            let runtime = self.clone();
            let shutdown = Arc::clone(&self.state);
            sessions.spawn(
                async move {
                    tokio::select! {
                        _ = shutdown.wait_for_shutdown() => {}
                        _ = runtime.serve_connection(socket, remote_addr, permit, handshake_permit) => {}
                    }
                }
                .instrument(span),
            );
        }

        while let Some(joined) = sessions.join_next().await {
            if let Err(join_error) = joined {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::ERROR,
                    event = "private.tcp_connection_task_failed",
                    cancelled = (join_error.is_cancelled()),
                    panicked = (join_error.is_panic())
                );
            }
        }
        Ok(())
    }

    async fn serve_connection(
        self,
        mut socket: TcpStream,
        remote_addr: SocketAddr,
        permit: OwnedSemaphorePermit,
        handshake_permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit;
        let handshake_deadline =
            Instant::now() + Duration::from_millis(self.config.hello_timeout_ms.max(1));
        let peer_remote_addr = match self
            .proxy_protocol
            .resolve_peer_remote_addr(&mut socket, remote_addr, handshake_deadline)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.app
                    .on_handshake_failure(
                        PeerMeta {
                            transport: TransportKind::Tcp,
                            remote_addr: Some(remote_addr.to_string()),
                        },
                        &error,
                    )
                    .await;
                return;
            }
        };

        if let Some(acceptor) = self.tls_acceptor.clone() {
            let tls_stream = match timeout_at(handshake_deadline, acceptor.accept(socket)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    self.app
                        .on_handshake_failure(
                            PeerMeta {
                                transport: TransportKind::Tcp,
                                remote_addr: Some(peer_remote_addr),
                            },
                            &WarpLinkError::Transport(err.to_string()),
                        )
                        .await;
                    return;
                }
                Err(_) => {
                    self.app
                        .on_handshake_failure(
                            PeerMeta {
                                transport: TransportKind::Tcp,
                                remote_addr: Some(peer_remote_addr),
                            },
                            &WarpLinkError::Timeout("tcp tls handshake timeout".to_string()),
                        )
                        .await;
                    return;
                }
            };
            let (reader, writer) = tokio::io::split(tls_stream);
            let mut runtime = self;
            if runtime.apply_remaining_hello_budget(handshake_deadline) {
                runtime
                    .run_session_io(
                        reader,
                        writer,
                        peer_remote_addr,
                        handshake_deadline,
                        handshake_permit,
                    )
                    .await;
            } else {
                runtime
                    .app
                    .on_handshake_failure(
                        PeerMeta {
                            transport: TransportKind::Tcp,
                            remote_addr: Some(peer_remote_addr),
                        },
                        &WarpLinkError::Timeout("tcp hello deadline exhausted".to_string()),
                    )
                    .await;
            }
        } else {
            let (reader, writer) = tokio::io::split(socket);
            let mut runtime = self;
            if runtime.apply_remaining_hello_budget(handshake_deadline) {
                runtime
                    .run_session_io(
                        reader,
                        writer,
                        peer_remote_addr,
                        handshake_deadline,
                        handshake_permit,
                    )
                    .await;
            } else {
                runtime
                    .app
                    .on_handshake_failure(
                        PeerMeta {
                            transport: TransportKind::Tcp,
                            remote_addr: Some(peer_remote_addr),
                        },
                        &WarpLinkError::Timeout("tcp hello deadline exhausted".to_string()),
                    )
                    .await;
            }
        }
    }

    fn apply_remaining_hello_budget(&mut self, deadline: Instant) -> bool {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        if remaining.is_zero() {
            return false;
        }
        self.config.hello_timeout_ms = remaining.as_millis().clamp(1, u64::MAX as u128) as u64;
        true
    }

    async fn run_session_io<R, W>(
        self,
        reader: R,
        writer: W,
        peer_remote_addr: String,
        handshake_deadline: Instant,
        handshake_permit: OwnedSemaphorePermit,
    ) where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut io = FramedServerIo {
            reader: FramedReader::new(reader),
            writer,
            write_timeout_ms: self.config.write_timeout_ms,
            prefetched_frame: None,
        };
        let peer = PeerMeta {
            transport: TransportKind::Tcp,
            remote_addr: Some(peer_remote_addr),
        };
        let hello_frame = match timeout_at(handshake_deadline, io.recv_prefixed_frame()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(err)) => {
                self.app.on_handshake_failure(peer, &err).await;
                return;
            }
            Err(_) => {
                let error = WarpLinkError::Timeout("tcp hello deadline exhausted".to_string());
                self.app.on_handshake_failure(peer, &error).await;
                return;
            }
        };
        io.prefetched_frame = Some(hello_frame);
        drop(handshake_permit);
        if let Err(err) = run_server_session(&self.config, self.app, &mut io, peer).await {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "private.tcp_session_failed",
                error = %(err.to_string())
            );
        }
    }
}

impl ProxyProtocolConfig {
    async fn resolve_peer_remote_addr(
        self,
        socket: &mut TcpStream,
        accepted_remote_addr: SocketAddr,
        deadline: Instant,
    ) -> Result<String, WarpLinkError> {
        if !self.enabled {
            return Ok(accepted_remote_addr.to_string());
        }
        let parsed = ProxyProtocolV1::read_source_addr(socket, deadline).await?;
        Ok(parsed.unwrap_or_else(|| accepted_remote_addr.to_string()))
    }
}

impl ProxyProtocolV1 {
    async fn read_source_addr(
        socket: &mut TcpStream,
        deadline: Instant,
    ) -> Result<Option<String>, WarpLinkError> {
        let mut line = Vec::with_capacity(64);
        let read_future = async {
            loop {
                let mut byte = [0u8; 1];
                socket
                    .read_exact(&mut byte)
                    .await
                    .map_err(|err| WarpLinkError::Transport(err.to_string()))?;
                line.push(byte[0]);
                if line.len() > MAX_PROXY_LINE_BYTES {
                    return Err(WarpLinkError::Protocol(
                        "proxy protocol header too long".to_string(),
                    ));
                }
                if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
                    break;
                }
            }
            let line_str = std::str::from_utf8(&line[..line.len().saturating_sub(2)])
                .map_err(|_| {
                    WarpLinkError::Protocol("proxy protocol header is not utf8".to_string())
                })?
                .to_string();
            Self::parse_source_addr(line_str.as_str())
        };

        timeout_at(deadline, read_future)
            .await
            .map_err(|_| WarpLinkError::Timeout("proxy protocol read timeout".to_string()))?
    }

    fn parse_source_addr(line: &str) -> Result<Option<String>, WarpLinkError> {
        let mut parts = line.split_whitespace();
        let signature = parts.next().unwrap_or_default();
        if signature != "PROXY" {
            return Err(WarpLinkError::Protocol(
                "missing PROXY protocol signature".to_string(),
            ));
        }
        let family = parts.next().unwrap_or_default();
        match family {
            "UNKNOWN" => Ok(None),
            "TCP4" => {
                let source_ip = parts.next().unwrap_or_default();
                let _dest_ip = parts.next().unwrap_or_default();
                let source_port = parts.next().unwrap_or_default();
                let _dest_port = parts.next().unwrap_or_default();
                if parts.next().is_some() {
                    return Err(WarpLinkError::Protocol(
                        "invalid PROXY TCP4 header field count".to_string(),
                    ));
                }
                source_ip.parse::<Ipv4Addr>().map_err(|_| {
                    WarpLinkError::Protocol("invalid PROXY TCP4 source ip".to_string())
                })?;
                let source_port = source_port.parse::<u16>().map_err(|_| {
                    WarpLinkError::Protocol("invalid PROXY TCP4 source port".to_string())
                })?;
                Ok(Some(format!("{source_ip}:{source_port}")))
            }
            "TCP6" => {
                let source_ip = parts.next().unwrap_or_default();
                let _dest_ip = parts.next().unwrap_or_default();
                let source_port = parts.next().unwrap_or_default();
                let _dest_port = parts.next().unwrap_or_default();
                if parts.next().is_some() {
                    return Err(WarpLinkError::Protocol(
                        "invalid PROXY TCP6 header field count".to_string(),
                    ));
                }
                source_ip.parse::<Ipv6Addr>().map_err(|_| {
                    WarpLinkError::Protocol("invalid PROXY TCP6 source ip".to_string())
                })?;
                let source_port = source_port.parse::<u16>().map_err(|_| {
                    WarpLinkError::Protocol("invalid PROXY TCP6 source port".to_string())
                })?;
                Ok(Some(format!("[{source_ip}]:{source_port}")))
            }
            _ => Err(WarpLinkError::Protocol(
                "unsupported PROXY protocol family".to_string(),
            )),
        }
    }
}

struct FramedServerIo<R, W> {
    reader: FramedReader<R>,
    writer: W,
    write_timeout_ms: u64,
    prefetched_frame: Option<Vec<u8>>,
}

impl<R, W> FramedServerIo<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn send_prefixed_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
            return Err(WarpLinkError::Protocol(format!(
                "invalid frame len={} for stream",
                frame.len()
            )));
        }
        let len = frame.len() as u32;
        self.writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|err| WarpLinkError::Transport(err.to_string()))?;
        self.writer
            .write_all(frame)
            .await
            .map_err(|err| WarpLinkError::Transport(err.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|err| WarpLinkError::Transport(err.to_string()))?;
        Ok(())
    }

    async fn recv_prefixed_frame(&mut self) -> Result<Vec<u8>, WarpLinkError> {
        self.reader.read_frame().await
    }
}

#[async_trait]
impl<R, W> ServerSessionIo for FramedServerIo<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_timeout_ms),
            self.send_prefixed_frame(frame),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("tcp write timeout".to_string()))??;
        Ok(())
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        if let Some(frame) = self.prefetched_frame.take() {
            return Ok(frame);
        }
        timeout(
            Duration::from_millis(timeout_ms),
            self.recv_prefixed_frame(),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("tcp read timeout".to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::{FramedServerIo, ProxyProtocolV1};
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncWriteExt, ReadBuf},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        time::Instant,
    };
    use warp_link::{ServerSessionIo, warp_link_core::WarpLinkError};

    struct PausedFrameReader {
        first: Vec<u8>,
        first_offset: usize,
        remaining: Vec<u8>,
        remaining_offset: usize,
        first_consumed: Option<oneshot::Sender<()>>,
        released: Arc<AtomicBool>,
    }

    impl AsyncRead for PausedFrameReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.first_offset < self.first.len() {
                let count = (self.first.len() - self.first_offset).min(buf.remaining());
                buf.put_slice(&self.first[self.first_offset..self.first_offset + count]);
                self.first_offset += count;
                if self.first_offset == self.first.len()
                    && let Some(sender) = self.first_consumed.take()
                {
                    let _ = sender.send(());
                }
                return Poll::Ready(Ok(()));
            }
            if !self.released.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            let count = (self.remaining.len() - self.remaining_offset).min(buf.remaining());
            buf.put_slice(&self.remaining[self.remaining_offset..self.remaining_offset + count]);
            self.remaining_offset += count;
            Poll::Ready(Ok(()))
        }
    }

    async fn cancelled_read_keeps_partial_frame(first: Vec<u8>, remaining: Vec<u8>) {
        let (first_consumed, outbound_ready) = oneshot::channel();
        let released = Arc::new(AtomicBool::new(false));
        let reader = PausedFrameReader {
            first,
            first_offset: 0,
            remaining,
            remaining_offset: 0,
            first_consumed: Some(first_consumed),
            released: Arc::clone(&released),
        };
        let mut io = FramedServerIo {
            reader: warp_link::warp_link_transport::FramedReader::new(reader),
            writer: tokio::io::sink(),
            write_timeout_ms: 1_000,
            prefetched_frame: None,
        };

        tokio::select! {
            result = io.recv_frame(1_000) => panic!("partial frame unexpectedly completed: {result:?}"),
            result = outbound_ready => result.expect("outbound wake should follow partial read"),
        }
        released.store(true, Ordering::SeqCst);
        let frame = io
            .recv_frame(1_000)
            .await
            .expect("frame should resume after outbound wake");
        assert_eq!(frame, b"abcdef");
    }

    #[tokio::test]
    async fn outbound_wake_preserves_partial_length_prefix() {
        cancelled_read_keeps_partial_frame(vec![0, 0], [vec![0, 6], b"abcdef".to_vec()].concat())
            .await;
    }

    #[tokio::test]
    async fn outbound_wake_preserves_partial_payload() {
        cancelled_read_keeps_partial_frame(
            [vec![0, 0, 0, 6], b"ab".to_vec()].concat(),
            b"cdef".to_vec(),
        )
        .await;
    }

    #[test]
    fn parse_proxy_tcp4_source_addr() {
        let parsed =
            ProxyProtocolV1::parse_source_addr("PROXY TCP4 203.0.113.8 198.51.100.2 54321 5223")
                .expect("proxy header should parse");
        assert_eq!(parsed.as_deref(), Some("203.0.113.8:54321"));
    }

    #[test]
    fn parse_proxy_tcp6_source_addr() {
        let parsed = ProxyProtocolV1::parse_source_addr(
            "PROXY TCP6 240e:390:1111::8 2408:4001:1111::2 54321 5223",
        )
        .expect("proxy header should parse");
        assert_eq!(parsed.as_deref(), Some("[240e:390:1111::8]:54321"));
    }

    #[test]
    fn parse_proxy_unknown_family() {
        let parsed = ProxyProtocolV1::parse_source_addr("PROXY UNKNOWN");
        assert!(parsed.is_ok());
        assert_eq!(parsed.expect("unknown should be accepted"), None);
    }

    #[test]
    fn reject_non_proxy_payload() {
        let parsed = ProxyProtocolV1::parse_source_addr("GET /private/ws HTTP/1.1");
        assert!(parsed.is_err());
    }

    #[tokio::test]
    async fn proxy_header_slowloris_cannot_renew_the_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("test address should exist");
        let mut client = TcpStream::connect(addr)
            .await
            .expect("test client should connect");
        let (mut server, _) = listener.accept().await.expect("server should accept");
        client
            .write_all(b"P")
            .await
            .expect("partial proxy header should write");

        let result = ProxyProtocolV1::read_source_addr(
            &mut server,
            Instant::now() + Duration::from_millis(50),
        )
        .await;

        assert!(matches!(result, Err(WarpLinkError::Timeout(_))));
    }
}
