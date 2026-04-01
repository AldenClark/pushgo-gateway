use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rustls::{
    ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use warp_link::warp_link_core::{PeerMeta, ServerApp, TlsMode, TransportKind, WarpLinkError};
use warp_link::{ServerSessionIo, run_server_session};

use crate::private::{
    PrivateState,
    warp_engine::{PushgoServerApp, default_server_config},
};

const MAX_FRAME_LEN: usize = (32 * 1024) + 2;
const MAX_PROXY_LINE_BYTES: usize = 108;

#[derive(Clone)]
struct TcpServerRuntime {
    config: warp_link::warp_link_core::ServerConfig,
    app: Arc<dyn ServerApp>,
    tls_acceptor: Option<TlsAcceptor>,
    proxy_protocol: ProxyProtocolConfig,
}

#[derive(Clone, Copy)]
struct ProxyProtocolConfig {
    enabled: bool,
    hello_timeout_ms: u64,
}

struct ProxyProtocolV1;

struct TcpTlsIdentity {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

pub async fn serve_tcp_tls(
    bind_addr: &str,
    cert_path: &str,
    key_path: &str,
    state: Arc<PrivateState>,
    proxy_protocol_enabled: bool,
) -> Result<(), String> {
    let app: Arc<dyn ServerApp> = Arc::new(PushgoServerApp::new(state));
    let mut config = default_server_config();
    config.tcp_listen_addr = Some(bind_addr.to_string());
    config.tls_cert_path = Some(cert_path.to_string());
    config.tls_key_path = Some(key_path.to_string());
    config.tcp_alpn = "pushgo-tcp".to_string();
    config.tcp_tls_mode = TlsMode::TerminateInWarp;
    let tls_acceptor =
        TcpTlsIdentity::load(cert_path, key_path)?.into_acceptor(config.tcp_alpn.as_str())?;
    TcpServerRuntime::new(config, app, Some(tls_acceptor), proxy_protocol_enabled)
        .serve()
        .await
}

pub async fn serve_tcp_plain(
    bind_addr: &str,
    state: Arc<PrivateState>,
    proxy_protocol_enabled: bool,
) -> Result<(), String> {
    let app: Arc<dyn ServerApp> = Arc::new(PushgoServerApp::new(state));
    let mut config = default_server_config();
    config.tcp_listen_addr = Some(bind_addr.to_string());
    config.tcp_alpn = "pushgo-tcp".to_string();
    config.tcp_tls_mode = TlsMode::OffloadAtEdge;
    config.tls_cert_path = None;
    config.tls_key_path = None;
    TcpServerRuntime::new(config, app, None, proxy_protocol_enabled)
        .serve()
        .await
}

impl TcpServerRuntime {
    fn new(
        config: warp_link::warp_link_core::ServerConfig,
        app: Arc<dyn ServerApp>,
        tls_acceptor: Option<TlsAcceptor>,
        proxy_protocol_enabled: bool,
    ) -> Self {
        let proxy_protocol = ProxyProtocolConfig {
            enabled: proxy_protocol_enabled,
            hello_timeout_ms: config.hello_timeout_ms,
        };
        Self {
            config,
            app,
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
        let session_limiter = Arc::new(Semaphore::new(self.config.max_concurrent_sessions.max(1)));

        loop {
            let (socket, remote_addr) = listener
                .accept()
                .await
                .map_err(|err| format!("accept tcp connection failed: {err}"))?;
            let permit = match Arc::clone(&session_limiter).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
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

            tokio::spawn(self.clone().serve_connection(socket, remote_addr, permit));
        }
    }

    async fn serve_connection(
        self,
        mut socket: TcpStream,
        remote_addr: SocketAddr,
        permit: OwnedSemaphorePermit,
    ) {
        let _permit = permit;
        let peer_remote_addr = match self
            .proxy_protocol
            .resolve_peer_remote_addr(&mut socket, remote_addr)
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
            let tls_stream = match acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(err) => {
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
            };
            let (reader, writer) = tokio::io::split(tls_stream);
            self.run_session_io(reader, writer, peer_remote_addr).await;
        } else {
            let (reader, writer) = tokio::io::split(socket);
            self.run_session_io(reader, writer, peer_remote_addr).await;
        }
    }

    async fn run_session_io<R, W>(self, reader: R, writer: W, peer_remote_addr: String)
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut io = FramedServerIo {
            reader,
            writer,
            write_timeout_ms: self.config.write_timeout_ms,
        };
        let peer = PeerMeta {
            transport: TransportKind::Tcp,
            remote_addr: Some(peer_remote_addr),
        };
        let _ = run_server_session(&self.config, self.app, &mut io, peer).await;
    }
}

impl ProxyProtocolConfig {
    async fn resolve_peer_remote_addr(
        self,
        socket: &mut TcpStream,
        accepted_remote_addr: SocketAddr,
    ) -> Result<String, WarpLinkError> {
        if !self.enabled {
            return Ok(accepted_remote_addr.to_string());
        }
        let parsed = ProxyProtocolV1::read_source_addr(socket, self.hello_timeout_ms).await?;
        Ok(parsed.unwrap_or_else(|| accepted_remote_addr.to_string()))
    }
}

impl ProxyProtocolV1 {
    async fn read_source_addr(
        socket: &mut TcpStream,
        timeout_ms: u64,
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
                if line.len() >= 2 && line[line.len() - 2..] == [b'\r', b'\n'] {
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

        timeout(Duration::from_millis(timeout_ms.max(1)), read_future)
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

impl TcpTlsIdentity {
    fn load(cert_path: &str, key_path: &str) -> Result<Self, String> {
        Ok(Self {
            certs: Self::load_certs(cert_path)?,
            key: Self::load_key(key_path)?,
        })
    }

    fn into_acceptor(self, alpn: &str) -> Result<TlsAcceptor, String> {
        let mut tls = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs, self.key)
            .map_err(|err| format!("invalid tcp tls cert/key: {err}"))?;
        tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
        Ok(TlsAcceptor::from(Arc::new(tls)))
    }

    fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|err| format!("{path}: {err}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("read certs failed: {err}"))?;
        if certs.is_empty() {
            return Err("empty certificate chain".to_string());
        }
        Ok(certs)
    }

    fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
        PrivateKeyDer::from_pem_file(path).map_err(|err| format!("read private key failed: {err}"))
    }
}

struct FramedServerIo<R, W> {
    reader: R,
    writer: W,
    write_timeout_ms: u64,
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
        let mut len_bytes = [0u8; 4];
        self.reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(|err| WarpLinkError::Transport(err.to_string()))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_FRAME_LEN {
            return Err(WarpLinkError::Protocol(format!(
                "invalid stream frame length {len}"
            )));
        }
        let mut frame = vec![0u8; len];
        self.reader
            .read_exact(&mut frame)
            .await
            .map_err(|err| WarpLinkError::Transport(err.to_string()))?;
        Ok(frame)
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
    use super::ProxyProtocolV1;

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
}
