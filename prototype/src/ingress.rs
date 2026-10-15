//! Reserve connection memory before Axum creates a connection task.
use crate::Counters;
use axum::serve::Listener;
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

pub struct BoundedListener {
    listener: TcpListener,
    permits: Arc<Semaphore>,
    counters: Arc<Counters>,
}
impl BoundedListener {
    pub fn new(listener: TcpListener, limit: usize, counters: Arc<Counters>) -> Self {
        assert!(limit > 0);
        Self {
            listener,
            permits: Arc::new(Semaphore::new(limit)),
            counters,
        }
    }
}
pub struct BoundedStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    counters: Arc<Counters>,
}
impl Listener for BoundedListener {
    type Io = BoundedStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("listener permit never closed");
        // Preserve Axum's normal accept error/backoff behavior.
        let (stream, address) = <TcpListener as Listener>::accept(&mut self.listener).await;
        let live = self
            .counters
            .http_connections
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        self.counters
            .peak_http_connections
            .fetch_max(live, Ordering::Relaxed);
        (
            BoundedStream {
                stream,
                _permit: permit,
                counters: self.counters.clone(),
            },
            address,
        )
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
impl Drop for BoundedStream {
    fn drop(&mut self) {
        self.counters
            .http_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}
impl AsyncRead for BoundedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for BoundedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buffer)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    #[tokio::test]
    async fn connection_budget_precedes_accept_and_releases_on_actual_stream_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let counters = Arc::new(Counters::default());
        let mut bounded = BoundedListener::new(listener, 2, counters.clone());
        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(TcpStream::connect(address).await.unwrap());
        }
        let (first, _) = bounded.accept().await;
        let (second, _) = bounded.accept().await;
        let mut third = Box::pin(bounded.accept());
        assert!(third.as_mut().now_or_never().is_none());
        assert_eq!(counters.http_connections.load(Ordering::Relaxed), 2);
        drop(first);
        let (third, _) = third.await;
        assert_eq!(counters.http_connections.load(Ordering::Relaxed), 2);
        assert_eq!(counters.peak_http_connections.load(Ordering::Relaxed), 2);
        drop((second, third, clients));
        assert_eq!(counters.http_connections.load(Ordering::Relaxed), 0);
    }
}
