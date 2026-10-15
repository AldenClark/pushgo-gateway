//! Protocol backpressure is applied before HTTP/2 constructs request futures.
use crate::{BoundedListener, Counters};
use axum::{Router, extract::ConnectInfo, serve::Listener};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use std::{io, sync::Arc};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    pub connections: usize,
    /// SETTINGS_MAX_CONCURRENT_STREAMS makes compliant peers queue streams;
    /// it does not reduce the existing 32 KiB legal request body allowance.
    pub streams_per_connection: u32,
}
impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connections: 128,
            streams_per_connection: 1,
        }
    }
}

pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: HttpLimits,
    counters: Arc<Counters>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    if limits.connections == 0 || limits.streams_per_connection == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "positive HTTP budgets required",
        ));
    }
    let mut listener = BoundedListener::new(listener, limits.connections, counters);
    let mut connections = JoinSet::new();
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => { break; }
            result = connections.join_next(), if !connections.is_empty() => {
                if result.is_some_and(|r| r.is_err()) {
                    return Err(io::Error::other("HTTP connection task failed"));
                }
            }
            (stream, peer) = listener.accept() => {
                let mut connection_app = app.clone();
                connection_app = connection_app.layer(axum::Extension(ConnectInfo(peer)));
                let mut connection_stop = stop.clone();
                connections.spawn(async move {
                    let mut builder = Builder::new(TokioExecutor::new());
                    builder.http2().max_concurrent_streams(limits.streams_per_connection)
                        .initial_stream_window_size(65_535).initial_connection_window_size(65_535);
                    let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(connection_app));
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {}
                        _ = connection_stop.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            return Err(io::Error::other("HTTP connection task failed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::get};
    use futures_util::{StreamExt, stream::FuturesUnordered};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn http2_stream_settings_backpressure_without_rejecting_requests() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/",
                get(
                    |State((live, peak)): State<(Arc<AtomicUsize>, Arc<AtomicUsize>)>| async move {
                        let n = live.fetch_add(1, Ordering::Relaxed) + 1;
                        peak.fetch_max(n, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        live.fetch_sub(1, Ordering::Relaxed);
                        "ok"
                    },
                ),
            )
            .with_state((live, peak.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let counters = Arc::new(Counters::default());
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            app,
            HttpLimits {
                connections: 1,
                streams_per_connection: 1,
            },
            counters.clone(),
            rx,
        ));
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        assert!(client.get(&url).send().await.unwrap().status().is_success());
        let mut requests = FuturesUnordered::new();
        for _ in 0..16 {
            requests.push(client.get(&url).send());
        }
        while let Some(response) = requests.next().await {
            assert!(response.unwrap().status().is_success());
        }
        assert_eq!(peak.load(Ordering::Relaxed), 1);
        stop.send_replace(true);
        task.await.unwrap().unwrap();
        assert_eq!(counters.http_connections.load(Ordering::Relaxed), 0);
    }
}
