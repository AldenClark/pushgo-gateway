//! Bounded MQTT5 protocol client for the actual normal Gateway process.
use bytes::BytesMut;
use mqttbytes::v5::{self, Connect, ConnectProperties, ConnectReturnCode, Packet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, Instant, timeout_at},
};

pub struct ProductMqttClient {
    stream: TcpStream,
    buffer: BytesMut,
}

/// Per-call counters only: no clock, additional socket operation or packet log.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "Shared MQTT client; only the opt-in load driver reads diagnostic counters"
)]
pub struct ProductMqttReceiveStats {
    pub buffered_before: usize,
    pub buffered_after: usize,
    pub buffered_peak: usize,
    /// stream.read attempts, including one whose deadline expires; not syscalls.
    pub read_calls: u64,
    pub read_bytes: u64,
    /// Successful mqttbytes packet parses, including non-PUBLISH packets.
    pub ready_parses: u64,
}

impl ProductMqttClient {
    pub async fn connect(port: u16, device_key: &str, gateway_token: &str) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect actual product MQTT listener");
        let mut client = Self {
            stream,
            buffer: BytesMut::with_capacity(4096),
        };
        let mut connect = Connect::new(device_key);
        connect.set_login(gateway_token, "");
        connect.properties = Some(ConnectProperties {
            session_expiry_interval: None,
            receive_maximum: None,
            max_packet_size: None,
            topic_alias_max: None,
            request_response_info: None,
            request_problem_info: None,
            user_properties: vec![("device_type".into(), "subscribe".into())],
            authentication_method: None,
            authentication_data: None,
        });
        let mut encoded = BytesMut::new();
        connect
            .write(&mut encoded)
            .expect("MQTT CONNECT should encode");
        client
            .stream
            .write_all(&encoded)
            .await
            .expect("MQTT CONNECT should send");
        match client
            .receive(Duration::from_secs(5))
            .await
            .expect("product CONNACK should arrive")
        {
            Packet::ConnAck(ack) => assert_eq!(ack.code, ConnectReturnCode::Success),
            other => panic!("expected product CONNACK, got {other:?}"),
        }
        client
    }

    pub async fn receive(&mut self, wait: Duration) -> Option<Packet> {
        self.receive_with_stats(wait, false).await.0
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// The original receive loop and deadline, with optional fixed counters.
    /// A timeout can retain partial bytes; ready_parses is not a PUBLISH count.
    pub async fn receive_with_stats(
        &mut self,
        wait: Duration,
        observe: bool,
    ) -> (Option<Packet>, Option<ProductMqttReceiveStats>) {
        let mut stats = observe.then(|| ProductMqttReceiveStats {
            buffered_before: self.buffered_bytes(),
            buffered_peak: self.buffered_bytes(),
            ..ProductMqttReceiveStats::default()
        });
        let deadline = Instant::now() + wait;
        loop {
            match v5::read(&mut self.buffer, 131072) {
                Ok(packet) => {
                    if let Some(stats) = &mut stats {
                        stats.ready_parses += 1;
                        stats.buffered_after = self.buffered_bytes();
                    }
                    return (Some(packet), stats);
                }
                Err(mqttbytes::Error::InsufficientBytes(_)) => {
                    let mut chunk = [0u8; 4096];
                    if let Some(stats) = &mut stats {
                        stats.read_calls += 1;
                    }
                    let read = match timeout_at(deadline, self.stream.read(&mut chunk)).await {
                        Ok(read) => read.expect("product MQTT read should complete"),
                        Err(_) => {
                            if let Some(stats) = &mut stats {
                                stats.buffered_after = self.buffered_bytes();
                            }
                            return (None, stats);
                        }
                    };
                    assert!(read > 0, "product MQTT connection closed unexpectedly");
                    self.buffer.extend_from_slice(&chunk[..read]);
                    if let Some(stats) = &mut stats {
                        stats.read_bytes += read as u64;
                        stats.buffered_peak = stats.buffered_peak.max(self.buffered_bytes());
                    }
                    assert!(
                        self.buffer.len() <= 131072 + 4096,
                        "test parser buffer must remain bounded"
                    );
                }
                Err(error) => panic!("product MQTT packet should decode: {error:?}"),
            }
        }
    }

    #[allow(
        dead_code,
        reason = "Shared integration-test client; expiry assertions are used by blackbox_private_fallback"
    )]
    pub async fn assert_no_delivery(&mut self, wait: Duration) {
        assert!(
            self.receive(wait).await.is_none(),
            "expired ordinary message must not start a new MQTT PUBLISH"
        );
    }

    /// Sending PUBACK alone is not evidence of durable ledger convergence.
    #[allow(dead_code)]
    pub async fn acknowledge(&mut self, packet_id: u16) {
        let mut encoded = BytesMut::new();
        v5::PubAck::new(packet_id)
            .write(&mut encoded)
            .expect("MQTT PUBACK should encode");
        self.stream
            .write_all(&encoded)
            .await
            .expect("MQTT PUBACK should send");
    }

    /// Keep the actual product connection alive during long idle observations.
    #[allow(dead_code)]
    pub async fn ping(&mut self) {
        self.stream
            .write_all(&[0xc0, 0x00])
            .await
            .expect("MQTT PINGREQ should send");
    }
}
