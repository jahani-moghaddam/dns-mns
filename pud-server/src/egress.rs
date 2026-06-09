//! Egress bridge: connect a stream to its upstream TCP target and pump bytes
//! between the target socket and the stream's buffers.

use crate::state::{OpenState, Stream};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedReceiver;

/// Connect to `host:port` and bridge it to `stream`.
///
/// `rx` is the receiver half of the uplink channel; the sender was already
/// installed on the stream by the caller, so uplink bytes are buffered here
/// even before the TCP connection completes (no early-data loss).
pub fn spawn_egress(
    stream: Arc<Stream>,
    host: String,
    port: u16,
    connect_timeout: Duration,
    mut rx: UnboundedReceiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        let addr = format!("{host}:{port}");
        let connect = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr)).await;
        let tcp = match connect {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(target: "egress", "connect to {addr} failed: {e}");
                stream.set_state(OpenState::Failed);
                return;
            }
            Err(_) => {
                tracing::debug!(target: "egress", "connect to {addr} timed out");
                stream.set_state(OpenState::Failed);
                return;
            }
        };
        let _ = tcp.set_nodelay(true);
        let (mut rd, mut wr) = tcp.into_split();
        stream.set_state(OpenState::Open);

        // Writer task: drain the uplink channel into the socket.
        let writer = tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if wr.write_all(&buf).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        // Reader loop: target -> downlink buffer.
        let mut buf = vec![0u8; 16 * 1024];
        let mut errored = false;
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => stream.push_downlink(&buf[..n]),
                Err(e) => {
                    tracing::debug!(target: "egress", "read from {addr} error: {e}");
                    errored = true;
                    break;
                }
            }
        }
        if errored {
            // Abnormal failure: tell the client to tear down promptly rather
            // than waiting for data that will never arrive.
            stream.mark_target_reset();
        } else {
            stream.mark_target_eof();
        }
        writer.abort();
    });
}
