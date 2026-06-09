//! Minimal SOCKS5 server (CONNECT) that bridges local TCP connections into
//! tunnel streams.

use crate::engine::{Engine, OpenState, StreamControl};
use anyhow::{bail, Result};
use pud_core::protocol::Addr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;

const SOCKS_VERSION: u8 = 5;
const CMD_CONNECT: u8 = 1;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;

/// Run the SOCKS5 listener, spawning a task per accepted connection.
pub async fn serve(listen: &str, engine: Engine, open_timeout: Duration) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!("SOCKS5 listening on {listen}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, engine, open_timeout).await {
                tracing::debug!("socks connection {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(mut tcp: TcpStream, engine: Engine, open_timeout: Duration) -> Result<()> {
    tcp.set_nodelay(true).ok();
    handshake(&mut tcp).await?;
    let (addr, port) = read_request(&mut tcp).await?;

    let (control, downlink) = engine.open(addr.clone(), port);
    match control.wait_open(open_timeout).await {
        OpenState::Open => {
            // SOCKS success reply with a dummy bound address.
            tcp.write_all(&[SOCKS_VERSION, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await?;
        }
        _ => {
            // Connection refused / host unreachable.
            tcp.write_all(&[SOCKS_VERSION, 0x05, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("upstream open failed for {addr:?}:{port}");
        }
    }

    bridge(tcp, control, downlink).await;
    Ok(())
}

/// SOCKS5 method negotiation: accept "no authentication".
async fn handshake(tcp: &mut TcpStream) -> Result<()> {
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version {}", head[0]);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    tcp.read_exact(&mut methods).await?;
    // We only support "no auth" (0x00).
    if methods.contains(&0x00) {
        tcp.write_all(&[SOCKS_VERSION, 0x00]).await?;
        Ok(())
    } else {
        tcp.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        bail!("no acceptable SOCKS auth method");
    }
}

/// Parse a SOCKS5 CONNECT request, returning the target address and port.
async fn read_request(tcp: &mut TcpStream) -> Result<(Addr, u16)> {
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        bail!("bad request version");
    }
    if head[1] != CMD_CONNECT {
        // Command not supported.
        tcp.write_all(&[SOCKS_VERSION, 0x07, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
            .await?;
        bail!("only CONNECT is supported");
    }
    let addr = match head[3] {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            tcp.read_exact(&mut b).await?;
            Addr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            tcp.read_exact(&mut b).await?;
            Addr::V6(Ipv6Addr::from(b))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut name).await?;
            Addr::Domain(String::from_utf8_lossy(&name).into_owned())
        }
        other => bail!("unknown SOCKS atyp {other}"),
    };
    let mut port = [0u8; 2];
    tcp.read_exact(&mut port).await?;
    Ok((addr, u16::from_be_bytes(port)))
}

/// Bridge bytes between the local TCP socket and the tunnel stream until either
/// side closes. Shared with the HTTP CONNECT proxy.
pub(crate) async fn bridge(
    tcp: TcpStream,
    control: StreamControl,
    mut downlink: UnboundedReceiver<Vec<u8>>,
) {
    let (mut rd, mut wr) = tcp.into_split();

    // Downlink: server -> local socket.
    let down = tokio::spawn(async move {
        while let Some(chunk) = downlink.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    // Uplink: local socket -> server.
    let mut buf = vec![0u8; 16 * 1024];
    let mut errored = false;
    loop {
        match rd.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => control.send_uplink(&buf[..n]),
            Err(_) => {
                errored = true;
                break;
            }
        }
    }
    if errored {
        control.reset();
    } else {
        control.app_close();
    }

    // Give the downlink writer a chance to flush remaining data, then stop.
    let _ = down.await;
}
