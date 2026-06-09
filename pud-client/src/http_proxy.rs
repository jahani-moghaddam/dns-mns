//! Minimal HTTP CONNECT proxy that bridges into tunnel streams, so apps that
//! speak an HTTP proxy (rather than SOCKS5) can use the tunnel.
//!
//! Only the `CONNECT` method is supported. CONNECT tunnels an arbitrary TCP
//! connection (which is how HTTPS and most proxied traffic works); plain-HTTP
//! origin forwarding (`GET http://host/path`) is intentionally not implemented.

use crate::engine::{Engine, OpenState};
use anyhow::{bail, Result};
use pud_core::protocol::Addr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Run the HTTP CONNECT listener, spawning a task per accepted connection.
pub async fn serve(listen: &str, engine: Engine, open_timeout: Duration) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!("HTTP CONNECT proxy listening on {listen}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("http accept error: {e}");
                continue;
            }
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, engine, open_timeout).await {
                tracing::debug!("http connection {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(mut tcp: TcpStream, engine: Engine, open_timeout: Duration) -> Result<()> {
    tcp.set_nodelay(true).ok();

    let (method, target) = read_request_head(&mut tcp).await?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        let _ = tcp
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await;
        bail!("only CONNECT is supported, got {method}");
    }

    let (host, port) = split_host_port(&target)?;
    let addr = host_to_addr(&host);

    let (control, downlink) = engine.open(addr, port);
    match control.wait_open(open_timeout).await {
        OpenState::Open => {
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        _ => {
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            bail!("upstream open failed for {host}:{port}");
        }
    }

    crate::socks::bridge(tcp, control, downlink).await;
    Ok(())
}

/// Read the request head (until CRLFCRLF) and return (method, target).
async fn read_request_head(tcp: &mut TcpStream) -> Result<(String, String)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            bail!("eof during request head");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("request head too large");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        bail!("malformed request line");
    }
    Ok((method, target))
}

/// Split a CONNECT target ("host:port" or "[v6]:port") into host and port.
fn split_host_port(target: &str) -> Result<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        // IPv6 literal: [::1]:443
        let end = rest.find(']').ok_or_else(|| anyhow::anyhow!("bad ipv6 target"))?;
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("missing port"))?;
        return Ok((host, port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target missing port"))?;
    let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("bad port"))?;
    Ok((host.to_string(), port))
}

/// Convert a host string to a protocol Addr (IP literal or domain).
fn host_to_addr(host: &str) -> Addr {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        Addr::V4(v4)
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        Addr::V6(v6)
    } else {
        Addr::Domain(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port() {
        assert_eq!(split_host_port("example.com:443").unwrap(), ("example.com".into(), 443));
        assert_eq!(split_host_port("[::1]:8443").unwrap(), ("::1".into(), 8443));
        assert!(split_host_port("noport").is_err());
    }

    #[test]
    fn host_to_addr_classifies() {
        assert!(matches!(host_to_addr("1.2.3.4"), Addr::V4(_)));
        assert!(matches!(host_to_addr("::1"), Addr::V6(_)));
        assert!(matches!(host_to_addr("example.com"), Addr::Domain(_)));
    }
}
