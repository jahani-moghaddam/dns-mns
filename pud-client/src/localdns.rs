//! Optional local caching DNS resolver.
//!
//! The OS points its DNS at this listener. Cache hits are answered instantly
//! (faster browsing, fewer queries a hijacking resolver ever sees). Misses are
//! resolved over the tunnel by opening a stream to a configured upstream DNS
//! server (DNS-over-TCP), then cached by the answer's TTL.

use crate::config::LocalDnsConfig;
use crate::engine::{Engine, OpenState};
use pud_core::cache::{CacheKey, DnsCache};
use pud_core::dns;
use pud_core::protocol::Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Run the local DNS listener until cancelled.
pub async fn serve(cfg: LocalDnsConfig, engine: Engine) -> anyhow::Result<()> {
    let upstream: SocketAddr = cfg
        .upstream
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid local_dns.upstream '{}': {e}", cfg.upstream))?;
    let socket = Arc::new(UdpSocket::bind(&cfg.listen).await?);
    let cache = Arc::new(DnsCache::new(cfg.cache_capacity));
    tracing::info!(
        "local DNS cache listening on {} (upstream {} over tunnel)",
        cfg.listen,
        cfg.upstream
    );

    // Periodic purge of expired entries.
    {
        let cache = cache.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                cache.purge_expired();
            }
        });
    }

    let max_ttl = cfg.max_ttl_secs;
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("local dns recv error: {e}");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let socket = socket.clone();
        let cache = cache.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            handle_query(query, peer, socket, cache, engine, upstream, max_ttl).await;
        });
    }
}

async fn handle_query(
    query: Vec<u8>,
    peer: SocketAddr,
    socket: Arc<UdpSocket>,
    cache: Arc<DnsCache>,
    engine: Engine,
    upstream: SocketAddr,
    max_ttl: u32,
) {
    if query.len() < 12 {
        return;
    }
    let parsed = match dns::parse_query(&query) {
        Ok(p) => p,
        Err(_) => return,
    };
    let key = CacheKey::new(&parsed.question.name, parsed.question.qtype);
    let req_id = [query[0], query[1]];

    // Cache hit: rewrite the transaction id and answer immediately.
    if let Some(mut cached) = cache.get(&key) {
        if cached.len() >= 2 {
            cached[0] = req_id[0];
            cached[1] = req_id[1];
            let _ = socket.send_to(&cached, peer).await;
            return;
        }
    }

    // Miss: resolve over the tunnel.
    match resolve_over_tunnel(&engine, upstream, &query).await {
        Some(mut response) => {
            if let Some(ttl) = dns::min_answer_ttl(&response) {
                let ttl = ttl.min(max_ttl);
                if ttl > 0 {
                    cache.put(key, response.clone(), Duration::from_secs(ttl as u64));
                }
            }
            if response.len() >= 2 {
                response[0] = req_id[0];
                response[1] = req_id[1];
            }
            let _ = socket.send_to(&response, peer).await;
        }
        None => {
            // Reply SERVFAIL so the client does not hang.
            let mut fail = query.clone();
            if fail.len() >= 4 {
                fail[2] = 0x81; // QR=1, RD=1
                fail[3] = 0x82; // RA=1, RCODE=2 (SERVFAIL)
            }
            let _ = socket.send_to(&fail, peer).await;
        }
    }
}

/// Resolve `query` by opening a DNS-over-TCP stream to `upstream` through the
/// tunnel: send the 2-byte length-prefixed query, read the length-prefixed
/// response.
async fn resolve_over_tunnel(
    engine: &Engine,
    upstream: SocketAddr,
    query: &[u8],
) -> Option<Vec<u8>> {
    let addr = match upstream.ip() {
        std::net::IpAddr::V4(v4) => Addr::V4(v4),
        std::net::IpAddr::V6(v6) => Addr::V6(v6),
    };
    let (control, mut downlink) = engine.open(addr, upstream.port());
    if control.wait_open(Duration::from_secs(10)).await != OpenState::Open {
        return None;
    }

    // DNS-over-TCP framing: 2-byte big-endian length prefix.
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    control.send_uplink(&framed);
    control.app_close();

    let mut acc: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
        match tokio::time::timeout(remaining, downlink.recv()).await {
            Ok(Some(chunk)) => {
                acc.extend_from_slice(&chunk);
                if acc.len() >= 2 {
                    let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                    if acc.len() >= 2 + len {
                        return Some(acc[2..2 + len].to_vec());
                    }
                }
            }
            _ => return None,
        }
    }
}
