//! UDP transport with per-resolver socket reuse and DNS-ID demultiplexing.
//!
//! The naive approach binds a fresh UDP socket per query, which adds a syscall
//! and setup cost on the hot path. Instead we keep one connected socket per
//! resolver and a background receive loop that routes each reply to the waiting
//! query by its DNS transaction id. This also gives us a natural place to race
//! a stalled query across two resolvers and take the first reply.
//!
//! The transport owns transaction-id allocation: callers hand in a fully built
//! DNS query and the transport rewrites its 2-byte id to a value unique among
//! that resolver's in-flight queries, so a large window never collides ids.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// One reusable connected socket to a single resolver.
struct ResolverConn {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>,
    next_id: Mutex<u16>,
}

impl ResolverConn {
    /// Allocate a transaction id not currently in flight on this connection.
    fn alloc_id(&self) -> u16 {
        let pending = self.pending.lock();
        let mut id = self.next_id.lock();
        for _ in 0..=u16::MAX {
            *id = id.wrapping_add(1);
            if !pending.contains_key(&*id) {
                return *id;
            }
        }
        *id // all ids in flight (absurd); reuse and let the demux drop it
    }
}

/// A pool of reusable per-resolver UDP connections.
pub struct Transport {
    conns: HashMap<SocketAddr, Arc<ResolverConn>>,
}

impl Transport {
    /// Bind one socket per resolver and start its receive loop. Resolvers whose
    /// socket cannot be bound are skipped (the pool routes around them).
    pub async fn bind(resolvers: &[SocketAddr]) -> Arc<Transport> {
        let mut conns = HashMap::new();
        for &resolver in resolvers {
            match Self::connect(resolver).await {
                Ok(conn) => {
                    conns.insert(resolver, conn);
                }
                Err(e) => tracing::warn!("transport: cannot bind socket for {resolver}: {e}"),
            }
        }
        Arc::new(Transport { conns })
    }

    async fn connect(resolver: SocketAddr) -> std::io::Result<Arc<ResolverConn>> {
        let bind: SocketAddr = if resolver.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        socket.connect(resolver).await?;
        let pending: Arc<Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Background receive loop: route datagrams to waiters by transaction id.
        {
            let socket = socket.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match socket.recv(&mut buf).await {
                        Ok(n) if n >= 2 => {
                            let id = u16::from_be_bytes([buf[0], buf[1]]);
                            if let Some(tx) = pending.lock().remove(&id) {
                                let _ = tx.send(buf[..n].to_vec());
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            // Transient socket error; avoid a busy spin.
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }
            });
        }

        Ok(Arc::new(ResolverConn {
            socket,
            pending,
            next_id: Mutex::new(rand::random()),
        }))
    }

    /// True if the transport has a live connection to `resolver`.
    pub fn has(&self, resolver: SocketAddr) -> bool {
        self.conns.contains_key(&resolver)
    }

    /// Send `query` to `resolver` and await the matching reply, or `None` on
    /// timeout. The query's transaction id is rewritten to a unique value.
    pub async fn query(
        &self,
        resolver: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let conn = self.conns.get(&resolver)?.clone();
        if query.len() < 2 {
            return None;
        }
        let id = conn.alloc_id();
        let mut q = query.to_vec();
        q[0] = (id >> 8) as u8;
        q[1] = (id & 0xFF) as u8;

        let (tx, rx) = oneshot::channel();
        conn.pending.lock().insert(id, tx);

        if conn.socket.send(&q).await.is_err() {
            conn.pending.lock().remove(&id);
            return None;
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(resp)) => Some(resp),
            _ => {
                conn.pending.lock().remove(&id);
                None
            }
        }
    }

    /// Send to `primary`; if it does not answer within `race_after`, also send a
    /// duplicate to `secondary` and take whichever replies first. Returns the
    /// resolver that answered alongside its reply.
    pub async fn query_raced(
        &self,
        primary: SocketAddr,
        secondary: SocketAddr,
        query: &[u8],
        timeout: Duration,
        race_after: Duration,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let p = self.query(primary, query, timeout);
        tokio::pin!(p);

        tokio::select! {
            r = &mut p => return r.map(|d| (primary, d)),
            _ = tokio::time::sleep(race_after) => {}
        }

        // Primary stalled: start the secondary and race the two.
        let s = self.query(secondary, query, timeout);
        tokio::pin!(s);
        tokio::select! {
            r = &mut p => r.map(|d| (primary, d)),
            r = &mut s => r.map(|d| (secondary, d)),
        }
    }
}
