//! The client tunnel engine.
//!
//! The engine owns the logical session and all proxied streams, and drives a
//! pool of concurrent DNS queries across many resolvers (multipath). Each query
//! carries uplink work (stream opens, data, acks) and brings back downlink work
//! (FEC shards, acks, control). Downlink shards are reassembled per block,
//! reconstructed with Reed-Solomon as soon as enough arrive, and delivered to
//! the owning stream in order.

use crate::config::ClientConfig;
use crate::resolver::ResolverPool;
use crate::transport::Transport;
use parking_lot::Mutex;
use pud_core::crypto::{Direction, Handshake, Session as CryptoSession};
use pud_core::fec::{self, BlockParams, Shard};
use pud_core::frame::{frame_to_qname, max_uplink_frame_bytes, open_frame, seal_frame};
use pud_core::protocol::{
    decode_downlink, encode_uplink, Addr, DownlinkMsg, FrameHeader, ShardMsg, UplinkMsg,
};
use pud_core::{dns, PROTOCOL_VERSION};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;

/// Open state of a stream's upstream connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenState {
    Pending,
    Open,
    Failed,
}

/// Uplink (app -> server) reliability buffer with go-back-on-stall.
struct UplinkBuf {
    base: u32,
    cursor: u32,
    data: VecDeque<u8>,
    last_progress: Instant,
    app_closed: bool,
    close_sent: bool,
}

impl UplinkBuf {
    fn new() -> Self {
        UplinkBuf {
            base: 0,
            cursor: 0,
            data: VecDeque::new(),
            last_progress: Instant::now(),
            app_closed: false,
            close_sent: false,
        }
    }
    fn next_offset(&self) -> u32 {
        self.base.wrapping_add(self.data.len() as u32)
    }
    fn push(&mut self, bytes: &[u8]) {
        self.data.extend(bytes.iter().copied());
    }
    /// Take up to `max` new bytes starting at the send cursor.
    fn take(&mut self, max: usize) -> Option<(u32, Vec<u8>)> {
        let avail_start = self.cursor.wrapping_sub(self.base) as usize;
        if avail_start >= self.data.len() || max == 0 {
            return None;
        }
        let n = max.min(self.data.len() - avail_start);
        let chunk: Vec<u8> = self
            .data
            .iter()
            .skip(avail_start)
            .take(n)
            .copied()
            .collect();
        let off = self.cursor;
        self.cursor = self.cursor.wrapping_add(n as u32);
        Some((off, chunk))
    }
    fn on_ack(&mut self, up_to: u32) {
        if up_to.wrapping_sub(self.base) as i64 > 0 && up_to.wrapping_sub(self.base) < u32::MAX / 2 {
            let advance = up_to.wrapping_sub(self.base) as usize;
            let drop = advance.min(self.data.len());
            for _ in 0..drop {
                self.data.pop_front();
            }
            self.base = up_to;
            if self.cursor.wrapping_sub(self.base) >= u32::MAX / 2 {
                self.cursor = self.base;
            }
            self.last_progress = Instant::now();
        }
    }
    /// If the send cursor has advanced past the ack point and no ack has come in
    /// for `rto`, rewind to retransmit the unacknowledged bytes.
    fn maybe_rewind(&mut self, rto: Duration) {
        if self.cursor != self.base && self.last_progress.elapsed() > rto {
            self.cursor = self.base;
            self.last_progress = Instant::now();
        }
    }
}

/// One downlink block being reassembled.
#[derive(Default)]
struct BlockAsm {
    params: Option<BlockParams>,
    shards: HashMap<u16, Vec<u8>>,
    payload: Option<Vec<u8>>,
}

/// Downlink (server -> app) reassembly with in-order delivery.
struct DownAsm {
    blocks: BTreeMap<u32, BlockAsm>,
    next_deliver: u32,
}

impl DownAsm {
    fn new() -> Self {
        DownAsm {
            blocks: BTreeMap::new(),
            next_deliver: 0,
        }
    }
}

/// A stream as tracked by the engine.
struct EngineStream {
    stream_id: u16,
    addr: Addr,
    port: u16,
    up: Mutex<UplinkBuf>,
    down: Mutex<DownAsm>,
    to_app: Mutex<Option<UnboundedSender<Vec<u8>>>>,
    open_state: Mutex<OpenState>,
    open_seen: AtomicBool,
    finished: AtomicBool,
    server_closed: AtomicBool,
    /// Set when the local app side failed abnormally; triggers an uplink Reset.
    local_reset: AtomicBool,
}

impl EngineStream {
    fn deliver_ready(&self) {
        let mut d = self.down.lock();
        while let Some(block) = d.blocks.get(&d.next_deliver) {
            if let Some(payload) = &block.payload {
                if let Some(tx) = self.to_app.lock().as_ref() {
                    let _ = tx.send(payload.clone());
                }
                let seq = d.next_deliver;
                d.blocks.remove(&seq);
                d.next_deliver = d.next_deliver.wrapping_add(1);
            } else {
                break;
            }
        }
        self.maybe_finish(&mut d);
    }

    fn maybe_finish(&self, d: &mut DownAsm) {
        if self.server_closed.load(Ordering::Relaxed)
            && d.blocks.values().all(|b| b.payload.is_some())
            && d.blocks.is_empty()
            && !self.finished.swap(true, Ordering::Relaxed)
        {
            // Drop the app sender so the SOCKS downlink writer closes the socket.
            *self.to_app.lock() = None;
        }
    }
}

/// Cloneable control handle for one stream, shared between the SOCKS uplink and
/// downlink tasks. The stream is closed when the last clone is dropped.
#[derive(Clone)]
pub struct StreamControl {
    inner: Arc<ControlInner>,
}

struct ControlInner {
    engine: Arc<EngineInner>,
    stream_id: u16,
}

impl Drop for ControlInner {
    fn drop(&mut self) {
        self.engine.close_stream(self.stream_id);
    }
}

impl StreamControl {
    #[allow(dead_code)]
    pub fn stream_id(&self) -> u16 {
        self.inner.stream_id
    }

    /// Queue application bytes for delivery to the server.
    pub fn send_uplink(&self, data: &[u8]) {
        if let Some(s) = self.inner.engine.streams.lock().get(&self.inner.stream_id) {
            s.up.lock().push(data);
        }
        self.inner.engine.mark_active();
    }

    /// Signal that the application closed its side (EOF).
    pub fn app_close(&self) {
        if let Some(s) = self.inner.engine.streams.lock().get(&self.inner.stream_id) {
            s.up.lock().app_closed = true;
        }
    }

    /// Signal that the local connection failed abnormally; sends a Reset so the
    /// server tears down the target promptly instead of treating it as a clean
    /// end-of-stream.
    pub fn reset(&self) {
        if let Some(s) = self.inner.engine.streams.lock().get(&self.inner.stream_id) {
            s.local_reset.store(true, Ordering::Relaxed);
        }
        self.inner.engine.mark_active();
    }

    /// Wait until the upstream connection opens or fails, or `timeout` elapses.
    pub async fn wait_open(&self, timeout: Duration) -> OpenState {
        let deadline = Instant::now() + timeout;
        loop {
            let st = self
                .inner
                .engine
                .streams
                .lock()
                .get(&self.inner.stream_id)
                .map(|s| *s.open_state.lock())
                .unwrap_or(OpenState::Failed);
            if st != OpenState::Pending {
                return st;
            }
            if Instant::now() >= deadline {
                return OpenState::Failed;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Shared engine state.
struct EngineInner {
    crypto: CryptoSession,
    /// Pre-shared key bytes, used to derive per-session data keys at handshake.
    psk: Vec<u8>,
    /// Per-session forward-secret data keys, set once the handshake completes.
    data_crypto: Mutex<Option<CryptoSession>>,
    session_id: AtomicU32,
    /// Last time a query got a successful reply; drives stall detection for
    /// automatic session reconnect.
    last_success: Mutex<Instant>,
    /// Tunnel domains to rotate across (>=1). Rotating per query survives the
    /// censor blacklisting any single delegated domain.
    domains: Vec<String>,
    domain_cursor: AtomicUsize,
    /// Response size currently advertised to the server (EDNS + Hello). Mutated
    /// by the probe task as it discovers a larger safe downlink size.
    adv_max_resp: AtomicU16,
    /// Last response size we actually told the server via Hello. When this
    /// differs from `adv_max_resp` a fresh Hello is sent. Starts at 0 so the
    /// very first uplink always carries a Hello.
    last_advertised: AtomicU16,
    max_uplink_chunk: usize,
    up_counter: AtomicU64,
    next_stream_id: AtomicU32,
    streams: Mutex<HashMap<u16, Arc<EngineStream>>>,
    loss: pud_core::policy::LossEstimator,
    last_loss_report: Mutex<Instant>,
    rto: Duration,
    /// Nonce of the most recently acknowledged probe (0 = none yet).
    probe_acked: AtomicU32,
    /// Last time application data moved in either direction; keeps the
    /// concurrency window open briefly after a burst.
    last_activity: Mutex<Instant>,
}

/// Additive-increase / multiplicative-decrease controller for the number of
/// simultaneously in-flight queries (the download "credits" / congestion
/// window). More in-flight queries means more downlink response slots, so this
/// is the primary throughput lever; it grows while deliveries succeed and
/// halves on loss, with TCP-style slow start.
struct WindowController {
    st: Mutex<WinState>,
    min: usize,
    max: usize,
}

struct WinState {
    cwnd: f64,
    ssthresh: f64,
}

impl WindowController {
    fn new(min: usize, max: usize) -> Self {
        let min = min.max(1);
        let max = max.max(min);
        WindowController {
            st: Mutex::new(WinState {
                cwnd: min as f64,
                ssthresh: max as f64,
            }),
            min,
            max,
        }
    }

    /// Current target window, in queries.
    fn target(&self) -> usize {
        let c = self.st.lock().cwnd;
        (c.floor() as usize).clamp(self.min, self.max)
    }

    /// A query was answered: grow (exponentially in slow start, linearly after).
    fn on_ack(&self) {
        let mut s = self.st.lock();
        if s.cwnd < s.ssthresh {
            s.cwnd += 1.0;
        } else {
            s.cwnd += 1.0 / s.cwnd;
        }
        let maxf = self.max as f64;
        if s.cwnd > maxf {
            s.cwnd = maxf;
        }
    }

    /// A query was lost: multiplicative decrease.
    fn on_loss(&self) {
        let mut s = self.st.lock();
        let half = (s.cwnd / 2.0).max(self.min as f64);
        s.ssthresh = half;
        s.cwnd = half;
    }
}

impl EngineInner {
    /// The response size currently advertised to the server.
    fn max_resp(&self) -> u16 {
        self.adv_max_resp.load(Ordering::Relaxed)
    }

    /// The forward-secret data keys established by the handshake. The data path
    /// only runs after the handshake completes, so this is always set there; it
    /// falls back to the PSK keys defensively.
    fn data(&self) -> CryptoSession {
        self.data_crypto
            .lock()
            .clone()
            .unwrap_or_else(|| self.crypto.clone())
    }

    /// The current session id.
    fn session_id(&self) -> u32 {
        self.session_id.load(Ordering::Relaxed)
    }

    /// Pick the next tunnel domain (round-robin across the configured list).
    fn pick_domain(&self) -> String {
        let i = self.domain_cursor.fetch_add(1, Ordering::Relaxed);
        self.domains[i % self.domains.len()].clone()
    }

    /// Rotate to a fresh random session id (used on reconnect so the new
    /// session never collides with the dead one).
    fn rotate_session_id(&self) {
        self.session_id.store(rand::random(), Ordering::Relaxed);
    }

    /// Record that a query just succeeded (resets the stall timer).
    fn mark_success(&self) {
        *self.last_success.lock() = Instant::now();
    }

    /// True if no query has succeeded for at least `timeout` — a strong signal
    /// the session is dead (server reaped or restarted).
    fn stalled(&self, timeout: Duration) -> bool {
        self.last_success.lock().elapsed() >= timeout
    }

    /// Whether the forward-secret data keys are currently established.
    fn data_established(&self) -> bool {
        self.data_crypto.lock().is_some()
    }

    /// Tear down every live stream (used on reconnect): the target connections
    /// are gone server-side, so the local apps must fail and retry rather than
    /// silently resume on a broken byte stream.
    fn reset_all_streams(&self) {
        let streams: Vec<Arc<EngineStream>> = self.streams.lock().values().cloned().collect();
        for s in &streams {
            s.server_closed.store(true, Ordering::Relaxed);
            s.finished.store(true, Ordering::Relaxed);
            *s.to_app.lock() = None;
        }
        self.gc_finished();
    }

    /// Note that application data moved, keeping the window open.
    fn mark_active(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// True while there is data to move (so the window should stay open). Goes
    /// false shortly after a burst ends, dropping to a paced keepalive.
    fn has_work(&self) -> bool {
        if self.last_activity.lock().elapsed() < Duration::from_millis(300) {
            return true;
        }
        let streams = self.streams.lock();
        for s in streams.values() {
            if s.finished.load(Ordering::Relaxed) {
                continue;
            }
            if !s.open_seen.load(Ordering::Relaxed) && *s.open_state.lock() == OpenState::Pending {
                return true;
            }
            // Non-empty buffer means unsent or unacknowledged uplink bytes.
            if !s.up.lock().data.is_empty() {
                return true;
            }
        }
        false
    }

    fn alloc_stream_id(&self) -> u16 {
        let streams = self.streams.lock();
        loop {
            let raw = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
            let id = ((raw % 65535) + 1) as u16; // 1..=65535, never 0
            if !streams.contains_key(&id) {
                return id;
            }
        }
    }

    fn close_stream(&self, stream_id: u16) {
        if let Some(s) = self.streams.lock().get(&stream_id) {
            s.up.lock().app_closed = true;
        }
    }

    /// Build a batch of uplink messages within `budget` plaintext bytes.
    fn build_uplink(&self, budget: usize) -> Vec<UplinkMsg> {
        let mut out = Vec::new();
        let mut used = 0usize;

        let push = |msg: UplinkMsg, out: &mut Vec<UplinkMsg>, used: &mut usize| -> bool {
            let sz = uplink_size(&msg);
            if *used + sz > budget {
                return false;
            }
            *used += sz;
            out.push(msg);
            true
        };

        // Advertise the current response size via Hello whenever it changes
        // (and always on the first uplink, since `last_advertised` starts at 0).
        // The probe task moves `adv_max_resp` as it discovers larger safe sizes.
        {
            let desired = self.adv_max_resp.load(Ordering::Relaxed);
            if self.last_advertised.load(Ordering::Relaxed) != desired
                && push(UplinkMsg::Hello { max_resp: desired }, &mut out, &mut used)
            {
                self.last_advertised.store(desired, Ordering::Relaxed);
            }
            let _ = PROTOCOL_VERSION;
        }

        // Periodic loss report so the server can size FEC parity.
        {
            let mut last = self.last_loss_report.lock();
            if last.elapsed() > Duration::from_millis(1000) {
                let permille = (self.loss.rate() * 1000.0).round() as u16;
                if push(UplinkMsg::Loss { permille }, &mut out, &mut used) {
                    *last = Instant::now();
                }
            }
        }

        let streams: Vec<Arc<EngineStream>> =
            self.streams.lock().values().cloned().collect();

        for s in &streams {
            // Abnormal local teardown takes priority: emit a Reset and finish
            // the stream locally (best-effort; the server also reaps).
            if s.local_reset.load(Ordering::Relaxed) && !s.finished.load(Ordering::Relaxed) {
                if push(
                    UplinkMsg::Reset {
                        stream_id: s.stream_id,
                    },
                    &mut out,
                    &mut used,
                ) {
                    s.finished.store(true, Ordering::Relaxed);
                }
                continue;
            }

            // (Re)send Open until acknowledged.
            if *s.open_state.lock() == OpenState::Pending && !s.open_seen.load(Ordering::Relaxed) {
                let _ = push(
                    UplinkMsg::Open {
                        stream_id: s.stream_id,
                        addr: s.addr.clone(),
                        port: s.port,
                    },
                    &mut out,
                    &mut used,
                );
            }

            // Acknowledge downlink progress.
            let next_deliver = s.down.lock().next_deliver;
            if next_deliver > 0 {
                let _ = push(
                    UplinkMsg::Ack {
                        stream_id: s.stream_id,
                        up_to: next_deliver,
                    },
                    &mut out,
                    &mut used,
                );
            }

            // Uplink data (progressive across concurrent queries).
            {
                let mut up = s.up.lock();
                up.maybe_rewind(self.rto);
                let room = budget.saturating_sub(used);
                let chunk_cap = self.max_uplink_chunk.min(room.saturating_sub(7));
                if chunk_cap > 0 {
                    if let Some((offset, payload)) = up.take(chunk_cap) {
                        let _ = push(
                            UplinkMsg::Data {
                                stream_id: s.stream_id,
                                offset,
                                payload,
                            },
                            &mut out,
                            &mut used,
                        );
                    }
                }

                // Close once all data is acknowledged.
                if up.app_closed
                    && !up.close_sent
                    && up.base == up.next_offset()
                {
                    if push(
                        UplinkMsg::Close {
                            stream_id: s.stream_id,
                        },
                        &mut out,
                        &mut used,
                    ) {
                        up.close_sent = true;
                    }
                }
            }
        }

        if out.is_empty() {
            out.push(UplinkMsg::Poll);
        }
        out
    }

    /// Apply a batch of downlink messages.
    fn process_downlink(&self, msgs: Vec<DownlinkMsg>) {
        for msg in msgs {
            match msg {
                DownlinkMsg::Welcome => {}
                DownlinkMsg::OpenResult { stream_id, status } => {
                    if let Some(s) = self.streams.lock().get(&stream_id) {
                        s.open_seen.store(true, Ordering::Relaxed);
                        *s.open_state.lock() = if status == 0 {
                            OpenState::Open
                        } else {
                            OpenState::Failed
                        };
                    }
                }
                DownlinkMsg::UpAck { stream_id, up_to } => {
                    if let Some(s) = self.streams.lock().get(&stream_id) {
                        s.up.lock().on_ack(up_to);
                    }
                }
                DownlinkMsg::Closed { stream_id } => {
                    if let Some(s) = self.streams.lock().get(&stream_id) {
                        s.server_closed.store(true, Ordering::Relaxed);
                        s.deliver_ready();
                    }
                }
                DownlinkMsg::Shard(shard) => {
                    self.on_shard(shard);
                }
                DownlinkMsg::Reset { stream_id } => {
                    // Target failed abnormally: tear the local connection down
                    // now rather than waiting for blocks that will never come.
                    if let Some(s) = self.streams.lock().get(&stream_id) {
                        s.server_closed.store(true, Ordering::Relaxed);
                        s.finished.store(true, Ordering::Relaxed);
                        *s.to_app.lock() = None;
                    }
                }
                DownlinkMsg::ServerHello { .. } => {
                    // Handshake replies are consumed by the handshake prelude,
                    // not the data path; ignore any stray late one.
                }
                DownlinkMsg::ProbeAck { nonce, data } => {
                    // Echo of a path probe: the requested-size response made it
                    // back intact, so this size is safe. Record the nonce for
                    // the probe task to observe.
                    if nonce != 0 {
                        self.probe_acked.store(nonce, Ordering::Relaxed);
                    }
                    tracing::trace!("probe ack: nonce={nonce} {} echo bytes", data.len());
                }
            }
        }
        self.gc_finished();
    }

    fn on_shard(&self, msg: ShardMsg) {
        let stream = match self.streams.lock().get(&msg.stream_id) {
            Some(s) => s.clone(),
            None => return,
        };
        {
            let mut d = stream.down.lock();
            if msg.block_seq < d.next_deliver {
                return; // already delivered
            }
            let block = d.blocks.entry(msg.block_seq).or_default();
            if block.payload.is_some() {
                return; // already reconstructed
            }
            block.params = Some(BlockParams {
                data_shards: msg.data_shards as u16,
                parity_shards: msg.parity_shards as u16,
                shard_len: msg.shard_len,
                original_len: msg.original_len,
            });
            block
                .shards
                .entry(msg.shard_index as u16)
                .or_insert_with(|| msg.shard.clone());

            if block.shards.len() >= msg.data_shards as usize {
                let params = block.params.unwrap();
                let shards: Vec<Shard> = block
                    .shards
                    .iter()
                    .map(|(&index, data)| Shard {
                        index,
                        data: data.clone(),
                    })
                    .collect();
                if let Ok(payload) = fec::decode(params, &shards) {
                    block.payload = Some(payload);
                }
            }
        }
        stream.deliver_ready();
    }

    fn gc_finished(&self) {
        self.streams
            .lock()
            .retain(|_, s| !s.finished.load(Ordering::Relaxed));
    }
}

/// The public engine handle.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

impl Engine {
    pub fn new(psk: &[u8], domains: Vec<String>, cfg: &ClientConfig) -> Self {
        let session_id: u32 = rand::random();
        let domains = if domains.is_empty() {
            vec!["t.example.com".to_string()]
        } else {
            domains
        };
        let inner = EngineInner {
            crypto: CryptoSession::from_psk(psk),
            psk: psk.to_vec(),
            data_crypto: Mutex::new(None),
            session_id: AtomicU32::new(session_id),
            last_success: Mutex::new(Instant::now()),
            domains,
            domain_cursor: AtomicUsize::new(0),
            adv_max_resp: AtomicU16::new(cfg.max_response),
            last_advertised: AtomicU16::new(0),
            max_uplink_chunk: cfg.max_uplink_chunk,
            up_counter: AtomicU64::new(0),
            next_stream_id: AtomicU32::new(1),
            streams: Mutex::new(HashMap::new()),
            loss: pud_core::policy::LossEstimator::new(0.15),
            last_loss_report: Mutex::new(Instant::now()),
            rto: Duration::from_millis(cfg.query_timeout_ms.max(500)),
            probe_acked: AtomicU32::new(0),
            last_activity: Mutex::new(Instant::now()),
        };
        Engine {
            inner: Arc::new(inner),
        }
    }

    pub fn session_id(&self) -> u32 {
        self.inner.session_id()
    }

    /// Register a new stream to `addr:port`. Returns a cloneable control handle
    /// and the downlink byte receiver.
    pub fn open(&self, addr: Addr, port: u16) -> (StreamControl, UnboundedReceiver<Vec<u8>>) {
        let stream_id = self.inner.alloc_stream_id();
        let (tx, rx) = unbounded_channel();
        let stream = Arc::new(EngineStream {
            stream_id,
            addr,
            port,
            up: Mutex::new(UplinkBuf::new()),
            down: Mutex::new(DownAsm::new()),
            to_app: Mutex::new(Some(tx)),
            open_state: Mutex::new(OpenState::Pending),
            open_seen: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            server_closed: AtomicBool::new(false),
            local_reset: AtomicBool::new(false),
        });
        self.inner.streams.lock().insert(stream_id, stream);
        self.inner.mark_active();
        let control = StreamControl {
            inner: Arc::new(ControlInner {
                engine: self.inner.clone(),
                stream_id,
            }),
        };
        (control, rx)
    }

    /// Run the multipath query pump until cancelled. Drives an adaptive
    /// concurrency window of in-flight queries over a reusable per-resolver
    /// transport, with RTT-weighted resolver selection and stall-racing.
    pub async fn run(&self, resolvers: Vec<std::net::SocketAddr>, cfg: ClientConfig) {
        let pool = Arc::new(ResolverPool::new(resolvers.clone()));
        let transport = Transport::bind(&resolvers).await;
        let cfg = Arc::new(cfg);

        let (wmin, wmax) = if cfg.window.adaptive {
            (cfg.window.min, cfg.window.max)
        } else {
            (cfg.in_flight, cfg.in_flight)
        };
        let window = Arc::new(WindowController::new(wmin, wmax));
        let active = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());

        // Forward-secret handshake (mandatory). Establishes per-session data
        // keys before any application data flows. Retries until it succeeds.
        loop {
            match client_handshake(&self.inner, &transport, &pool, &cfg).await {
                Some(data) => {
                    *self.inner.data_crypto.lock() = Some(data);
                    self.inner.mark_success();
                    tracing::info!("session established (forward-secret handshake complete)");
                    break;
                }
                None => {
                    tracing::warn!("handshake failed; retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        // Periodic resolver health/RTT/window log.
        {
            let pool = pool.clone();
            let engine = self.inner.clone();
            let window = window.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(30));
                loop {
                    tick.tick().await;
                    let loss = engine.loss.rate();
                    tracing::debug!(
                        "window cwnd={} resp={} active_resolvers={}",
                        window.target(),
                        engine.max_resp(),
                        pool.active_count()
                    );
                    for (addr, rtt, samples, benched) in pool.snapshot() {
                        tracing::debug!(
                            "resolver {addr}: rtt={rtt:.0}ms samples={samples} benched={benched} loss={:.1}%",
                            loss * 100.0
                        );
                    }
                }
            });
        }
        // Background resolver reactivation: periodically probe benched resolvers
        // with a lightweight Poll and bring back any that respond, instead of
        // waiting out the full backoff.
        {
            let engine = self.inner.clone();
            let transport = transport.clone();
            let pool = pool.clone();
            let floor = cfg.max_response;
            let timeout = Duration::from_millis(cfg.window.rto_max_ms.max(500));
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    if !engine.data_established() {
                        continue;
                    }
                    for addr in pool.benched() {
                        if !transport.has(addr) {
                            continue;
                        }
                        if health_check_resolver(&engine, &transport, addr, floor, timeout).await {
                            pool.revive(addr);
                            tracing::debug!("resolver {addr} reactivated by health check");
                        }
                    }
                }
            });
        }
        // Adaptive per-resolver downlink MTU discovery.
        if cfg.probe.enabled {
            let engine = self.inner.clone();
            let transport = transport.clone();
            let pool = pool.clone();
            let pcfg = cfg.probe.clone();
            let floor = cfg.max_response;
            let rto = Duration::from_millis(cfg.window.rto_max_ms.max(500));
            tokio::spawn(async move {
                probe_loop(engine, transport, pool, pcfg, floor, rto).await;
            });
        }

        // Dispatcher: hold the in-flight count at the window target while there
        // is work; collapse to a paced keepalive when idle.
        let idle = Duration::from_millis(cfg.idle_poll_ms);
        let reconnect_after =
            Duration::from_secs(30).max(Duration::from_millis(cfg.window.rto_max_ms) * 6);
        loop {
            // Auto-reconnect: if we have work but no reply has landed for a long
            // time, the session is almost certainly dead (server reaped or
            // restarted). Reset the dead streams, rotate to a fresh session id
            // (so keys/nonces never collide with the old one), and re-handshake.
            if self.inner.has_work() && self.inner.stalled(reconnect_after) {
                tracing::warn!("session stalled; reconnecting with a fresh session");
                self.inner.reset_all_streams();
                self.inner.rotate_session_id();
                *self.inner.data_crypto.lock() = None;
                loop {
                    match client_handshake(&self.inner, &transport, &pool, &cfg).await {
                        Some(data) => {
                            *self.inner.data_crypto.lock() = Some(data);
                            self.inner.mark_success();
                            tracing::info!("reconnected (new forward-secret session)");
                            break;
                        }
                        None => tokio::time::sleep(Duration::from_secs(1)).await,
                    }
                }
                continue;
            }

            if self.inner.has_work() {
                let target = window.target();
                while active.load(Ordering::Relaxed) < target {
                    spawn_query(
                        self.inner.clone(),
                        transport.clone(),
                        pool.clone(),
                        window.clone(),
                        active.clone(),
                        notify.clone(),
                        cfg.clone(),
                    );
                }
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
            } else {
                if active.load(Ordering::Relaxed) == 0 {
                    spawn_query(
                        self.inner.clone(),
                        transport.clone(),
                        pool.clone(),
                        window.clone(),
                        active.clone(),
                        notify.clone(),
                        cfg.clone(),
                    );
                }
                tokio::time::sleep(idle).await;
            }
        }
    }
}

/// Background task that continuously adapts the **per-resolver** downlink
/// response MTU to each path's conditions.
///
/// Each cycle it round-robins to one resolver and runs an additive-increase /
/// multiplicative-decrease controller against that resolver alone:
///
/// * **Grow** — while below the ceiling and not cooling down, it probes
///   `confirmed + step` *on that resolver*; success raises that resolver's
///   confirmed MTU, failure holds it and starts a cooldown.
/// * **Validate** — otherwise it re-probes the resolver's current MTU; repeated
///   failures shrink it multiplicatively toward the floor.
///
/// Because each probe is sent as a dedicated query to a specific resolver and
/// the server answers it inline (so the echo returns through that same
/// resolver), discovery is accurate per path: a fragile resolver no longer caps
/// the size used by fast ones. The effective maximum is still bounded by the
/// server's own `max_response`, and no resolver drops below the floor.
async fn probe_loop(
    engine: Arc<EngineInner>,
    transport: Arc<Transport>,
    pool: Arc<ResolverPool>,
    cfg: crate::config::ProbeConfig,
    floor: u16,
    rto: Duration,
) {
    /// Consecutive validation failures required before shrinking, so a single
    /// dropped datagram does not trigger a needless back-off.
    const VALIDATION_FAIL_LIMIT: u32 = 2;

    let ceiling = cfg.max_response_ceiling.max(floor);
    let step = cfg.step.max(1);
    let interval = Duration::from_secs(cfg.interval_secs.max(1));
    let grow_cooldown = interval * 6;

    // Multiplicative decrease toward the floor.
    let shrink = |size: u16| -> u16 {
        let reduced = (size as u32 * 3 / 4) as u16;
        floor.max(reduced.min(size.saturating_sub(1)))
    };

    // Per-resolver controller state: (cooldown_until, consecutive validation fails).
    let mut state: HashMap<SocketAddr, (Instant, u32)> = HashMap::new();
    let mut cursor = 0usize;

    loop {
        tokio::time::sleep(interval).await;

        // Pause while keys are unset (e.g. during a reconnect re-handshake).
        if !engine.data_established() {
            continue;
        }

        let addrs = pool.addrs();
        if addrs.is_empty() {
            continue;
        }
        // One resolver per cycle keeps probe traffic light.
        let resolver = addrs[cursor % addrs.len()];
        cursor = cursor.wrapping_add(1);
        if !transport.has(resolver) {
            continue;
        }

        let confirmed = pool.down_mtu(resolver, floor);
        let entry = state.entry(resolver).or_insert((Instant::now(), 0));

        let may_grow = confirmed < ceiling && Instant::now() >= entry.0;
        let target = if may_grow {
            confirmed.saturating_add(step).min(ceiling)
        } else {
            confirmed
        };

        let ok = probe_resolver(&engine, &transport, resolver, target, rto).await;

        if may_grow {
            if ok {
                pool.set_down_mtu(resolver, target);
                entry.1 = 0;
                tracing::debug!("probe[{resolver}]: grew downlink MTU to {target} bytes");
            } else {
                entry.0 = Instant::now() + grow_cooldown;
                tracing::debug!("probe[{resolver}]: {target} unreachable, holding at {confirmed}");
            }
        } else if ok {
            entry.1 = 0;
        } else if confirmed > floor {
            entry.1 += 1;
            if entry.1 >= VALIDATION_FAIL_LIMIT {
                let shrunk = shrink(confirmed);
                pool.set_down_mtu(resolver, shrunk);
                entry.0 = Instant::now() + grow_cooldown;
                entry.1 = 0;
                tracing::debug!("probe[{resolver}]: degraded, shrink to {shrunk} bytes");
            }
        }
    }
}

/// Send one dedicated probe to `resolver`, advertising `target_resp` as the
/// EDNS size and requesting an echo that nearly fills it. Returns true if the
/// matching `ProbeAck` returns (i.e. a `target_resp`-byte response traverses
/// that resolver's downlink path).
async fn probe_resolver(
    engine: &Arc<EngineInner>,
    transport: &Arc<Transport>,
    resolver: SocketAddr,
    target_resp: u16,
    rto: Duration,
) -> bool {
    let want = probe_echo_len(target_resp);
    if want == 0 {
        return false;
    }
    let nonce = loop {
        let n: u32 = rand::random();
        if n != 0 {
            break n;
        }
    };

    let msgs = [UplinkMsg::Probe {
        nonce,
        want,
        pad: Vec::new(),
    }];
    let counter = engine.up_counter.fetch_add(1, Ordering::Relaxed);
    let header = FrameHeader {
        session_id: engine.session_id(),
        counter: counter as u32,
    };
    let plaintext = encode_uplink(&msgs);
    let frame = seal_frame(&engine.data(), Direction::ClientToServer, header, &plaintext);
    let qname = match frame_to_qname(&frame, &engine.pick_domain()) {
        Ok(q) => q,
        Err(_) => return false,
    };
    let query = match dns::build_query(0, &qname, target_resp) {
        Ok(q) => q,
        Err(_) => return false,
    };

    engine.probe_acked.store(0, Ordering::Relaxed);
    if let Some(resp) = transport.query(resolver, &query, rto).await {
        apply_response(engine, &resp);
    }
    engine.probe_acked.load(Ordering::Relaxed) == nonce
}

/// Perform the forward-secret handshake: send `ClientHello` (PSK-encrypted)
/// with our ephemeral public key and wait for the server's `ServerHello`, then
/// derive the per-session data keys. Returns the data `CryptoSession` on
/// success. Retries across resolvers a bounded number of times.
async fn client_handshake(
    engine: &Arc<EngineInner>,
    transport: &Arc<Transport>,
    pool: &Arc<ResolverPool>,
    cfg: &ClientConfig,
) -> Option<CryptoSession> {
    let hs = Handshake::new();
    let client_pub = hs.public;
    let mut hs_opt = Some(hs);
    let floor = cfg.max_response;
    let rto = Duration::from_millis(cfg.window.rto_max_ms.max(500));

    for _ in 0..16 {
        let msgs = [UplinkMsg::ClientHello {
            eph_pub: client_pub,
        }];
        let counter = engine.up_counter.fetch_add(1, Ordering::Relaxed);
        let header = FrameHeader {
            session_id: engine.session_id(),
            counter: counter as u32,
        };
        let plaintext = encode_uplink(&msgs);
        // ClientHello rides PSK-derived keys; data keys do not exist yet.
        let frame = seal_frame(&engine.crypto, Direction::ClientToServer, header, &plaintext);
        let qname = match frame_to_qname(&frame, &engine.pick_domain()) {
            Ok(q) => q,
            Err(_) => return None,
        };
        let query = match dns::build_query(0, &qname, floor) {
            Ok(q) => q,
            Err(_) => return None,
        };

        let resolver = pool.pick_weighted();
        if !transport.has(resolver) {
            continue;
        }
        if let Some(resp) = transport.query(resolver, &query, rto).await {
            pool.record_ok(resolver, Duration::from_millis(0));
            if let Some(server_pub) = parse_server_hello(engine, &resp) {
                let hs = hs_opt.take()?;
                return Some(hs.complete(
                    &server_pub,
                    &engine.psk,
                    engine.session_id(),
                    &client_pub,
                    &server_pub,
                ));
            }
        } else {
            pool.record_fail(resolver);
        }
    }
    None
}

/// Decrypt a handshake response with the PSK keys and extract the server's
/// ephemeral public key from a `ServerHello`, if present.
fn parse_server_hello(engine: &Arc<EngineInner>, resp: &[u8]) -> Option<[u8; 32]> {
    let frame = dns::parse_txt_response(resp).ok()?;
    if frame.is_empty() {
        return None;
    }
    let (_h, plaintext) = open_frame(&engine.crypto, Direction::ServerToClient, &frame).ok()?;
    for msg in decode_downlink(&plaintext).ok()? {
        if let DownlinkMsg::ServerHello { eph_pub } = msg {
            return Some(eph_pub);
        }
    }
    None
}

/// Send a lightweight Poll to `resolver` to see if it is reachable again.
/// Used by the background health-check to reactivate benched resolvers.
async fn health_check_resolver(
    engine: &Arc<EngineInner>,
    transport: &Arc<Transport>,
    resolver: SocketAddr,
    floor: u16,
    timeout: Duration,
) -> bool {
    let msgs = [UplinkMsg::Poll];
    let counter = engine.up_counter.fetch_add(1, Ordering::Relaxed);
    let header = FrameHeader {
        session_id: engine.session_id(),
        counter: counter as u32,
    };
    let plaintext = encode_uplink(&msgs);
    let frame = seal_frame(&engine.data(), Direction::ClientToServer, header, &plaintext);
    let qname = match frame_to_qname(&frame, &engine.pick_domain()) {
        Ok(q) => q,
        Err(_) => return false,
    };
    let query = match dns::build_query(0, &qname, floor) {
        Ok(q) => q,
        Err(_) => return false,
    };
    if let Some(resp) = transport.query(resolver, &query, timeout).await {
        // A well-formed tunnel response means the resolver path is alive.
        apply_response(engine, &resp);
        true
    } else {
        false
    }
}

/// Echo length to request for a probe targeting a `target_resp`-byte response.
///
/// Mirrors the server's response-budget math (with a short representative
/// QNAME, since the echo can be deferred onto a low-overhead query) and leaves
/// slack for the `ProbeAck` header and any co-resident control messages, so the
/// resulting answer datagram closely approaches `target_resp`.
fn probe_echo_len(target_resp: u16) -> u16 {
    let qname_len = 64usize; // representative low-overhead query
    let max = target_resp as usize;
    let question = qname_len + 1 + 4;
    let fixed = 12 + question + 12; // DNS header + question + answer fixed fields
    let rdata_room = max.saturating_sub(fixed);
    let frame_room = rdata_room.saturating_sub(rdata_room / 255 + 1);
    let plaintext = frame_room.saturating_sub(8 + 8); // frame header + truncated tag
    // 7 = ProbeAck wire header (kind + nonce + 2-byte length); 16 = slack.
    plaintext.saturating_sub(7 + 16) as u16
}

/// Outcome of one query, fed back to the window and loss controllers.
enum QueryOutcome {
    /// A reply arrived from `resolver` after `rtt`; `got_downlink` is true if it
    /// carried tunnel data.
    Ok {
        resolver: SocketAddr,
        rtt: Duration,
        got_downlink: bool,
    },
    /// No reply arrived; `resolver` is the primary that was tried, if any.
    Lost { resolver: Option<SocketAddr> },
    /// The query could not be built or sent; not counted for control.
    Skip,
}

/// Spawn one in-flight query, accounting for it in `active` and reporting its
/// outcome to the window controller and loss estimator on completion.
fn spawn_query(
    engine: Arc<EngineInner>,
    transport: Arc<Transport>,
    pool: Arc<ResolverPool>,
    window: Arc<WindowController>,
    active: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    cfg: Arc<ClientConfig>,
) {
    active.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        match do_query(&engine, &transport, &pool, &cfg).await {
            QueryOutcome::Ok {
                resolver,
                rtt,
                got_downlink,
            } => {
                pool.record_ok(resolver, rtt);
                engine.loss.record(false);
                window.on_ack();
                engine.mark_success();
                if got_downlink {
                    engine.mark_active();
                }
            }
            QueryOutcome::Lost { resolver } => {
                if let Some(r) = resolver {
                    pool.record_fail(r);
                }
                engine.loss.record(true);
                window.on_loss();
            }
            QueryOutcome::Skip => {}
        }
        active.fetch_sub(1, Ordering::Relaxed);
        notify.notify_one();
    });
}

/// Build, send, and apply a single query.
async fn do_query(
    engine: &Arc<EngineInner>,
    transport: &Arc<Transport>,
    pool: &Arc<ResolverPool>,
    cfg: &ClientConfig,
) -> QueryOutcome {
    let domain = engine.pick_domain();
    let frame_budget = max_uplink_frame_bytes(&domain);
    // Plaintext budget = frame budget - header(8) - tag(8).
    let plain_budget = frame_budget.saturating_sub(8 + 8).max(8);
    let msgs = engine.build_uplink(plain_budget);

    let counter = engine.up_counter.fetch_add(1, Ordering::Relaxed);
    let header = FrameHeader {
        session_id: engine.session_id(),
        counter: counter as u32,
    };
    let plaintext = encode_uplink(&msgs);
    let frame = seal_frame(&engine.data(), Direction::ClientToServer, header, &plaintext);
    let qname = match frame_to_qname(&frame, &domain) {
        Ok(q) => q,
        Err(_) => return QueryOutcome::Skip,
    };
    // The transport assigns the DNS transaction id, so 0 is just a placeholder.
    let rto_min = Duration::from_millis(cfg.window.rto_min_ms);
    let rto_max = Duration::from_millis(cfg.window.rto_max_ms);
    let floor = cfg.max_response;

    // Pick the resolver(s) first so the query can advertise this resolver's
    // discovered downlink MTU as its EDNS size (per-resolver response sizing).
    let (primary, secondary) = if cfg.resolvers_policy.race_on_stall {
        pool.pick_pair()
    } else if cfg.resolvers_policy.strategy != "roundrobin" {
        (pool.pick_weighted(), None)
    } else {
        (pool.pick(), None)
    };
    if !transport.has(primary) {
        return QueryOutcome::Lost {
            resolver: Some(primary),
        };
    }

    let edns = pool.down_mtu(primary, floor);
    let query = match dns::build_query(0, &qname, edns) {
        Ok(q) => q,
        Err(_) => return QueryOutcome::Skip,
    };

    let timeout = pool.rto(primary, rto_min, rto_max);
    let started = Instant::now();

    match secondary.filter(|s| transport.has(*s)) {
        Some(sec) => {
            // Race the secondary after ~1.5x the primary's smoothed RTT.
            let race_after = match pool.stats_for(primary) {
                Some((srtt, _)) => {
                    let ms = (srtt * 1.5) as u64;
                    Duration::from_millis(ms.clamp(50, rto_max.as_millis() as u64))
                }
                None => rto_max / 2,
            };
            match transport
                .query_raced(primary, sec, &query, timeout, race_after)
                .await
            {
                Some((who, resp)) => QueryOutcome::Ok {
                    resolver: who,
                    rtt: started.elapsed(),
                    got_downlink: apply_response(engine, &resp),
                },
                None => QueryOutcome::Lost {
                    resolver: Some(primary),
                },
            }
        }
        None => match transport.query(primary, &query, timeout).await {
            Some(resp) => QueryOutcome::Ok {
                resolver: primary,
                rtt: started.elapsed(),
                got_downlink: apply_response(engine, &resp),
            },
            None => QueryOutcome::Lost {
                resolver: Some(primary),
            },
        },
    }
}

/// Decode a DNS response into downlink messages and apply them. Returns true if
/// any downlink messages were present.
fn apply_response(engine: &Arc<EngineInner>, resp: &[u8]) -> bool {
    let frame = match dns::parse_txt_response(resp) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if frame.is_empty() {
        return false;
    }
    let (_h, plaintext) = match open_frame(&engine.data(), Direction::ServerToClient, &frame) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let msgs = match decode_downlink(&plaintext) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let had = !msgs.is_empty();
    engine.process_downlink(msgs);
    had
}

/// Encoded wire size of an uplink message (matches the protocol codec).
fn uplink_size(msg: &UplinkMsg) -> usize {
    match msg {
        UplinkMsg::Hello { .. } => 1 + 2,
        UplinkMsg::Open { addr, .. } => {
            let addr_len = match addr {
                Addr::V4(_) => 1 + 4,
                Addr::V6(_) => 1 + 16,
                Addr::Domain(d) => 1 + 1 + d.len(),
            };
            1 + 2 + addr_len + 2
        }
        UplinkMsg::Data { payload, .. } => 1 + 2 + 4 + 2 + payload.len(),
        UplinkMsg::Close { .. } => 1 + 2,
        UplinkMsg::Ack { .. } => 1 + 2 + 4,
        UplinkMsg::Poll => 1,
        UplinkMsg::Loss { .. } => 1 + 2,
        UplinkMsg::Probe { pad, .. } => 1 + 4 + 2 + 2 + pad.len(),
        UplinkMsg::Reset { .. } => 1 + 2,
        UplinkMsg::ClientHello { .. } => 1 + 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The echo length requested for a probe must nearly fill the target
    /// response while leaving enough headroom that the resulting answer
    /// datagram never exceeds the target size.
    #[test]
    fn probe_echo_len_fits_target() {
        for target in [1232u16, 1488, 2048, 4096] {
            let want = probe_echo_len(target) as usize;
            assert!(want > 0, "want should be positive for target {target}");

            // Reconstruct the worst-case answer datagram size for this echo,
            // mirroring the server codec, and ensure it stays within target.
            let probeack_plaintext = 1 + 4 + 2 + want; // kind + nonce + lp16 + data
            let frame = 8 + 8 + probeack_plaintext; // header + truncated tag + plaintext
            let rdata = frame + (frame / 255 + 1); // TXT length octets
            let qname_len = 64usize;
            let datagram = 12 + (qname_len + 1 + 4) + 12 + rdata;
            assert!(
                datagram <= target as usize,
                "probe datagram {datagram} exceeds target {target}"
            );
            // And it should be a genuinely large fraction of the target.
            assert!(
                datagram * 100 >= target as usize * 90,
                "probe datagram {datagram} underfills target {target}"
            );
        }
    }

    /// A target too small to hold any echo must yield zero rather than panic.
    #[test]
    fn probe_echo_len_tiny_target_is_zero() {
        assert_eq!(probe_echo_len(64), 0);
    }

    #[test]
    fn reconnect_helpers_behave() {
        let cfg = ClientConfig::default();
        let engine = Engine::new(b"test-key", vec!["t.example.com".to_string()], &cfg);
        let inner = &engine.inner;

        // Session id rotates to a fresh value.
        let before = inner.session_id();
        inner.rotate_session_id();
        assert_ne!(inner.session_id(), before);

        // Stall detection: a zero threshold always trips; a huge one never does.
        assert!(inner.stalled(Duration::from_millis(0)));
        assert!(!inner.stalled(Duration::from_secs(3600)));
        inner.mark_success();
        assert!(!inner.stalled(Duration::from_secs(3600)));

        // Data keys are not established until the handshake completes.
        assert!(!inner.data_established());
    }

    #[test]
    fn window_slow_starts_then_caps() {
        let w = WindowController::new(2, 8);
        assert_eq!(w.target(), 2);
        // Slow start: +1 per ack until ssthresh (== max here), capped at max.
        for _ in 0..20 {
            w.on_ack();
        }
        assert_eq!(w.target(), 8);
    }

    #[test]
    fn window_halves_on_loss_and_respects_floor() {
        let w = WindowController::new(2, 64);
        for _ in 0..40 {
            w.on_ack();
        }
        let before = w.target();
        assert!(before > 2);
        w.on_loss();
        let after = w.target();
        assert!(after <= before / 2 + 1 && after >= 2, "after={after} before={before}");
        // Repeated losses never go below the floor.
        for _ in 0..10 {
            w.on_loss();
        }
        assert_eq!(w.target(), 2);
    }

    #[test]
    fn window_congestion_avoidance_is_slower_than_slow_start() {
        // Past ssthresh, growth is ~1 per cwnd acks rather than 1 per ack.
        let w = WindowController::new(2, 1000);
        // Force ssthresh low by taking a loss after a little growth.
        for _ in 0..8 {
            w.on_ack();
        }
        w.on_loss();
        let base = w.target();
        // A single ack should not immediately bump the integer window.
        w.on_ack();
        assert_eq!(w.target(), base, "one ack should not grow cwnd in avoidance");
    }
}
