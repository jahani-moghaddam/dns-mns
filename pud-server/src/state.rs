//! Server-side session and stream state.
//!
//! The server is poll-driven: it only gets to send when a query arrives. So
//! data coming back from upstream targets is buffered per stream and drained
//! into FEC-coded shards whenever we build a response. Uplink data is
//! reordered by byte offset before being written to the target.

use parking_lot::Mutex;
use pud_core::crypto::{Handshake, Session as CryptoSession};
use pud_core::fec;
use pud_core::policy::FecPolicy;
use pud_core::protocol::{DownlinkMsg, ShardMsg};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

/// Replay protection: a sliding window of recently seen counters per session.
pub struct ReplayWindow {
    highest: u64,
    bitmap: u64,
    seen_any: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Returns true if `counter` is fresh (not seen before and within window),
    /// recording it. Returns false for replays / too-old counters.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = counter;
            self.bitmap = 1;
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest = counter;
            true
        } else {
            let diff = self.highest - counter;
            if diff >= 64 {
                return false; // too old
            }
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                false // already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow::new()
    }
}

/// One FEC-encoded downlink block awaiting acknowledgement.
struct OutBlock {
    params: fec::BlockParams,
    shards: Vec<fec::Shard>,
    /// Round-robin cursor so repeated sends cycle through all shards.
    cursor: usize,
}

/// Per-stream downlink (target -> client) state.
struct Downlink {
    /// Raw bytes received from the target, not yet chopped into a block.
    raw: VecDeque<u8>,
    /// Encoded blocks not yet acknowledged, keyed by block sequence.
    blocks: BTreeMap<u32, OutBlock>,
    next_block_seq: u32,
    /// Client has acknowledged all blocks with seq < this.
    acked_up_to: u32,
    target_eof: bool,
    closed_sent: bool,
}

/// Per-stream uplink (client -> target) reordering state.
struct Uplink {
    next_offset: u32,
    reorder: BTreeMap<u32, Vec<u8>>,
    dirty: bool,
}

/// Open state of a stream's connection to its target.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpenState {
    Pending,
    Open,
    Failed,
}

/// A single proxied stream.
pub struct Stream {
    pub stream_id: u16,
    /// Channel that feeds ordered uplink bytes to the target writer task.
    to_target: Mutex<Option<UnboundedSender<Vec<u8>>>>,
    down: Mutex<Downlink>,
    up: Mutex<Uplink>,
    state: Mutex<OpenState>,
    /// True once the OpenResult has been delivered to the client.
    result_sent: AtomicBool,
    /// True if the target connection failed abnormally (reset, not clean EOF).
    reset: AtomicBool,
}

const MAX_REORDER_BYTES: usize = 256 * 1024;

impl Stream {
    fn new(stream_id: u16) -> Self {
        Stream {
            stream_id,
            to_target: Mutex::new(None),
            down: Mutex::new(Downlink {
                raw: VecDeque::new(),
                blocks: BTreeMap::new(),
                next_block_seq: 0,
                acked_up_to: 0,
                target_eof: false,
                closed_sent: false,
            }),
            up: Mutex::new(Uplink {
                next_offset: 0,
                reorder: BTreeMap::new(),
                dirty: true,
            }),
            state: Mutex::new(OpenState::Pending),
            result_sent: AtomicBool::new(false),
            reset: AtomicBool::new(false),
        }
    }

    pub fn set_sender(&self, tx: UnboundedSender<Vec<u8>>) {
        *self.to_target.lock() = Some(tx);
    }

    /// Close the uplink to the target (client asked to close the stream). The
    /// writer task observes the dropped channel and shuts the socket down.
    pub fn close_uplink(&self) {
        *self.to_target.lock() = None;
    }

    pub fn set_state(&self, s: OpenState) {
        *self.state.lock() = s;
    }

    pub fn state(&self) -> OpenState {
        *self.state.lock()
    }

    /// Append bytes received from the target into the downlink buffer.
    pub fn push_downlink(&self, bytes: &[u8]) {
        let mut d = self.down.lock();
        d.raw.extend(bytes.iter().copied());
    }

    /// Mark that the target connection reached EOF / closed.
    pub fn mark_target_eof(&self) {
        self.down.lock().target_eof = true;
    }

    /// Mark that the target connection failed abnormally (error/reset). The
    /// stream will be torn down with a Reset rather than a graceful Closed.
    pub fn mark_target_reset(&self) {
        self.reset.store(true, Ordering::Relaxed);
        self.down.lock().target_eof = true;
    }

    /// True if this stream was abnormally reset.
    pub fn is_reset(&self) -> bool {
        self.reset.load(Ordering::Relaxed)
    }

    /// Handle uplink data with reordering. Ordered bytes are forwarded to the
    /// target. Returns the new cumulative next-expected offset.
    pub fn handle_uplink_data(&self, offset: u32, payload: &[u8]) -> u32 {
        let mut u = self.up.lock();
        if offset == u.next_offset {
            self.forward(&mut u, offset, payload.to_vec());
        } else if offset > u.next_offset {
            // Future data: buffer it if there is room.
            let buffered: usize = u.reorder.values().map(|v| v.len()).sum();
            if buffered + payload.len() <= MAX_REORDER_BYTES {
                u.reorder.entry(offset).or_insert_with(|| payload.to_vec());
            }
        }
        // offset < next_offset: duplicate, ignore.
        u.dirty = true;
        u.next_offset
    }

    fn forward(&self, u: &mut Uplink, offset: u32, payload: Vec<u8>) {
        let mut cur = offset;
        let mut data = payload;
        loop {
            if let Some(tx) = self.to_target.lock().as_ref() {
                let _ = tx.send(data.clone());
            }
            cur = cur.wrapping_add(data.len() as u32);
            u.next_offset = cur;
            match u.reorder.remove(&cur) {
                Some(next) => {
                    data = next;
                }
                None => break,
            }
        }
    }

    /// Acknowledge downlink blocks: drop everything below `up_to`.
    pub fn ack_downlink(&self, up_to: u32) {
        let mut d = self.down.lock();
        if up_to > d.acked_up_to {
            d.acked_up_to = up_to;
            let stale: Vec<u32> = d.blocks.range(..up_to).map(|(k, _)| *k).collect();
            for k in stale {
                d.blocks.remove(&k);
            }
        }
    }

    /// True when the target has closed and all downlink data is drained+acked.
    fn fully_drained(&self) -> bool {
        let d = self.down.lock();
        d.target_eof && d.raw.is_empty() && d.blocks.is_empty()
    }
}

/// A logical client session, identified by the 32-bit session id.
pub struct ClientSession {
    #[allow(dead_code)]
    pub session_id: u32,
    streams: Mutex<HashMap<u16, Arc<Stream>>>,
    downlink_counter: AtomicU64,
    replay: Mutex<ReplayWindow>,
    last_seen: Mutex<Instant>,
    welcomed: AtomicBool,
    /// One-shot control messages waiting to be sent (OpenResult, Closed).
    pending_control: Mutex<Vec<DownlinkMsg>>,
    /// Client-reported downlink loss, per-mille.
    loss_permille: AtomicU64,
    /// Largest response the client said it can receive (0 = unknown).
    client_max_resp: AtomicU64,
    /// Per-session forward-secret data keys, set once the handshake completes.
    data_session: Mutex<Option<CryptoSession>>,
    /// Our ephemeral public key for this session's handshake (to resend).
    server_hello_pub: Mutex<Option<[u8; 32]>>,
    /// The client's ephemeral public key we established with (for idempotency).
    client_eph: Mutex<Option<[u8; 32]>>,
}

impl ClientSession {
    pub fn new(session_id: u32) -> Self {
        ClientSession {
            session_id,
            streams: Mutex::new(HashMap::new()),
            downlink_counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::new()),
            last_seen: Mutex::new(Instant::now()),
            welcomed: AtomicBool::new(false),
            pending_control: Mutex::new(Vec::new()),
            loss_permille: AtomicU64::new(0),
            client_max_resp: AtomicU64::new(0),
            data_session: Mutex::new(None),
            server_hello_pub: Mutex::new(None),
            client_eph: Mutex::new(None),
        }
    }

    pub fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }

    pub fn idle_for(&self) -> std::time::Duration {
        self.last_seen.lock().elapsed()
    }

    pub fn accept_counter(&self, counter: u64) -> bool {
        self.replay.lock().accept(counter)
    }

    pub fn next_downlink_counter(&self) -> u64 {
        self.downlink_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn set_loss(&self, permille: u16) {
        self.loss_permille.store(permille as u64, Ordering::Relaxed);
    }

    pub fn set_client_max_resp(&self, v: u16) {
        self.client_max_resp.store(v as u64, Ordering::Relaxed);
    }

    /// The established per-session data keys, if the handshake has completed.
    pub fn data_session(&self) -> Option<CryptoSession> {
        self.data_session.lock().clone()
    }

    /// Complete (or idempotently re-confirm) the handshake for `client_eph` and
    /// return our ephemeral public key to send back in the `ServerHello`.
    /// Re-sending the same `ClientHello` returns the same key (so the client's
    /// derived keys stay valid); a new `client_eph` re-establishes fresh keys.
    pub fn establish(&self, psk: &[u8], client_eph: [u8; 32], session_id: u32) -> [u8; 32] {
        let mut ds = self.data_session.lock();
        let mut sp = self.server_hello_pub.lock();
        let mut ce = self.client_eph.lock();
        if ds.is_some() && *ce == Some(client_eph) {
            return sp.unwrap_or([0u8; 32]);
        }
        let hs = Handshake::new();
        let server_pub = hs.public;
        let session = hs.complete(&client_eph, psk, session_id, &client_eph, &server_pub);
        *ds = Some(session);
        *sp = Some(server_pub);
        *ce = Some(client_eph);
        server_pub
    }

    pub fn client_max_resp(&self) -> u16 {
        self.client_max_resp.load(Ordering::Relaxed) as u16
    }

    pub fn take_welcome(&self) -> bool {
        !self.welcomed.swap(true, Ordering::Relaxed)
    }

    pub fn get_stream(&self, stream_id: u16) -> Option<Arc<Stream>> {
        self.streams.lock().get(&stream_id).cloned()
    }

    /// Get an existing stream or create a fresh one (in Pending state).
    pub fn get_or_create_stream(&self, stream_id: u16) -> (Arc<Stream>, bool) {
        let mut streams = self.streams.lock();
        if let Some(s) = streams.get(&stream_id) {
            (s.clone(), false)
        } else {
            let s = Arc::new(Stream::new(stream_id));
            streams.insert(stream_id, s.clone());
            (s, true)
        }
    }

    pub fn remove_stream(&self, stream_id: u16) {
        self.streams.lock().remove(&stream_id);
    }

    /// Build a downlink message batch that fits within `budget` plaintext bytes.
    pub fn build_downlink(&self, budget: usize, policy: &FecPolicy) -> Vec<DownlinkMsg> {
        let mut out: Vec<DownlinkMsg> = Vec::new();
        let mut used = 0usize;

        let try_push = |msg: DownlinkMsg, out: &mut Vec<DownlinkMsg>, used: &mut usize| -> bool {
            let sz = encoded_size(&msg);
            if *used + sz > budget {
                return false;
            }
            *used += sz;
            out.push(msg);
            true
        };

        if self.take_welcome() {
            let _ = try_push(DownlinkMsg::Welcome, &mut out, &mut used);
        }

        // Drain one-shot control messages.
        {
            let mut ctrl = self.pending_control.lock();
            let mut keep = Vec::new();
            for msg in ctrl.drain(..) {
                if !try_push(msg.clone(), &mut out, &mut used) {
                    keep.push(msg);
                }
            }
            *ctrl = keep;
        }

        // Per-stream: emit OpenResult, UpAck, then shards.
        let streams: Vec<Arc<Stream>> = self.streams.lock().values().cloned().collect();

        // Open results for newly resolved streams.
        for s in &streams {
            if !s.result_sent.load(Ordering::Relaxed) {
                match s.state() {
                    OpenState::Open => {
                        if try_push(
                            DownlinkMsg::OpenResult {
                                stream_id: s.stream_id,
                                status: 0,
                            },
                            &mut out,
                            &mut used,
                        ) {
                            s.result_sent.store(true, Ordering::Relaxed);
                        }
                    }
                    OpenState::Failed => {
                        if try_push(
                            DownlinkMsg::OpenResult {
                                stream_id: s.stream_id,
                                status: 1,
                            },
                            &mut out,
                            &mut used,
                        ) {
                            s.result_sent.store(true, Ordering::Relaxed);
                        }
                    }
                    OpenState::Pending => {}
                }
            }
        }

        // UpAck for streams that consumed uplink data since last build.
        for s in &streams {
            let mut u = s.up.lock();
            if u.dirty {
                if try_push(
                    DownlinkMsg::UpAck {
                        stream_id: s.stream_id,
                        up_to: u.next_offset,
                    },
                    &mut out,
                    &mut used,
                ) {
                    u.dirty = false;
                }
            }
        }

        // Refill blocks from raw buffers, then round-robin shards across streams.
        let loss = self.loss_permille.load(Ordering::Relaxed) as f64 / 1000.0;
        let parity = policy.parity_for_loss(loss);
        for s in &streams {
            refill_blocks(s, policy.data_shards, parity);
        }

        // Round-robin passes: one shard per stream per pass until budget is full.
        let mut progress = true;
        while progress {
            progress = false;
            for s in &streams {
                let mut d = s.down.lock();
                // Find the lowest-seq block with shards to send.
                let next_key = d.blocks.keys().next().copied();
                if let Some(key) = next_key {
                    if let Some(block) = d.blocks.get_mut(&key) {
                        let idx = block.cursor % block.shards.len();
                        let shard = &block.shards[idx];
                        let msg = DownlinkMsg::Shard(ShardMsg {
                            stream_id: s.stream_id,
                            block_seq: key,
                            data_shards: block.params.data_shards as u8,
                            parity_shards: block.params.parity_shards as u8,
                            shard_len: block.params.shard_len,
                            original_len: block.params.original_len,
                            shard_index: shard.index as u8,
                            shard: shard.data.clone(),
                        });
                        let sz = encoded_size(&msg);
                        if used + sz <= budget {
                            used += sz;
                            block.cursor = block.cursor.wrapping_add(1);
                            out.push(msg);
                            progress = true;
                        }
                    }
                }
            }
        }

        // Emit Reset for abnormally-failed streams, or Closed for cleanly
        // drained ones.
        for s in &streams {
            if s.is_reset() {
                if try_push(
                    DownlinkMsg::Reset {
                        stream_id: s.stream_id,
                    },
                    &mut out,
                    &mut used,
                ) {
                    self.remove_stream(s.stream_id);
                }
                continue;
            }
            let drained = s.fully_drained();
            if drained {
                let mut d = s.down.lock();
                if !d.closed_sent {
                    if try_push(
                        DownlinkMsg::Closed {
                            stream_id: s.stream_id,
                        },
                        &mut out,
                        &mut used,
                    ) {
                        d.closed_sent = true;
                        drop(d);
                        self.remove_stream(s.stream_id);
                    }
                }
            }
        }

        out
    }
}

/// Move raw downlink bytes into FEC-encoded blocks sized for one shard per
/// response. `block_data` is `data_shards * shard_target` bytes.
fn refill_blocks(stream: &Arc<Stream>, data_shards: u16, parity: u16) {
    let mut d = stream.down.lock();
    // Target one block's worth of payload per encode.
    let block_data = (data_shards as usize) * SHARD_TARGET;
    loop {
        let have = d.raw.len();
        let take = if have >= block_data {
            block_data
        } else if d.target_eof && have > 0 {
            have // flush the tail at EOF
        } else {
            break;
        };
        let chunk: Vec<u8> = d.raw.drain(..take).collect();
        match fec::encode(&chunk, data_shards, parity) {
            Ok((params, shards)) => {
                let seq = d.next_block_seq;
                d.next_block_seq = d.next_block_seq.wrapping_add(1);
                d.blocks.insert(
                    seq,
                    OutBlock {
                        params,
                        shards,
                        cursor: 0,
                    },
                );
            }
            Err(_) => break,
        }
        if have < block_data {
            break;
        }
    }
}

/// Target shard payload length, chosen so a single shard comfortably fits one
/// response. The response budget bounds the actual message size regardless.
const SHARD_TARGET: usize = 1024;

/// Estimate the encoded size of a downlink message (matches the wire codec).
fn encoded_size(msg: &DownlinkMsg) -> usize {
    match msg {
        DownlinkMsg::Welcome => 1,
        DownlinkMsg::OpenResult { .. } => 1 + 2 + 1,
        DownlinkMsg::UpAck { .. } => 1 + 2 + 4,
        DownlinkMsg::Closed { .. } => 1 + 2,
        DownlinkMsg::Shard(s) => 1 + 2 + 4 + 1 + 1 + 2 + 4 + 1 + 2 + s.shard.len(),
        DownlinkMsg::ProbeAck { data, .. } => 1 + 4 + 2 + data.len(),
        DownlinkMsg::Reset { .. } => 1 + 2,
        DownlinkMsg::ServerHello { .. } => 1 + 32,
    }
}

/// The set of all live sessions.
pub struct Sessions {
    map: Mutex<HashMap<u32, Arc<ClientSession>>>,
}

impl Sessions {
    pub fn new() -> Self {
        Sessions {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_or_create(&self, session_id: u32) -> Arc<ClientSession> {
        let mut map = self.map.lock();
        map.entry(session_id)
            .or_insert_with(|| Arc::new(ClientSession::new(session_id)))
            .clone()
    }

    /// Look up a session without creating one (so unauthenticated frames cannot
    /// allocate session state).
    pub fn get(&self, session_id: u32) -> Option<Arc<ClientSession>> {
        self.map.lock().get(&session_id).cloned()
    }

    /// Drop sessions idle longer than `timeout`.
    pub fn reap(&self, timeout: std::time::Duration) -> usize {
        let mut map = self.map.lock();
        let before = map.len();
        map.retain(|_, s| s.idle_for() < timeout);
        before - map.len()
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Sessions::new()
    }
}
