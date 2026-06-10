//! PersianUltraDNS server — the VPS-side authoritative DNS tunnel endpoint.
//!
//! It binds UDP/53, decodes tunnel frames carried in QNAMEs, maintains client
//! sessions and proxied TCP streams, and answers with TXT responses carrying
//! FEC-coded downlink data.

mod config;
mod egress;
mod state;

use crate::config::{load_or_create_key, ServerConfig};
use crate::egress::spawn_egress;
use crate::state::{ClientSession, Sessions};
use anyhow::{Context, Result};
use clap::Parser;
use pud_core::crypto::{Direction, Session as CryptoSession};
use pud_core::frame::{open_frame, qname_to_frame, seal_frame};
use pud_core::policy::FecPolicy;
use pud_core::protocol::{
    addr_to_host, decode_uplink, encode_downlink, DownlinkMsg, FrameHeader, UplinkMsg,
};
use pud_core::{dns, PROTOCOL_VERSION};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(name = "pud-server", version, about = "PersianUltraDNS VPS server")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "server_config.toml")]
    config: String,
    /// Write a default configuration template to the config path and exit.
    #[arg(long)]
    init: bool,
}

/// Shared context handed to every datagram handler.
struct Ctx {
    socket: Arc<UdpSocket>,
    sessions: Sessions,
    crypto: CryptoSession,
    /// Raw pre-shared key, for deriving per-session data keys at handshake.
    key: Vec<u8>,
    /// All delegated tunnel domains this server answers for.
    domains: Vec<String>,
    cfg: ServerConfig,
    policy: FecPolicy,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.init {
        ServerConfig::write_template(&cli.config)?;
        println!("Wrote default server config to {}", cli.config);
        return Ok(());
    }

    let cfg = ServerConfig::load(&cli.config)
        .with_context(|| format!("loading config (try --init to create {})", cli.config))?;

    init_tracing(&cfg.log_level);

    let key = load_or_create_key(&cfg.key_file)?;
    tracing::info!(
        "PersianUltraDNS server v{} starting; domain={} bind={} key={} (share this with clients)",
        env!("CARGO_PKG_VERSION"),
        cfg.domain,
        cfg.bind,
        config::encode_hex(&key)
    );

    let socket = Arc::new(
        UdpSocket::bind(&cfg.bind)
            .await
            .with_context(|| format!("binding UDP {}", cfg.bind))?,
    );

    let policy = FecPolicy {
        data_shards: cfg.data_shards,
        min_parity: cfg.min_parity,
        max_parity: cfg.max_parity,
        safety_margin: 1,
    };

    let ctx = Arc::new(Ctx {
        socket: socket.clone(),
        sessions: Sessions::new(),
        crypto: CryptoSession::from_psk(&key),
        key: key.clone(),
        domains: cfg.effective_domains(),
        cfg: cfg.clone(),
        policy,
    });

    // Session reaper.
    {
        let ctx = ctx.clone();
        let timeout = Duration::from_secs(cfg.session_timeout_secs);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let reaped = ctx.sessions.reap(timeout);
                if reaped > 0 {
                    tracing::debug!("reaped {reaped} idle sessions; {} live", ctx.sessions.len());
                }
            }
        });
    }

    tracing::info!("listening for tunnel queries on {}", cfg.bind);

    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("recv_from error: {e}");
                continue;
            }
        };
        let datagram = buf[..n].to_vec();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            handle_datagram(&ctx, datagram, peer).await;
        });
    }
}

async fn handle_datagram(ctx: &Ctx, datagram: Vec<u8>, peer: std::net::SocketAddr) {
    // Parse the DNS query.
    let query = match dns::parse_query(&datagram) {
        Ok(q) => q,
        Err(_) => return, // not a DNS query we understand
    };
    if query.question.qtype != dns::TYPE_TXT {
        return;
    }

    // Recover the tunnel frame from the QNAME, trying each delegated domain.
    let frame = match ctx
        .domains
        .iter()
        .find_map(|d| qname_to_frame(&query.question.name, d).ok())
    {
        Some(f) => f,
        None => return, // not for any of our tunnel domains
    };

    // Authenticate and decrypt.
    // The cleartext header carries the session id, which we need before we can
    // choose keys. Try the session's established data keys first, then the PSK
    // keys (which carry the handshake). Sessions are only created on a frame
    // that authenticates, so unauthenticated traffic cannot allocate state.
    let header = match FrameHeader::decode(&frame) {
        Ok(h) => h,
        Err(_) => return,
    };
    let existing = ctx.sessions.get(header.session_id);
    let (used_psk, plaintext) = {
        let data = existing.as_ref().and_then(|s| s.data_session());
        if let Some(ds) = data {
            if let Ok((_h, pt)) = open_frame(&ds, Direction::ClientToServer, &frame) {
                (false, pt)
            } else if let Ok((_h, pt)) = open_frame(&ctx.crypto, Direction::ClientToServer, &frame) {
                (true, pt)
            } else {
                tracing::debug!(
                    "session 0x{:08x}: decrypt failed (counter={})",
                    header.session_id,
                    header.counter
                );
                return;
            }
        } else if let Ok((_h, pt)) = open_frame(&ctx.crypto, Direction::ClientToServer, &frame) {
            (true, pt)
        } else {
            tracing::debug!(
                "session 0x{:08x}: decrypt failed (counter={})",
                header.session_id,
                header.counter
            );
            return;
        }
    };

    let session = ctx.sessions.get_or_create(header.session_id);
    session.touch();

    // Process uplink messages only if this frame is fresh (replay-safe). Any
    // immediate responses (e.g. a ProbeAck or ServerHello) come back so we can
    // deliver them in THIS response.
    let mut inline: Vec<DownlinkMsg> = Vec::new();
    let mut log_exchange = false;
    let mut uplink_summary = "none".to_string();
    let replay_ok = session.accept_counter(header.counter as u64);
    if replay_ok {
        if let Ok(msgs) = decode_uplink(&plaintext) {
            log_exchange = should_log_uplink(&msgs);
            uplink_summary = summarize_uplink(&msgs);
            inline = process_uplink(ctx, &session, header.session_id, msgs).await;
        }
    } else {
        tracing::debug!(
            "session 0x{:08x}: replay rejected counter={}",
            header.session_id,
            header.counter
        );
    }

    // Build the downlink response within the negotiated budget. The budget is
    // driven by this query's EDNS size, so each resolver receives responses
    // sized to its own discovered downlink MTU.
    let max_resp = negotiated_max_resp(ctx, &query, &session);
    let inline_reserve: usize = inline.iter().map(downlink_wire_size).sum();
    let budget = plaintext_budget(max_resp, query.question.name.len());
    let mut down_msgs = session.build_downlink(budget.saturating_sub(inline_reserve), &ctx.policy);
    let has_inline = !inline.is_empty();
    down_msgs.extend(inline);
    let down_plain = encode_downlink(&down_msgs);

    let counter = session.next_downlink_counter();
    let resp_header = FrameHeader {
        session_id: header.session_id,
        counter: counter as u32,
    };
    // Seal with the same epoch we received under: a handshake (PSK) request gets
    // a PSK-sealed reply carrying the ServerHello; data requests get data keys.
    let seal_keys = if used_psk {
        ctx.crypto.clone()
    } else {
        session.data_session().unwrap_or_else(|| ctx.crypto.clone())
    };
    let resp_frame = seal_frame(
        &seal_keys,
        Direction::ServerToClient,
        resp_header,
        &down_plain,
    );

    match dns::build_txt_response(&datagram, &resp_frame) {
        Ok(resp) => {
            if log_exchange || should_log_downlink(&down_msgs, has_inline) {
                tracing::debug!(
                    "reply peer={peer} session=0x{:08x} up_ctr={} psk={} replay_ok={} uplink={} downlink={} resp_bytes={}",
                    header.session_id,
                    header.counter,
                    used_psk,
                    replay_ok,
                    uplink_summary,
                    summarize_downlink(&down_msgs),
                    resp.len()
                );
            }
            if let Err(e) = ctx.socket.send_to(&resp, peer).await {
                tracing::debug!("send_to {peer} failed: {e}");
            }
        }
        Err(e) => tracing::debug!("build response failed: {e}"),
    }
}

async fn process_uplink(
    ctx: &Ctx,
    session: &Arc<ClientSession>,
    session_id: u32,
    msgs: Vec<UplinkMsg>,
) -> Vec<DownlinkMsg> {
    let mut inline = Vec::new();
    for msg in msgs {
        match msg {
            UplinkMsg::Hello { max_resp } => {
                session.set_client_max_resp(max_resp);
                tracing::debug!("session 0x{session_id:08x}: Hello max_resp={max_resp}");
                let _ = PROTOCOL_VERSION;
            }
            UplinkMsg::Open {
                stream_id,
                addr,
                port,
            } => {
                let (stream, created) = session.get_or_create_stream(stream_id);
                let host = addr_to_host(&addr);
                tracing::debug!(
                    "session 0x{session_id:08x}: Open stream={stream_id} {host}:{port} created={created}"
                );
                if created {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    stream.set_sender(tx);
                    spawn_egress(
                        stream.clone(),
                        host,
                        port,
                        Duration::from_secs(ctx.cfg.connect_timeout_secs),
                        rx,
                    );
                }
            }
            UplinkMsg::Data {
                stream_id,
                offset,
                payload,
            } => {
                tracing::debug!(
                    "session 0x{session_id:08x}: Data stream={stream_id} offset={offset} len={}",
                    payload.len()
                );
                if let Some(stream) = session.get_stream(stream_id) {
                    stream.handle_uplink_data(offset, &payload);
                } else {
                    tracing::debug!(
                        "session 0x{session_id:08x}: Data for unknown stream={stream_id}"
                    );
                }
            }
            UplinkMsg::Close { stream_id } => {
                tracing::debug!("session 0x{session_id:08x}: Close stream={stream_id}");
                if let Some(stream) = session.get_stream(stream_id) {
                    stream.close_uplink();
                }
            }
            UplinkMsg::Reset { stream_id } => {
                tracing::debug!("session 0x{session_id:08x}: Reset stream={stream_id}");
                // Client aborted the stream; stop feeding the target and drop it.
                if let Some(stream) = session.get_stream(stream_id) {
                    stream.close_uplink();
                }
                session.remove_stream(stream_id);
            }
            UplinkMsg::Ack { stream_id, up_to } => {
                tracing::debug!(
                    "session 0x{session_id:08x}: Ack stream={stream_id} up_to={up_to}"
                );
                if let Some(stream) = session.get_stream(stream_id) {
                    stream.ack_downlink(up_to);
                }
            }
            UplinkMsg::Loss { permille } => {
                session.set_loss(permille);
            }
            UplinkMsg::Probe { nonce, want, pad } => {
                // `pad` only inflates the uplink frame to probe the uplink MTU;
                // it carries no data. Echo `want` bytes back so the client can
                // measure the downlink MTU. Returned inline so the ProbeAck goes
                // back through the same resolver that carried this probe.
                let _ = pad;
                let data = vec![0u8; want as usize];
                inline.push(DownlinkMsg::ProbeAck { nonce, data });
            }
            UplinkMsg::ClientHello { eph_pub } => {
                tracing::debug!("session 0x{session_id:08x}: ClientHello (handshake)");
                // Forward-secret key exchange: derive per-session data keys and
                // reply with our ephemeral public key (inline, same response).
                let server_pub = session.establish(&ctx.key, eph_pub, session_id);
                inline.push(DownlinkMsg::ServerHello { eph_pub: server_pub });
            }
            UplinkMsg::Poll => {}
        }
    }
    inline
}

fn should_log_uplink(msgs: &[UplinkMsg]) -> bool {
    msgs.iter()
        .any(|m| !matches!(m, UplinkMsg::Poll | UplinkMsg::Loss { .. }))
}

fn should_log_downlink(msgs: &[DownlinkMsg], has_inline: bool) -> bool {
    has_inline
        || msgs.iter().any(|m| {
            !matches!(
                m,
                DownlinkMsg::Welcome | DownlinkMsg::UpAck { .. } | DownlinkMsg::ProbeAck { .. }
            )
        })
}

fn summarize_uplink(msgs: &[UplinkMsg]) -> String {
    if msgs.is_empty() {
        return "none".into();
    }
    let mut parts = Vec::new();
    for msg in msgs {
        match msg {
            UplinkMsg::Hello { max_resp } => parts.push(format!("Hello({max_resp})")),
            UplinkMsg::Open { stream_id, addr, port } => {
                parts.push(format!("Open({stream_id},{addr:?}:{port})"));
            }
            UplinkMsg::Data { stream_id, offset, payload } => {
                parts.push(format!("Data({stream_id},{offset},{}b)", payload.len()));
            }
            UplinkMsg::Close { stream_id } => parts.push(format!("Close({stream_id})")),
            UplinkMsg::Ack { stream_id, up_to } => {
                parts.push(format!("Ack({stream_id},{up_to})"));
            }
            UplinkMsg::Poll => parts.push("Poll".into()),
            UplinkMsg::Loss { permille } => parts.push(format!("Loss({permille})")),
            UplinkMsg::Probe { want, .. } => parts.push(format!("Probe(want={want})")),
            UplinkMsg::Reset { stream_id } => parts.push(format!("Reset({stream_id})")),
            UplinkMsg::ClientHello { .. } => parts.push("ClientHello".into()),
        }
    }
    parts.join(",")
}

fn summarize_downlink(msgs: &[DownlinkMsg]) -> String {
    if msgs.is_empty() {
        return "none".into();
    }
    let mut parts = Vec::new();
    for msg in msgs {
        match msg {
            DownlinkMsg::Welcome => parts.push("Welcome".into()),
            DownlinkMsg::OpenResult { stream_id, status } => {
                parts.push(format!("OpenResult({stream_id},{status})"));
            }
            DownlinkMsg::UpAck { stream_id, up_to } => {
                parts.push(format!("UpAck({stream_id},{up_to})"));
            }
            DownlinkMsg::Closed { stream_id } => parts.push(format!("Closed({stream_id})")),
            DownlinkMsg::Shard(s) => {
                parts.push(format!(
                    "Shard({},{},{})",
                    s.stream_id, s.block_seq, s.shard.len()
                ));
            }
            DownlinkMsg::ProbeAck { data, .. } => parts.push(format!("ProbeAck({}b)", data.len())),
            DownlinkMsg::Reset { stream_id } => parts.push(format!("Reset({stream_id})")),
            DownlinkMsg::ServerHello { .. } => parts.push("ServerHello".into()),
        }
    }
    parts.join(",")
}

/// Wire size of a downlink message that may be appended inline to a response.
/// Only `ProbeAck` is ever delivered this way today.
fn downlink_wire_size(msg: &DownlinkMsg) -> usize {
    match msg {
        DownlinkMsg::ProbeAck { data, .. } => 1 + 4 + 2 + data.len(),
        DownlinkMsg::ServerHello { .. } => 1 + 32,
        _ => 0,
    }
}

/// The response size we will target: the smaller of our cap and the size the
/// client requested for this specific query (its EDNS UDP size, which the
/// client sets to the resolver's discovered downlink MTU). Falls back to the
/// session-wide value from `Hello` when the query carries no EDNS size.
fn negotiated_max_resp(ctx: &Ctx, query: &dns::ParsedQuery, session: &Arc<ClientSession>) -> u16 {
    let edns = query.edns_udp_size.unwrap_or(0);
    let client = if edns > 0 { edns } else { session.client_max_resp() };
    if client == 0 {
        ctx.cfg.max_response
    } else {
        client.min(ctx.cfg.max_response)
    }
}

/// Compute how many plaintext bytes of downlink fit in a response of size
/// `max_resp`, given the echoed question name length.
///
/// Response layout: DNS header (12) + echoed question (name+1 root + 4) +
/// answer fixed fields (12) + TXT rdata = frame bytes + 1 length octet per 255.
/// The frame itself is 12-byte header + ciphertext (plaintext + 16 tag).
fn plaintext_budget(max_resp: u16, qname_len: usize) -> usize {
    let max = max_resp as usize;
    let question = qname_len + 1 + 4;
    let fixed = 12 + question + 12; // header + question + answer fixed
    let rdata_room = max.saturating_sub(fixed);
    // rdata holds the frame plus a length octet for every 255 bytes.
    let frame_room = rdata_room.saturating_sub(rdata_room / 255 + 1);
    // frame = 8 (header) + 8 (truncated tag) + plaintext
    frame_room.saturating_sub(8 + 8).max(16)
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("pud_server={level},pud_core={level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_sane() {
        // Short name leaves a big budget; long name shrinks it but stays >= min.
        let big = plaintext_budget(1232, 20);
        let small = plaintext_budget(1232, 240);
        assert!(big > small);
        assert!(small >= 16);
        assert!(big < 1232);
    }
}
