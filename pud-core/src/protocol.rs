//! The PersianUltraDNS application protocol that rides inside the encrypted
//! payload of each DNS message.
//!
//! Design (asymmetric, FEC-first, poll-driven):
//!
//! * A **frame** is what travels in one DNS message. Cleartext header
//!   `session_id (u32) || counter (u64)` (also the AEAD nonce material),
//!   followed by the AEAD ciphertext of a list of messages.
//! * The **uplink** (client -> server) lives in the QNAME and is scarce, so it
//!   carries small things: stream open/close, small data with byte offsets, and
//!   ACKs of downlink blocks. Many micro-messages are packed per frame.
//! * The **downlink** (server -> client) lives in the fat TXT answer and carries
//!   FEC-coded data shards plus uplink ACKs.
//! * There is no explicit handshake: the server creates session state on the
//!   first authenticated frame (0-RTT). The client keeps several queries in
//!   flight ("download credits") so the server always has response slots.

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Size in bytes of the cleartext frame header (session_id + counter).
pub const FRAME_HEADER_LEN: usize = 8;

/// A destination address for a SOCKS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

impl Addr {
    fn write(&self, w: &mut Writer) {
        match self {
            Addr::V4(ip) => {
                w.u8(1);
                w.bytes(&ip.octets());
            }
            Addr::V6(ip) => {
                w.u8(2);
                w.bytes(&ip.octets());
            }
            Addr::Domain(name) => {
                w.u8(3);
                w.lp8(name.as_bytes());
            }
        }
    }
    fn read(r: &mut Reader) -> Result<Addr> {
        match r.u8()? {
            1 => {
                let b = r.take(4)?;
                Ok(Addr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            2 => {
                let b = r.take(16)?;
                let mut o = [0u8; 16];
                o.copy_from_slice(b);
                Ok(Addr::V6(Ipv6Addr::from(o)))
            }
            3 => {
                let b = r.lp8()?;
                let s = std::str::from_utf8(b)
                    .map_err(|_| Error::Protocol("invalid domain utf8".into()))?;
                Ok(Addr::Domain(s.to_string()))
            }
            other => Err(Error::Protocol(format!("unknown addr type {other}"))),
        }
    }
}

/// The cleartext header at the front of every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub session_id: u32,
    pub counter: u32,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut h = [0u8; FRAME_HEADER_LEN];
        h[..4].copy_from_slice(&self.session_id.to_be_bytes());
        h[4..].copy_from_slice(&self.counter.to_be_bytes());
        h
    }
    pub fn decode(buf: &[u8]) -> Result<FrameHeader> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(Error::Protocol("frame shorter than header".into()));
        }
        let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let counter = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok(FrameHeader { session_id, counter })
    }
}

// ----------------------------- Uplink messages -----------------------------

const U_HELLO: u8 = 1;
const U_OPEN: u8 = 2;
const U_DATA: u8 = 3;
const U_CLOSE: u8 = 4;
const U_ACK: u8 = 5;
const U_POLL: u8 = 6;
const U_LOSS: u8 = 7;
const U_PROBE: u8 = 8;
const U_RESET: u8 = 9;
const U_CLIENT_HELLO: u8 = 10;

/// A message sent client -> server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UplinkMsg {
    /// First contact: advertises the response size the client can receive.
    Hello { max_resp: u16 },
    /// Open a new stream to `addr:port`.
    Open { stream_id: u16, addr: Addr, port: u16 },
    /// Stream payload at absolute byte `offset`.
    Data { stream_id: u16, offset: u32, payload: Vec<u8> },
    /// Close a stream.
    Close { stream_id: u16 },
    /// Acknowledge that all downlink blocks `< up_to` for `stream_id` are done.
    Ack { stream_id: u16, up_to: u32 },
    /// Empty poll, just to give the server a response slot.
    Poll,
    /// Client-observed downlink loss rate, in per-mille (0..=1000). Lets the
    /// server size FEC parity to current conditions.
    Loss { permille: u16 },
    /// Path probe: `pad` inflates the uplink frame to test the uplink MTU, and
    /// `want` requests that many echo bytes back to test the downlink MTU.
    Probe { nonce: u32, want: u16, pad: Vec<u8> },
    /// Abnormal stream teardown (local socket error). Distinct from `Close`,
    /// which is a graceful end-of-stream.
    Reset { stream_id: u16 },
    /// Key-exchange handshake: the client's ephemeral X25519 public key. Sent
    /// in a frame encrypted under the PSK-derived keys before any data flows.
    ClientHello { eph_pub: [u8; 32] },
}

impl UplinkMsg {
    fn write(&self, w: &mut Writer) {
        match self {
            UplinkMsg::Hello { max_resp } => {
                w.u8(U_HELLO);
                w.u16(*max_resp);
            }
            UplinkMsg::Open { stream_id, addr, port } => {
                w.u8(U_OPEN);
                w.u16(*stream_id);
                addr.write(w);
                w.u16(*port);
            }
            UplinkMsg::Data { stream_id, offset, payload } => {
                w.u8(U_DATA);
                w.u16(*stream_id);
                w.u32(*offset);
                w.lp16(payload);
            }
            UplinkMsg::Close { stream_id } => {
                w.u8(U_CLOSE);
                w.u16(*stream_id);
            }
            UplinkMsg::Ack { stream_id, up_to } => {
                w.u8(U_ACK);
                w.u16(*stream_id);
                w.u32(*up_to);
            }
            UplinkMsg::Poll => {
                w.u8(U_POLL);
            }
            UplinkMsg::Loss { permille } => {
                w.u8(U_LOSS);
                w.u16(*permille);
            }
            UplinkMsg::Probe { nonce, want, pad } => {
                w.u8(U_PROBE);
                w.u32(*nonce);
                w.u16(*want);
                w.lp16(pad);
            }
            UplinkMsg::Reset { stream_id } => {
                w.u8(U_RESET);
                w.u16(*stream_id);
            }
            UplinkMsg::ClientHello { eph_pub } => {
                w.u8(U_CLIENT_HELLO);
                w.bytes(eph_pub);
            }
        }
    }

    fn read(r: &mut Reader) -> Result<UplinkMsg> {
        match r.u8()? {
            U_HELLO => Ok(UplinkMsg::Hello { max_resp: r.u16()? }),
            U_OPEN => {
                let stream_id = r.u16()?;
                let addr = Addr::read(r)?;
                let port = r.u16()?;
                Ok(UplinkMsg::Open { stream_id, addr, port })
            }
            U_DATA => {
                let stream_id = r.u16()?;
                let offset = r.u32()?;
                let payload = r.lp16()?.to_vec();
                Ok(UplinkMsg::Data { stream_id, offset, payload })
            }
            U_CLOSE => Ok(UplinkMsg::Close { stream_id: r.u16()? }),
            U_ACK => Ok(UplinkMsg::Ack {
                stream_id: r.u16()?,
                up_to: r.u32()?,
            }),
            U_POLL => Ok(UplinkMsg::Poll),
            U_LOSS => Ok(UplinkMsg::Loss { permille: r.u16()? }),
            U_PROBE => {
                let nonce = r.u32()?;
                let want = r.u16()?;
                let pad = r.lp16()?.to_vec();
                Ok(UplinkMsg::Probe { nonce, want, pad })
            }
            U_RESET => Ok(UplinkMsg::Reset { stream_id: r.u16()? }),
            U_CLIENT_HELLO => {
                let b = r.take(32)?;
                let mut eph_pub = [0u8; 32];
                eph_pub.copy_from_slice(b);
                Ok(UplinkMsg::ClientHello { eph_pub })
            }
            other => Err(Error::Protocol(format!("unknown uplink kind {other}"))),
        }
    }
}

/// Serialize a batch of uplink messages into a plaintext payload.
pub fn encode_uplink(msgs: &[UplinkMsg]) -> Vec<u8> {
    let mut w = Writer::new();
    for m in msgs {
        m.write(&mut w);
    }
    w.into_vec()
}

/// Parse a plaintext payload into a batch of uplink messages.
pub fn decode_uplink(buf: &[u8]) -> Result<Vec<UplinkMsg>> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(UplinkMsg::read(&mut r)?);
    }
    Ok(out)
}

// ---------------------------- Downlink messages ----------------------------

const D_WELCOME: u8 = 1;
const D_OPEN_RESULT: u8 = 2;
const D_SHARD: u8 = 3;
const D_UPACK: u8 = 4;
const D_CLOSED: u8 = 5;
const D_PROBEACK: u8 = 6;
const D_RESET: u8 = 7;
const D_SERVER_HELLO: u8 = 8;

/// A FEC shard belonging to a per-stream block, self-describing so it can be
/// decoded independently of arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardMsg {
    pub stream_id: u16,
    pub block_seq: u32,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub shard_len: u16,
    pub original_len: u32,
    pub shard_index: u8,
    pub shard: Vec<u8>,
}

/// A message sent server -> client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownlinkMsg {
    /// Acknowledges session creation.
    Welcome,
    /// Result of an Open request: status 0 = success, non-zero = failure code.
    OpenResult { stream_id: u16, status: u8 },
    /// A FEC data shard.
    Shard(ShardMsg),
    /// Next expected uplink byte offset for a stream (cumulative ACK).
    UpAck { stream_id: u16, up_to: u32 },
    /// The stream has been closed by the server/target.
    Closed { stream_id: u16 },
    /// Echo response to a [`UplinkMsg::Probe`], carrying `want` bytes back.
    ProbeAck { nonce: u32, data: Vec<u8> },
    /// Abnormal stream teardown (target connection error). Distinct from
    /// `Closed`, which is a graceful end-of-stream; on `Reset` the client tears
    /// the local connection down promptly instead of waiting for more data.
    Reset { stream_id: u16 },
    /// Key-exchange handshake reply: the server's ephemeral X25519 public key.
    ServerHello { eph_pub: [u8; 32] },
}

impl DownlinkMsg {
    fn write(&self, w: &mut Writer) {
        match self {
            DownlinkMsg::Welcome => w.u8(D_WELCOME),
            DownlinkMsg::OpenResult { stream_id, status } => {
                w.u8(D_OPEN_RESULT);
                w.u16(*stream_id);
                w.u8(*status);
            }
            DownlinkMsg::Shard(s) => {
                w.u8(D_SHARD);
                w.u16(s.stream_id);
                w.u32(s.block_seq);
                w.u8(s.data_shards);
                w.u8(s.parity_shards);
                w.u16(s.shard_len);
                w.u32(s.original_len);
                w.u8(s.shard_index);
                w.lp16(&s.shard);
            }
            DownlinkMsg::UpAck { stream_id, up_to } => {
                w.u8(D_UPACK);
                w.u16(*stream_id);
                w.u32(*up_to);
            }
            DownlinkMsg::Closed { stream_id } => {
                w.u8(D_CLOSED);
                w.u16(*stream_id);
            }
            DownlinkMsg::ProbeAck { nonce, data } => {
                w.u8(D_PROBEACK);
                w.u32(*nonce);
                w.lp16(data);
            }
            DownlinkMsg::Reset { stream_id } => {
                w.u8(D_RESET);
                w.u16(*stream_id);
            }
            DownlinkMsg::ServerHello { eph_pub } => {
                w.u8(D_SERVER_HELLO);
                w.bytes(eph_pub);
            }
        }
    }

    fn read(r: &mut Reader) -> Result<DownlinkMsg> {
        match r.u8()? {
            D_WELCOME => Ok(DownlinkMsg::Welcome),
            D_OPEN_RESULT => Ok(DownlinkMsg::OpenResult {
                stream_id: r.u16()?,
                status: r.u8()?,
            }),
            D_SHARD => {
                let stream_id = r.u16()?;
                let block_seq = r.u32()?;
                let data_shards = r.u8()?;
                let parity_shards = r.u8()?;
                let shard_len = r.u16()?;
                let original_len = r.u32()?;
                let shard_index = r.u8()?;
                let shard = r.lp16()?.to_vec();
                Ok(DownlinkMsg::Shard(ShardMsg {
                    stream_id,
                    block_seq,
                    data_shards,
                    parity_shards,
                    shard_len,
                    original_len,
                    shard_index,
                    shard,
                }))
            }
            D_UPACK => Ok(DownlinkMsg::UpAck {
                stream_id: r.u16()?,
                up_to: r.u32()?,
            }),
            D_CLOSED => Ok(DownlinkMsg::Closed { stream_id: r.u16()? }),
            D_PROBEACK => {
                let nonce = r.u32()?;
                let data = r.lp16()?.to_vec();
                Ok(DownlinkMsg::ProbeAck { nonce, data })
            }
            D_RESET => Ok(DownlinkMsg::Reset { stream_id: r.u16()? }),
            D_SERVER_HELLO => {
                let b = r.take(32)?;
                let mut eph_pub = [0u8; 32];
                eph_pub.copy_from_slice(b);
                Ok(DownlinkMsg::ServerHello { eph_pub })
            }
            other => Err(Error::Protocol(format!("unknown downlink kind {other}"))),
        }
    }
}

/// Serialize a batch of downlink messages.
pub fn encode_downlink(msgs: &[DownlinkMsg]) -> Vec<u8> {
    let mut w = Writer::new();
    for m in msgs {
        m.write(&mut w);
    }
    w.into_vec()
}

/// Parse a plaintext payload into a batch of downlink messages.
pub fn decode_downlink(buf: &[u8]) -> Result<Vec<DownlinkMsg>> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(DownlinkMsg::read(&mut r)?);
    }
    Ok(out)
}

/// Convert a parsed [`Addr`] + port to a connectable host string.
pub fn addr_to_host(addr: &Addr) -> String {
    match addr {
        Addr::V4(ip) => IpAddr::V4(*ip).to_string(),
        Addr::V6(ip) => IpAddr::V6(*ip).to_string(),
        Addr::Domain(d) => d.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_round_trip() {
        let h = FrameHeader {
            session_id: 0xA1B2C3D4,
            counter: 0x05060708,
        };
        let enc = h.encode();
        let dec = FrameHeader::decode(&enc).unwrap();
        assert_eq!(h, dec);
    }

    #[test]
    fn uplink_batch_round_trip() {
        let msgs = vec![
            UplinkMsg::Hello { max_resp: 1232 },
            UplinkMsg::Open {
                stream_id: 1,
                addr: Addr::Domain("example.com".into()),
                port: 443,
            },
            UplinkMsg::Data {
                stream_id: 1,
                offset: 0,
                payload: b"GET / HTTP/1.1".to_vec(),
            },
            UplinkMsg::Ack { stream_id: 1, up_to: 3 },
            UplinkMsg::Poll,
            UplinkMsg::Reset { stream_id: 2 },
            UplinkMsg::ClientHello { eph_pub: [0x5au8; 32] },
            UplinkMsg::Close { stream_id: 1 },
        ];
        let enc = encode_uplink(&msgs);
        let dec = decode_uplink(&enc).unwrap();
        assert_eq!(msgs, dec);
    }

    #[test]
    fn downlink_batch_round_trip() {
        let msgs = vec![
            DownlinkMsg::Welcome,
            DownlinkMsg::OpenResult { stream_id: 2, status: 0 },
            DownlinkMsg::Shard(ShardMsg {
                stream_id: 2,
                block_seq: 7,
                data_shards: 8,
                parity_shards: 3,
                shard_len: 200,
                original_len: 1500,
                shard_index: 5,
                shard: vec![9u8; 200],
            }),
            DownlinkMsg::UpAck { stream_id: 2, up_to: 14 },
            DownlinkMsg::Reset { stream_id: 3 },
            DownlinkMsg::ServerHello { eph_pub: [0xa5u8; 32] },
            DownlinkMsg::Closed { stream_id: 2 },
        ];
        let enc = encode_downlink(&msgs);
        let dec = decode_downlink(&enc).unwrap();
        assert_eq!(msgs, dec);
    }

    #[test]
    fn addr_v4_v6_round_trip() {
        for addr in [
            Addr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            Addr::V6(Ipv6Addr::LOCALHOST),
            Addr::Domain("a.example.org".into()),
        ] {
            let mut w = Writer::new();
            addr.write(&mut w);
            let bytes = w.into_vec();
            let mut r = Reader::new(&bytes);
            assert_eq!(Addr::read(&mut r).unwrap(), addr);
        }
    }
}
