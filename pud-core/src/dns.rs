//! Minimal, correct DNS wire-format codec specialised for the tunnel.
//!
//! We hand-roll just enough of RFC 1035 (+ EDNS0, RFC 6891) to:
//!   * build a query whose QNAME carries uplink bytes and which advertises a
//!     large EDNS UDP buffer,
//!   * on the server, parse that query and build a response whose TXT answer
//!     carries downlink bytes,
//!   * on the client, parse the response and recover the TXT bytes.
//!
//! Name parsing handles compression pointers because recursive resolvers
//! routinely compress the echoed question name in their responses.

use crate::error::{Error, Result};

/// DNS record type for TXT.
pub const TYPE_TXT: u16 = 16;
/// DNS record type for OPT (EDNS0 pseudo-record).
pub const TYPE_OPT: u16 = 41;
/// DNS class IN.
pub const CLASS_IN: u16 = 1;

/// Each TXT "character-string" is length-prefixed by a single byte.
pub const TXT_CHUNK_MAX: usize = 255;

/// A parsed DNS question.
#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A parsed query as seen by the server.
#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub id: u16,
    pub question: Question,
    /// EDNS UDP payload size advertised by the requester, if any.
    pub edns_udp_size: Option<u16>,
}

/// Write a DNS name (dotted form) into `out` without compression.
fn write_name(out: &mut Vec<u8>, name: &str) -> Result<()> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(Error::Dns(format!("label too long: {} bytes", label.len())));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root terminator
    Ok(())
}

/// Parse a DNS name starting at `pos`, following compression pointers.
/// Returns the dotted name and the position immediately after the name in the
/// *original* (non-pointer) stream.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut after_pointer = start;
    let mut hops = 0usize;

    loop {
        if pos >= buf.len() {
            return Err(Error::Dns("name parse out of bounds".into()));
        }
        let len = buf[pos];
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= buf.len() {
                return Err(Error::Dns("truncated compression pointer".into()));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            if !jumped {
                after_pointer = pos + 2;
            }
            jumped = true;
            hops += 1;
            if hops > 64 {
                return Err(Error::Dns("compression pointer loop".into()));
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let len = len as usize;
        let s = pos + 1;
        let e = s + len;
        if e > buf.len() {
            return Err(Error::Dns("label out of bounds".into()));
        }
        let label = String::from_utf8_lossy(&buf[s..e]).into_owned();
        labels.push(label);
        pos = e;
    }

    let end = if jumped { after_pointer } else { pos };
    Ok((labels.join("."), end))
}

/// Build a tunnel query: a single TXT question for `qname`, RD set, and an
/// EDNS0 OPT record advertising `udp_size`.
pub fn build_query(id: u16, qname: &str, udp_size: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(qname.len() + 32);
    // Header.
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (the OPT record)

    // Question.
    write_name(&mut out, qname)?;
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());

    // EDNS0 OPT record in the additional section.
    out.push(0); // root name
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&udp_size.to_be_bytes()); // CLASS = requestor UDP size
    out.extend_from_slice(&0u32.to_be_bytes()); // TTL: extended rcode + flags
    out.extend_from_slice(&0u16.to_be_bytes()); // RDLEN = 0

    Ok(out)
}

/// Parse the first question (and EDNS UDP size, if present) from a query.
pub fn parse_query(buf: &[u8]) -> Result<ParsedQuery> {
    if buf.len() < 12 {
        return Err(Error::Dns("query shorter than header".into()));
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);
    if qdcount < 1 {
        return Err(Error::Dns("no question in query".into()));
    }

    let (name, mut pos) = read_name(buf, 12)?;
    if pos + 4 > buf.len() {
        return Err(Error::Dns("truncated question".into()));
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    pos += 4;

    // Walk the additional section looking for an OPT record to read its UDP size.
    let mut edns_udp_size = None;
    if arcount > 0 {
        // Skip the answer and authority sections (both zero in a query, but be safe).
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let to_skip = ancount as usize + nscount as usize;
        for _ in 0..to_skip {
            pos = skip_rr(buf, pos)?;
        }
        for _ in 0..arcount {
            if pos >= buf.len() {
                break;
            }
            let (_n, p) = read_name(buf, pos)?;
            if p + 10 > buf.len() {
                break;
            }
            let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
            let class = u16::from_be_bytes([buf[p + 2], buf[p + 3]]);
            let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
            if rtype == TYPE_OPT {
                edns_udp_size = Some(class); // CLASS field doubles as UDP size for OPT
            }
            pos = p + 10 + rdlen;
        }
    }

    Ok(ParsedQuery {
        id,
        question: Question { name, qtype, qclass },
        edns_udp_size,
    })
}

/// Advance past one resource record starting at `pos`, returning the position
/// after it.
fn skip_rr(buf: &[u8], pos: usize) -> Result<usize> {
    let (_n, p) = read_name(buf, pos)?;
    if p + 10 > buf.len() {
        return Err(Error::Dns("truncated rr header".into()));
    }
    let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
    let end = p + 10 + rdlen;
    if end > buf.len() {
        return Err(Error::Dns("truncated rr rdata".into()));
    }
    Ok(end)
}

/// Build a response to `query` carrying `payload` inside one or more TXT
/// character-strings within a single TXT answer record.
///
/// `payload` is split into <=255-byte character-strings. The caller is
/// responsible for keeping the total response within the negotiated UDP size.
pub fn build_txt_response(query: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(Error::Dns("query too short to answer".into()));
    }
    let id = u16::from_be_bytes([query[0], query[1]]);

    // Re-read the question so we can echo it verbatim.
    let (qname, mut qend) = read_name(query, 12)?;
    if qend + 4 > query.len() {
        return Err(Error::Dns("truncated question in query".into()));
    }
    let qtype = u16::from_be_bytes([query[qend], query[qend + 1]]);
    let qclass = u16::from_be_bytes([query[qend + 2], query[qend + 3]]);
    qend += 4;
    let _ = qend;

    let mut out = Vec::with_capacity(payload.len() + qname.len() + 64);
    // Header: response, RD+RA, one question, one answer.
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (echoed). It begins right after the 12-byte header.
    write_name(&mut out, &qname)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());

    // Answer: a TXT record. Name is a compression pointer to offset 12.
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0 (do not cache the tunnel)

    // RDATA: a sequence of character-strings.
    let mut rdata = Vec::with_capacity(payload.len() + payload.len() / TXT_CHUNK_MAX + 1);
    if payload.is_empty() {
        rdata.push(0); // a single empty character-string
    } else {
        for chunk in payload.chunks(TXT_CHUNK_MAX) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
    }
    if rdata.len() > u16::MAX as usize {
        return Err(Error::TooLarge {
            got: rdata.len(),
            limit: u16::MAX as usize,
        });
    }
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);

    Ok(out)
}

/// Parse a response and concatenate the bytes of every TXT character-string
/// found in the answer section.
pub fn parse_txt_response(buf: &[u8]) -> Result<Vec<u8>> {
    if buf.len() < 12 {
        return Err(Error::Dns("response shorter than header".into()));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = 12;
    // Skip questions.
    for _ in 0..qdcount {
        let (_n, p) = read_name(buf, pos)?;
        pos = p + 4; // QTYPE + QCLASS
        if pos > buf.len() {
            return Err(Error::Dns("truncated question in response".into()));
        }
    }

    let mut payload = Vec::new();
    for _ in 0..ancount {
        let (_n, p) = read_name(buf, pos)?;
        if p + 10 > buf.len() {
            return Err(Error::Dns("truncated answer header".into()));
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        let rstart = p + 10;
        let rend = rstart + rdlen;
        if rend > buf.len() {
            return Err(Error::Dns("truncated answer rdata".into()));
        }
        if rtype == TYPE_TXT {
            let mut i = rstart;
            while i < rend {
                let slen = buf[i] as usize;
                i += 1;
                if i + slen > rend {
                    return Err(Error::Dns("truncated txt character-string".into()));
                }
                payload.extend_from_slice(&buf[i..i + slen]);
                i += slen;
            }
        }
        pos = rend;
    }

    Ok(payload)
}

/// Extract the minimum TTL across all answer records in a response, used to
/// decide how long the client may cache it. Returns `None` if there are no
/// answers or the response cannot be parsed.
pub fn min_answer_ttl(buf: &[u8]) -> Option<u32> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        let (_n, p) = read_name(buf, pos).ok()?;
        pos = p + 4;
        if pos > buf.len() {
            return None;
        }
    }
    let mut min_ttl: Option<u32> = None;
    for _ in 0..ancount {
        let (_n, p) = read_name(buf, pos).ok()?;
        if p + 10 > buf.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        min_ttl = Some(match min_ttl {
            Some(m) => m.min(ttl),
            None => ttl,
        });
        pos = p + 10 + rdlen;
        if pos > buf.len() {
            return None;
        }
    }
    min_ttl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip() {
        let q = build_query(0x1234, "abcde.fghij.t.example.com", 4096).unwrap();
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.question.name, "abcde.fghij.t.example.com");
        assert_eq!(parsed.question.qtype, TYPE_TXT);
        assert_eq!(parsed.edns_udp_size, Some(4096));
    }

    #[test]
    fn response_round_trip_small() {
        let q = build_query(0x4242, "data.t.example.com", 4096).unwrap();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let resp = build_txt_response(&q, payload).unwrap();
        let recovered = parse_txt_response(&resp).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn response_round_trip_multi_chunk() {
        let q = build_query(1, "x.t.example.com", 4096).unwrap();
        let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let resp = build_txt_response(&q, &payload).unwrap();
        let recovered = parse_txt_response(&resp).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn response_empty_payload() {
        let q = build_query(7, "y.t.example.com", 1232).unwrap();
        let resp = build_txt_response(&q, &[]).unwrap();
        let recovered = parse_txt_response(&resp).unwrap();
        assert!(recovered.is_empty());
    }
}
