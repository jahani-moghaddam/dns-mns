//! Frame assembly: combine the cleartext header, AEAD, and QNAME packing.
//!
//! A frame on the wire is `header(12) || AEAD_ciphertext`. The header is bound
//! as AEAD associated data, so it is authenticated even though it is sent in the
//! clear (the server needs the session id and counter before it can decrypt).

use crate::crypto::{make_nonce, Direction, Session};
use crate::encoding;
use crate::error::{Error, Result};
use crate::protocol::{FrameHeader, FRAME_HEADER_LEN};

/// Maximum length of a DNS name, in bytes (RFC 1035).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum length of a single DNS label.
pub const MAX_LABEL_LEN: usize = 63;

/// Seal a plaintext message batch into a complete frame (`header || ciphertext`).
pub fn seal_frame(session: &Session, dir: Direction, header: FrameHeader, plaintext: &[u8]) -> Vec<u8> {
    let aad = header.encode();
    let nonce = make_nonce(header.session_id, header.counter);
    let ct = session.seal(dir, nonce, &aad, plaintext);
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct);
    out
}

/// Open a complete frame, returning its header and decrypted plaintext.
pub fn open_frame(session: &Session, dir: Direction, frame: &[u8]) -> Result<(FrameHeader, Vec<u8>)> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(Error::Protocol("frame shorter than header".into()));
    }
    let header = FrameHeader::decode(frame)?;
    let aad = &frame[..FRAME_HEADER_LEN];
    let ct = &frame[FRAME_HEADER_LEN..];
    let nonce = make_nonce(header.session_id, header.counter);
    let pt = session.open(dir, nonce, aad, ct)?;
    Ok((header, pt))
}

/// Compute how many raw frame bytes can be packed into the QNAME for a given
/// base domain, accounting for base32 expansion, label-separator dots, and the
/// 255-byte name ceiling. Returns 0 if the base domain alone leaves no room.
pub fn max_uplink_frame_bytes(base_domain: &str) -> usize {
    let base = base_domain.trim_matches('.');
    // Bytes consumed by the base domain plus the dot that separates it from the
    // data labels, plus a small safety margin for the trailing root and length
    // octets the wire format adds.
    let overhead = base.len() + 1 + 2;
    if overhead >= MAX_NAME_LEN {
        return 0;
    }
    let mut budget = MAX_NAME_LEN - overhead;
    // Every up-to-63 data characters also costs one separator dot.
    // Solve for usable characters: chars + ceil(chars/63) <= budget.
    // Approximate conservatively.
    let dots = budget / (MAX_LABEL_LEN + 1) + 1;
    if dots >= budget {
        return 0;
    }
    budget -= dots;
    encoding::max_input_for_chars(budget)
}

/// Pack a frame into a QNAME under `base_domain`:
/// `<base32-of-frame split into <=63 char labels>.<base_domain>`.
pub fn frame_to_qname(frame: &[u8], base_domain: &str) -> Result<String> {
    let encoded = encoding::encode(frame);
    let base = base_domain.trim_matches('.');

    let mut name = String::with_capacity(encoded.len() + base.len() + 8);
    let bytes = encoded.as_bytes();
    let mut first = true;
    for chunk in bytes.chunks(MAX_LABEL_LEN) {
        if !first {
            name.push('.');
        }
        first = false;
        // Safe: base32 output is ASCII.
        name.push_str(std::str::from_utf8(chunk).expect("base32 is ascii"));
    }
    if !name.is_empty() {
        name.push('.');
    }
    name.push_str(base);

    if name.len() > MAX_NAME_LEN {
        return Err(Error::TooLarge {
            got: name.len(),
            limit: MAX_NAME_LEN,
        });
    }
    Ok(name)
}

/// Recover the frame bytes from a QNAME under `base_domain`.
pub fn qname_to_frame(qname: &str, base_domain: &str) -> Result<Vec<u8>> {
    let qname = qname.trim_matches('.').to_ascii_lowercase();
    let base = base_domain.trim_matches('.').to_ascii_lowercase();

    let data_part = if base.is_empty() {
        qname.as_str()
    } else {
        let suffix = format!(".{base}");
        match qname.strip_suffix(&suffix) {
            Some(p) => p,
            None => {
                // Query might be exactly the base (no data) — reject as not ours.
                return Err(Error::Protocol("qname does not match base domain".into()));
            }
        }
    };

    let stripped: String = data_part.chars().filter(|&c| c != '.').collect();
    encoding::decode(stripped.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{encode_uplink, UplinkMsg};

    #[test]
    fn frame_seal_open_round_trip() {
        let s = Session::from_psk(b"psk");
        let header = FrameHeader {
            session_id: 0x11223344,
            counter: 99,
        };
        let pt = encode_uplink(&[UplinkMsg::Poll]);
        let frame = seal_frame(&s, Direction::ClientToServer, header, &pt);
        let (h2, pt2) = open_frame(&s, Direction::ClientToServer, &frame).unwrap();
        assert_eq!(h2, header);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn qname_round_trip() {
        let frame: Vec<u8> = (0..40u8).collect();
        for base in ["t.example.com", "x.io", "a.b.c.example.org"] {
            let qname = frame_to_qname(&frame, base).unwrap();
            assert!(qname.len() <= MAX_NAME_LEN);
            assert!(qname.ends_with(base));
            for label in qname.split('.') {
                assert!(label.len() <= MAX_LABEL_LEN);
            }
            let recovered = qname_to_frame(&qname, base).unwrap();
            assert_eq!(recovered, frame);
        }
    }

    #[test]
    fn capacity_is_respected() {
        let base = "t.example.com";
        let cap = max_uplink_frame_bytes(base);
        assert!(cap > 0);
        let frame = vec![0xABu8; cap];
        let qname = frame_to_qname(&frame, base).unwrap();
        assert!(qname.len() <= MAX_NAME_LEN, "qname {} too long", qname.len());
    }

    #[test]
    fn foreign_qname_rejected() {
        assert!(qname_to_frame("foo.bar.different.com", "t.example.com").is_err());
    }
}
