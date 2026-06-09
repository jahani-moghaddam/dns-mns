//! DNS-safe base32 encoding for the uplink channel.
//!
//! The uplink carries tunnel bytes inside the QNAME of a DNS query. DNS names
//! are case-insensitive and reliably preserve only the characters `[a-z0-9]`
//! (and `-`). We therefore use a lowercase RFC 4648 base32 alphabet
//! (`abcdefghijklmnopqrstuvwxyz234567`) with no padding. Base32 packs 5 bits
//! per character, so the expansion factor is 8/5 = 1.6x. This is the densest
//! encoding that survives case-folding resolvers.
//!
//! Decoding is strict: any character outside the alphabet is an error, so a
//! resolver that mangles the name produces a clean decode failure rather than
//! silently corrupt data.

use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Reverse lookup table: byte -> 5-bit value, or 0xFF if not in the alphabet.
const fn build_reverse() -> [u8; 256] {
    let mut table = [0xFFu8; 256];
    let mut i = 0;
    while i < 32 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const REVERSE: [u8; 256] = build_reverse();

/// Number of base32 characters needed to encode `n` bytes (no padding).
pub fn encoded_len(n: usize) -> usize {
    // ceil(n * 8 / 5)
    (n * 8 + 4) / 5
}

/// Maximum number of input bytes whose encoding fits in `chars` characters.
pub fn max_input_for_chars(chars: usize) -> usize {
    // floor(chars * 5 / 8)
    chars * 5 / 8
}

/// Encode bytes to a lowercase base32 string with no padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(data.len()));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Decode a lowercase (or uppercase) base32 string with no padding.
pub fn decode(text: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &raw in text {
        // Accept uppercase too in case a resolver upcases the name.
        let c = raw.to_ascii_lowercase();
        let val = REVERSE[c as usize];
        if val == 0xFF {
            return Err(Error::Base32(format!(
                "invalid character 0x{raw:02x} in base32 input"
            )));
        }
        buffer = (buffer << 5) | val as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_random() {
        for len in 0..300usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let encoded = encode(&data);
            assert_eq!(encoded.len(), encoded_len(data.len()));
            assert!(encoded.bytes().all(|b| ALPHABET.contains(&b)));
            let decoded = decode(encoded.as_bytes()).expect("decode");
            assert_eq!(decoded, data, "mismatch at len {len}");
        }
    }

    #[test]
    fn case_insensitive_decode() {
        let data = b"persian ultra dns";
        let encoded = encode(data).to_uppercase();
        let decoded = decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn rejects_invalid() {
        assert!(decode(b"!!!!").is_err());
        // '0', '1', '8', '9' are not in the alphabet.
        assert!(decode(b"01890").is_err());
    }

    #[test]
    fn capacity_helpers_consistent() {
        for n in 0..100 {
            let chars = encoded_len(n);
            assert!(max_input_for_chars(chars) >= n);
        }
    }
}
