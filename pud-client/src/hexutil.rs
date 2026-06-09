//! Minimal hex decoding for the pre-shared key.

use anyhow::Result;

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    anyhow::ensure!(s.len() % 2 == 0, "hex string has odd length");
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = val(pair[0])?;
        let lo = val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    anyhow::ensure!(out.len() >= 16, "key must be at least 16 bytes");
    Ok(out)
}

fn val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid hex character 0x{c:02x}"),
    }
}
