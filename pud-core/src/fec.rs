//! Forward error correction over Reed-Solomon erasure codes.
//!
//! Why FEC and not just retransmission: on a high-RTT, lossy path (an Iranian
//! resolver during a shutdown) every retransmit costs a full round trip, which
//! is exactly what kills classic ARQ tunnels. Instead we group a block of `k`
//! data shards into `k + m` coded shards. The receiver reconstructs the whole
//! block from *any* `k` of the `k + m` shards, with zero extra round trips.
//!
//! Each shard is carried in its own DNS message and tagged (out of band, by the
//! protocol layer) with its block id and shard index, so missing shards are
//! known erasures — the easy case for Reed-Solomon.
//!
//! The amount of parity `m` is chosen adaptively by the protocol layer from the
//! measured loss rate; this module is the pure codec.

use crate::error::{Error, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

/// A single coded shard with its position in the block.
#[derive(Debug, Clone)]
pub struct Shard {
    /// Index within the block: `0..k` are data shards, `k..k+m` are parity.
    pub index: u16,
    pub data: Vec<u8>,
}

/// Parameters describing an encoded block, needed for decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockParams {
    /// Number of data shards.
    pub data_shards: u16,
    /// Number of parity shards.
    pub parity_shards: u16,
    /// Equal length of every shard.
    pub shard_len: u16,
    /// Length of the original (pre-padding) payload.
    pub original_len: u32,
}

/// Encode `data` into `data_shards + parity_shards` equal-length shards.
///
/// `parity_shards` may be zero, in which case the data is simply split into
/// shards with no redundancy (every data shard is then required to recover).
pub fn encode(data: &[u8], data_shards: u16, parity_shards: u16) -> Result<(BlockParams, Vec<Shard>)> {
    if data_shards == 0 {
        return Err(Error::Fec("data_shards must be >= 1".into()));
    }
    let k = data_shards as usize;
    let m = parity_shards as usize;

    let shard_len = data.len().div_ceil(k).max(1);
    if shard_len > u16::MAX as usize {
        return Err(Error::TooLarge {
            got: shard_len,
            limit: u16::MAX as usize,
        });
    }

    // Build k data shards (zero-padded) plus m empty parity shards.
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
    for i in 0..k {
        let start = i * shard_len;
        let mut shard = vec![0u8; shard_len];
        if start < data.len() {
            let end = (start + shard_len).min(data.len());
            shard[..end - start].copy_from_slice(&data[start..end]);
        }
        shards.push(shard);
    }
    for _ in 0..m {
        shards.push(vec![0u8; shard_len]);
    }

    if m > 0 {
        let rs = ReedSolomon::new(k, m).map_err(|e| Error::Fec(e.to_string()))?;
        rs.encode(&mut shards).map_err(|e| Error::Fec(e.to_string()))?;
    }

    let params = BlockParams {
        data_shards,
        parity_shards,
        shard_len: shard_len as u16,
        original_len: data.len() as u32,
    };

    let out = shards
        .into_iter()
        .enumerate()
        .map(|(i, data)| Shard {
            index: i as u16,
            data,
        })
        .collect();

    Ok((params, out))
}

/// Decode a block from a (possibly incomplete) set of received shards.
///
/// Returns the reconstructed original payload, or an error if fewer than
/// `data_shards` distinct shards are available.
pub fn decode(params: BlockParams, received: &[Shard]) -> Result<Vec<u8>> {
    let k = params.data_shards as usize;
    let m = params.parity_shards as usize;
    let total = k + m;
    let shard_len = params.shard_len as usize;

    let mut slots: Vec<Option<Vec<u8>>> = vec![None; total];
    let mut present = 0usize;
    for shard in received {
        let idx = shard.index as usize;
        if idx >= total {
            continue;
        }
        if shard.data.len() != shard_len {
            return Err(Error::Fec(format!(
                "shard {idx} has length {}, expected {shard_len}",
                shard.data.len()
            )));
        }
        if slots[idx].is_none() {
            slots[idx] = Some(shard.data.clone());
            present += 1;
        }
    }

    if present < k {
        return Err(Error::Fec(format!(
            "insufficient shards: have {present}, need {k}"
        )));
    }

    if m > 0 {
        // If any data shard is missing, reconstruct using parity.
        let data_missing = slots[..k].iter().any(|s| s.is_none());
        if data_missing {
            let rs = ReedSolomon::new(k, m).map_err(|e| Error::Fec(e.to_string()))?;
            rs.reconstruct(&mut slots)
                .map_err(|e| Error::Fec(e.to_string()))?;
        }
    } else if slots[..k].iter().any(|s| s.is_none()) {
        return Err(Error::Fec("no parity and a data shard is missing".into()));
    }

    let mut out = Vec::with_capacity(k * shard_len);
    for slot in slots.iter().take(k) {
        let shard = slot
            .as_ref()
            .ok_or_else(|| Error::Fec("reconstruction left a hole".into()))?;
        out.extend_from_slice(shard);
    }
    out.truncate(params.original_len as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    #[test]
    fn no_loss_round_trip() {
        let data = sample(1000);
        let (params, shards) = encode(&data, 8, 4).unwrap();
        let decoded = decode(params, &shards).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn recovers_from_parity_count_loss() {
        let data = sample(1000);
        let (params, shards) = encode(&data, 8, 4).unwrap();
        // Drop 4 shards (== parity count): keep any 8 of 12.
        let kept: Vec<Shard> = shards.into_iter().filter(|s| s.index % 3 != 0).collect();
        let decoded = decode(params, &kept).unwrap();
        assert_eq!(decoded.len(), data.len());
        assert_eq!(decoded, data);
    }

    #[test]
    fn drop_only_data_shards_still_recovers() {
        let data = sample(777);
        let (params, shards) = encode(&data, 6, 3).unwrap();
        // Drop 3 data shards; rely entirely on parity.
        let kept: Vec<Shard> = shards.into_iter().filter(|s| s.index >= 3).collect();
        assert_eq!(kept.len(), 6);
        let decoded = decode(params, &kept).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn too_few_shards_fails() {
        let data = sample(500);
        let (params, shards) = encode(&data, 8, 2).unwrap();
        let kept: Vec<Shard> = shards.into_iter().take(7).collect();
        assert!(decode(params, &kept).is_err());
    }

    #[test]
    fn zero_parity_requires_all_data() {
        let data = sample(300);
        let (params, shards) = encode(&data, 5, 0).unwrap();
        let decoded = decode(params, &shards).unwrap();
        assert_eq!(decoded, data);
        let missing: Vec<Shard> = shards.into_iter().skip(1).collect();
        assert!(decode(params, &missing).is_err());
    }
}
