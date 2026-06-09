//! Authenticated encryption for tunnel frames.
//!
//! We use the ChaCha20-Poly1305 AEAD construction (RFC 8439), assembled here
//! over the RustCrypto `chacha20` and `poly1305` primitives so we can use a
//! **truncated 8-byte authentication tag**. DNS payload is the scarcest
//! resource in the whole system, and a full 16-byte tag is pure overhead on
//! every message; an 8-byte (64-bit) tag is a standard space/security tradeoff
//! used by constrained protocols (IPsec ESP, DTLS). A forged frame would need
//! ~2^64 work per attempt and, even if it authenticated, would only decode to
//! garbage the protocol layer drops.
//!
//! Two independent keys are derived from the pre-shared key with BLAKE3's
//! `derive_key`, one per direction, so the two directions never share a
//! keystream:
//!
//!   * client -> server  ("PersianUltraDNS c2s v1")
//!   * server -> client  ("PersianUltraDNS s2c v1")
//!
//! The 96-bit nonce is built by the protocol layer as
//! `session_id (4 bytes LE) || counter (4 bytes LE) || 0 (4 bytes)`. Folding the
//! session id in gives every session its own nonce space, so multiple clients
//! can share one pre-shared key without colliding nonces. The cleartext frame
//! header bytes are bound as AAD so they cannot be tampered with.

use crate::error::{Error, Result};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use x25519_dalek::{EphemeralSecret, PublicKey};

const CONTEXT_C2S: &str = "PersianUltraDNS c2s v1";
const CONTEXT_S2C: &str = "PersianUltraDNS s2c v1";
const CONTEXT_PSK: &str = "PersianUltraDNS psk v1";
const CONTEXT_DATA_C2S: &str = "PersianUltraDNS data c2s v1";
const CONTEXT_DATA_S2C: &str = "PersianUltraDNS data s2c v1";

/// Poly1305 authentication tag length carried on the wire (truncated from the
/// full 16-byte tag). This is the only per-frame crypto overhead.
pub const TAG_LEN: usize = 8;

/// Direction of a frame, selecting which derived key to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// A keyed context holding both directional keys.
#[derive(Clone)]
pub struct Session {
    c2s_key: [u8; 32],
    s2c_key: [u8; 32],
}

impl Session {
    /// Derive directional keys from a pre-shared secret.
    pub fn from_psk(psk: &[u8]) -> Self {
        Session {
            c2s_key: blake3::derive_key(CONTEXT_C2S, psk),
            s2c_key: blake3::derive_key(CONTEXT_S2C, psk),
        }
    }

    /// Derive the per-session **data** keys from the handshake: the X25519
    /// shared secret bound together with the pre-shared key and the handshake
    /// transcript (both ephemeral public keys + session id).
    ///
    /// Binding both `dh` and `psk` gives us both properties at once:
    ///   * forward secrecy — without the ephemeral `dh`, the PSK alone cannot
    ///     derive these keys, so recording traffic + later stealing the PSK does
    ///     not decrypt past sessions;
    ///   * mutual authentication — without the PSK, an active MITM doing its own
    ///     DH derives different keys and cannot talk to either side.
    ///
    /// Because the keys are unique per handshake (fresh ephemerals), reusing a
    /// session id across reconnects can never reuse a (key, nonce) pair.
    pub fn derive_data(
        psk: &[u8],
        dh: &[u8; 32],
        session_id: u32,
        client_pub: &[u8; 32],
        server_pub: &[u8; 32],
    ) -> Self {
        let psk32 = blake3::derive_key(CONTEXT_PSK, psk);
        let mut ikm = Vec::with_capacity(32 + 32 + 32 + 4);
        ikm.extend_from_slice(dh);
        ikm.extend_from_slice(client_pub);
        ikm.extend_from_slice(server_pub);
        ikm.extend_from_slice(&session_id.to_be_bytes());
        let master = blake3::keyed_hash(&psk32, &ikm);
        Session {
            c2s_key: blake3::derive_key(CONTEXT_DATA_C2S, master.as_bytes()),
            s2c_key: blake3::derive_key(CONTEXT_DATA_S2C, master.as_bytes()),
        }
    }

    fn key(&self, dir: Direction) -> &[u8; 32] {
        match dir {
            Direction::ClientToServer => &self.c2s_key,
            Direction::ServerToClient => &self.s2c_key,
        }
    }

    /// Encrypt `plaintext` for `dir` using `nonce`, binding `aad` as associated
    /// data. Returns ciphertext concatenated with the truncated tag.
    pub fn seal(&self, dir: Direction, nonce: [u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = self.key(dir);
        let mut cipher = ChaCha20::new(key.into(), (&nonce).into());

        // Block 0 keystream gives the one-time Poly1305 key; encryption runs
        // from block 1 onward (RFC 8439).
        let mut block0 = [0u8; 64];
        cipher.apply_keystream(&mut block0);

        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        let tag = poly1305_tag(&block0[..32], aad, &ciphertext);

        let mut out = ciphertext;
        out.extend_from_slice(&tag[..TAG_LEN]);
        out
    }

    /// Decrypt `data` (ciphertext with appended truncated tag) for `dir`,
    /// verifying `aad`.
    pub fn open(&self, dir: Direction, nonce: [u8; 12], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < TAG_LEN {
            return Err(Error::Crypto("frame shorter than tag".into()));
        }
        let (ciphertext, tag_recv) = data.split_at(data.len() - TAG_LEN);

        let key = self.key(dir);
        let mut cipher = ChaCha20::new(key.into(), (&nonce).into());

        let mut block0 = [0u8; 64];
        cipher.apply_keystream(&mut block0);

        let tag = poly1305_tag(&block0[..32], aad, ciphertext);
        if !ct_eq(&tag[..TAG_LEN], tag_recv) {
            return Err(Error::Crypto("authentication failed".into()));
        }

        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }
}

/// Compute the (full 16-byte) Poly1305 tag over the RFC 8439 AEAD message:
/// `aad || pad16 || ciphertext || pad16 || len(aad) u64le || len(ct) u64le`.
fn poly1305_tag(poly_key: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mac = Poly1305::new(poly_key.into());

    let mut buf =
        Vec::with_capacity(aad.len() + pad16(aad.len()) + ciphertext.len() + pad16(ciphertext.len()) + 16);
    buf.extend_from_slice(aad);
    buf.resize(buf.len() + pad16(aad.len()), 0);
    buf.extend_from_slice(ciphertext);
    buf.resize(buf.len() + pad16(ciphertext.len()), 0);
    buf.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    buf.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    // `buf` is a multiple of 16 by construction, so no implicit padding occurs.
    let tag = mac.compute_unpadded(&buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// Number of zero bytes needed to pad `n` up to a 16-byte boundary.
fn pad16(n: usize) -> usize {
    (16 - (n % 16)) % 16
}

/// Constant-time equality for the (fixed, short) tag comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Build a 96-bit nonce from a session id and a per-direction counter.
/// Layout: `session_id (4 bytes LE) || counter (4 bytes LE) || 0 (4 bytes)`.
pub fn make_nonce(session_id: u32, counter: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&session_id.to_le_bytes());
    n[4..8].copy_from_slice(&counter.to_le_bytes());
    n
}

/// One side's ephemeral X25519 key for a session handshake. Single-use: the
/// secret is consumed when the shared secret is computed, enforcing forward
/// secrecy.
pub struct Handshake {
    secret: EphemeralSecret,
    /// Our ephemeral public key, to send to the peer (and resend on retransmit).
    pub public: [u8; 32],
}

impl Handshake {
    /// Generate a fresh ephemeral keypair from the OS CSPRNG.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Handshake { secret, public }
    }

    /// Consume the ephemeral secret to compute the shared secret with `peer_pub`
    /// and derive the directional data keys. `client_pub`/`server_pub` are the
    /// full transcript (same on both ends, in the same order).
    pub fn complete(
        self,
        peer_pub: &[u8; 32],
        psk: &[u8],
        session_id: u32,
        client_pub: &[u8; 32],
        server_pub: &[u8; 32],
    ) -> Session {
        let their = PublicKey::from(*peer_pub);
        let dh = self.secret.diffie_hellman(&their);
        Session::derive_data(psk, dh.as_bytes(), session_id, client_pub, server_pub)
    }
}

impl Default for Handshake {
    fn default() -> Self {
        Handshake::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let s = Session::from_psk(b"shared secret");
        let aad = b"header-b";
        let pt = b"hello tunnel";
        let nonce = make_nonce(0xDEADBEEF, 1);
        let ct = s.seal(Direction::ClientToServer, nonce, aad, pt);
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
        let rt = s.open(Direction::ClientToServer, nonce, aad, &ct).unwrap();
        assert_eq!(rt, pt);
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let s = Session::from_psk(b"k");
        let n = make_nonce(7, 3);
        let ct = s.seal(Direction::ClientToServer, n, b"aad12345", b"");
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(s.open(Direction::ClientToServer, n, b"aad12345", &ct).unwrap(), b"");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let s = Session::from_psk(b"k");
        let n = make_nonce(1, 1);
        let mut ct = s.seal(Direction::ClientToServer, n, b"aad", b"some data here");
        ct[0] ^= 0x01;
        assert!(s.open(Direction::ClientToServer, n, b"aad", &ct).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let s = Session::from_psk(b"k");
        let n = make_nonce(1, 1);
        let mut ct = s.seal(Direction::ClientToServer, n, b"aad", b"some data here");
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        assert!(s.open(Direction::ClientToServer, n, b"aad", &ct).is_err());
    }

    #[test]
    fn wrong_counter_fails() {
        let s = Session::from_psk(b"k");
        let ct = s.seal(Direction::ServerToClient, make_nonce(1, 5), b"a", b"data");
        assert!(s
            .open(Direction::ServerToClient, make_nonce(1, 6), b"a", &ct)
            .is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let s = Session::from_psk(b"k");
        let n = make_nonce(2, 5);
        let ct = s.seal(Direction::ServerToClient, n, b"aad1", b"data");
        assert!(s.open(Direction::ServerToClient, n, b"aad2", &ct).is_err());
    }

    #[test]
    fn wrong_direction_fails() {
        let s = Session::from_psk(b"k");
        let n = make_nonce(3, 1);
        let ct = s.seal(Direction::ClientToServer, n, b"", b"data");
        assert!(s.open(Direction::ServerToClient, n, b"", &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let a = Session::from_psk(b"key-a");
        let b = Session::from_psk(b"key-b");
        let n = make_nonce(4, 1);
        let ct = a.seal(Direction::ClientToServer, n, b"", b"data");
        assert!(b.open(Direction::ClientToServer, n, b"", &ct).is_err());
    }

    #[test]
    fn distinct_sessions_distinct_nonces() {
        assert_ne!(make_nonce(1, 1), make_nonce(2, 1));
        assert_ne!(make_nonce(1, 1), make_nonce(1, 2));
    }

    #[test]
    fn handshake_both_sides_agree() {
        let psk = b"shared secret";
        let sid = 0x11223344u32;
        let client = Handshake::new();
        let server = Handshake::new();
        let cpub = client.public;
        let spub = server.public;

        let cs = client.complete(&spub, psk, sid, &cpub, &spub);
        let ss = server.complete(&cpub, psk, sid, &cpub, &spub);

        let n = make_nonce(sid, 1);
        let ct = cs.seal(Direction::ClientToServer, n, b"hdr12345", b"payload");
        assert_eq!(
            ss.open(Direction::ClientToServer, n, b"hdr12345", &ct).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn handshake_wrong_psk_yields_incompatible_keys() {
        let sid = 7u32;
        let client = Handshake::new();
        let server = Handshake::new();
        let cpub = client.public;
        let spub = server.public;

        let cs = client.complete(&spub, b"psk-A", sid, &cpub, &spub);
        let ss = server.complete(&cpub, b"psk-B", sid, &cpub, &spub);

        let n = make_nonce(sid, 1);
        let ct = cs.seal(Direction::ClientToServer, n, b"", b"data");
        assert!(ss.open(Direction::ClientToServer, n, b"", &ct).is_err());
    }

    #[test]
    fn handshake_fresh_ephemerals_give_fresh_keys() {
        let psk = b"k";
        let sid = 1u32;
        let derive = || {
            let c = Handshake::new();
            let s = Handshake::new();
            let (cp, sp) = (c.public, s.public);
            let cs = c.complete(&sp, psk, sid, &cp, &sp);
            let n = make_nonce(sid, 1);
            cs.seal(Direction::ClientToServer, n, b"", b"same-plaintext")
        };
        assert_ne!(derive(), derive());
    }

    /// Validate our hand-assembled construction against the reference
    /// `chacha20poly1305` crate: the full 16-byte tag and ciphertext must match
    /// byte-for-byte, proving the RFC 8439 assembly is correct (independent of
    /// truncation).
    #[test]
    fn matches_reference_chacha20poly1305() {
        use chacha20poly1305::aead::{AeadInPlace, KeyInit as RefKeyInit};
        use chacha20poly1305::ChaCha20Poly1305;

        let key = [7u8; 32];
        let nonce = make_nonce(0x01020304, 0x0A0B0C0D);
        let aad = b"associated-data-xyz";
        let pt = b"the quick brown fox jumps over the lazy dog";

        // Reference: detached encryption gives ciphertext + full 16-byte tag.
        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut ref_ct = pt.to_vec();
        let ref_tag = cipher
            .encrypt_in_place_detached((&nonce).into(), aad, &mut ref_ct)
            .unwrap();

        // Ours: replicate the keystream/tag manually with the full tag.
        let mut c = ChaCha20::new((&key).into(), (&nonce).into());
        let mut block0 = [0u8; 64];
        c.apply_keystream(&mut block0);
        let mut our_ct = pt.to_vec();
        c.apply_keystream(&mut our_ct);
        let our_tag = poly1305_tag(&block0[..32], aad, &our_ct);

        assert_eq!(our_ct, ref_ct.as_slice(), "ciphertext mismatch");
        assert_eq!(&our_tag[..], ref_tag.as_slice(), "tag mismatch");
    }
}
