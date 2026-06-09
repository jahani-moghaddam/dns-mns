//! PersianUltraDNS core library.
//!
//! This crate is the shared engine for both the client and the server. It is
//! transport-agnostic: it knows how to turn a stream of bytes into DNS-carried,
//! encrypted, forward-error-corrected frames and back, but it does not itself
//! own any sockets. The binaries (`pud-client`, `pud-server`) drive it.
//!
//! Module map:
//!   * [`encoding`] — DNS-safe base32 for the uplink QNAME.
//!   * [`dns`]      — minimal DNS wire codec (query / TXT response).
//!   * [`crypto`]   — ChaCha20-Poly1305 AEAD with per-direction keys.
//!   * [`fec`]      — Reed-Solomon erasure coding (loss recovery, no round trip).
//!   * [`policy`]   — online loss estimation + adaptive parity selection.
//!   * [`wire`]     — byte reader/writer primitives.
//!   * [`protocol`] — the application messages exchanged in each direction.
//!   * [`frame`]    — header + AEAD + QNAME packing.
//!   * [`cache`]    — client-side DNS answer cache.

pub mod cache;
pub mod crypto;
pub mod dns;
pub mod encoding;
pub mod error;
pub mod fec;
pub mod frame;
pub mod policy;
pub mod protocol;
pub mod wire;

pub use error::{Error, Result};

/// Protocol version carried in the client Hello.
pub const PROTOCOL_VERSION: u8 = 1;
