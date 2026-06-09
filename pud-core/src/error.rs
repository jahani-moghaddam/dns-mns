//! Error types shared across PersianUltraDNS.

use thiserror::Error;

/// Result alias used throughout the core crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the core protocol, codec, crypto and FEC layers.
#[derive(Debug, Error)]
pub enum Error {
    #[error("dns codec error: {0}")]
    Dns(String),

    #[error("base32 decode error: {0}")]
    Base32(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("fec error: {0}")]
    Fec(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("payload too large: {got} bytes, limit {limit}")]
    TooLarge { got: usize, limit: usize },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
