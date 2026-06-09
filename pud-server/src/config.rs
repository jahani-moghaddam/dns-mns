//! Server configuration (TOML) and pre-shared key handling.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// On-disk server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP address to bind the authoritative DNS listener on (usually 0.0.0.0:53).
    pub bind: String,
    /// The delegated tunnel domain, e.g. "t.example.com".
    pub domain: String,
    /// Optional list of delegated tunnel domains this server answers for (all
    /// delegated to this server). When non-empty this supersedes `domain` and
    /// lets clients rotate domains for censorship resistance.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Path to the pre-shared key file (hex). Generated on first run if missing.
    pub key_file: String,
    /// Maximum DNS response size to emit (EDNS UDP budget). 1232 is the safe
    /// no-fragmentation value; raise only if your path tolerates it.
    pub max_response: u16,
    /// Number of data shards per downlink FEC block.
    pub data_shards: u16,
    /// Minimum parity shards per block (covers sporadic loss even on clean links).
    pub min_parity: u16,
    /// Maximum parity shards per block.
    pub max_parity: u16,
    /// Idle session timeout in seconds.
    pub session_timeout_secs: u64,
    /// Connect timeout to upstream targets, in seconds.
    pub connect_timeout_secs: u64,
    /// Log level: error, warn, info, debug, trace.
    pub log_level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind: "0.0.0.0:53".to_string(),
            domain: "t.example.com".to_string(),
            domains: Vec::new(),
            key_file: "pud_key.hex".to_string(),
            max_response: 1232,
            data_shards: 8,
            min_parity: 1,
            max_parity: 16,
            session_timeout_secs: 120,
            connect_timeout_secs: 10,
            log_level: "info".to_string(),
        }
    }
}

impl ServerConfig {
    /// The effective list of tunnel domains this server answers for.
    pub fn effective_domains(&self) -> Vec<String> {
        if self.domains.is_empty() {
            vec![self.domain.clone()]
        } else {
            self.domains.clone()
        }
    }

    pub fn load(path: &str) -> Result<ServerConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading server config {path}"))?;
        let cfg: ServerConfig =
            toml::from_str(&text).with_context(|| format!("parsing server config {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.domain.is_empty(), "domain must not be empty");
        anyhow::ensure!(self.data_shards >= 1, "data_shards must be >= 1");
        anyhow::ensure!(self.data_shards <= 255, "data_shards must be <= 255");
        anyhow::ensure!(self.max_parity <= 255, "max_parity must be <= 255");
        anyhow::ensure!(
            self.max_parity >= self.min_parity,
            "max_parity must be >= min_parity"
        );
        anyhow::ensure!(self.max_response >= 512, "max_response must be >= 512");
        Ok(())
    }

    /// Write a default config template to `path`.
    pub fn write_template(path: &str) -> Result<()> {
        let cfg = ServerConfig::default();
        let text = toml::to_string_pretty(&cfg)?;
        std::fs::write(path, text).with_context(|| format!("writing template {path}"))?;
        Ok(())
    }
}

/// Load the pre-shared key from `path`, generating a fresh random one if the
/// file does not exist. The key is stored as lowercase hex.
pub fn load_or_create_key(path: &str) -> Result<Vec<u8>> {
    if Path::new(path).exists() {
        let hex = std::fs::read_to_string(path)
            .with_context(|| format!("reading key file {path}"))?;
        let key = decode_hex(hex.trim()).context("decoding key hex")?;
        anyhow::ensure!(key.len() >= 16, "key must be at least 16 bytes");
        Ok(key)
    } else {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        std::fs::write(path, encode_hex(&key))
            .with_context(|| format!("writing key file {path}"))?;
        Ok(key)
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    anyhow::ensure!(s.len() % 2 == 0, "hex string has odd length");
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid hex character: 0x{c:02x}"),
    }
}
