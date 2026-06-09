//! Client configuration (TOML) and resolver list loading.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

/// Largest number of hosts a single CIDR entry may expand to (guards against an
/// accidental /8 producing millions of resolvers).
const MAX_CIDR_HOSTS: u32 = 4096;

/// On-disk client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Local SOCKS5 listen address, e.g. "127.0.0.1:18080".
    pub socks_listen: String,
    /// Optional local HTTP CONNECT proxy listen address (empty = disabled),
    /// e.g. "127.0.0.1:18081". Exposes the tunnel to apps that speak an HTTP
    /// proxy rather than SOCKS5.
    #[serde(default)]
    pub http_listen: String,
    /// The delegated tunnel domain, must match the server's `domain`.
    pub domain: String,
    /// Optional list of tunnel domains to rotate across (all must delegate to
    /// the same server). When non-empty this supersedes `domain`; rotating
    /// domains survives the censor blacklisting any single one.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Pre-shared key as lowercase hex (copy from the server's startup log).
    pub key_hex: String,
    /// Resolvers to send tunnel queries through. Accepts "IP" or "IP:port".
    /// If empty, `resolvers_file` is consulted.
    #[serde(default)]
    pub resolvers: Vec<String>,
    /// Optional path to a newline-separated resolver list.
    #[serde(default)]
    pub resolvers_file: String,
    /// EDNS UDP response size to advertise/accept (1232 is fragmentation-safe).
    pub max_response: u16,
    /// Number of concurrent in-flight DNS queries (multipath pipelining depth).
    /// Used as the initial/maximum congestion window unless `window` overrides.
    pub in_flight: usize,
    /// Adaptive concurrency-window settings.
    #[serde(default)]
    pub window: WindowConfig,
    /// Resolver selection and racing settings.
    #[serde(default)]
    pub resolvers_policy: ResolverPolicy,
    /// Idle polling interval in milliseconds when there is no active traffic.
    pub idle_poll_ms: u64,
    /// Per-query response timeout in milliseconds.
    pub query_timeout_ms: u64,
    /// Maximum uplink data bytes to attach per query (bounded by name budget).
    pub max_uplink_chunk: usize,
    /// Local DNS cache settings.
    #[serde(default)]
    pub local_dns: LocalDnsConfig,
    /// Adaptive downlink MTU discovery settings.
    #[serde(default)]
    pub probe: ProbeConfig,
    /// Log level: error, warn, info, debug, trace.
    pub log_level: String,
}

/// Adaptive path-MTU discovery for the downlink (server -> client) response
/// size. The client grows the EDNS response size it advertises and verifies
/// each larger size with an echo probe; a confirmed size lets the server pack
/// more FEC shards per answer, raising throughput. Discovery is always bounded
/// by the server's own `max_response`, so this can never exceed what the server
/// allows and falls back cleanly when a size does not traverse the path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Enable adaptive downlink MTU discovery.
    pub enabled: bool,
    /// Largest response size (bytes) the client will try to grow toward. The
    /// effective ceiling is also capped by the server's `max_response`.
    pub max_response_ceiling: u16,
    /// Bytes to grow the response size by per successful probe.
    pub step: u16,
    /// Seconds between probe attempts.
    pub interval_secs: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            enabled: true,
            max_response_ceiling: 4096,
            step: 256,
            interval_secs: 10,
        }
    }
}

/// Adaptive concurrency window (congestion control over in-flight queries).
///
/// Downlink throughput scales with the number of simultaneously in-flight
/// queries (each query is one response slot the server can push into). The
/// engine grows the window while deliveries succeed and backs off on loss
/// (AIMD with slow start), keeping the pipe full without inducing congestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    /// Enable the adaptive window. When false, a fixed window of `in_flight`
    /// queries is used.
    pub adaptive: bool,
    /// Smallest the window may shrink to.
    pub min: usize,
    /// Largest the window may grow to.
    pub max: usize,
    /// Per-resolver adaptive retransmit-timeout floor, milliseconds.
    pub rto_min_ms: u64,
    /// Per-resolver adaptive retransmit-timeout ceiling, milliseconds.
    pub rto_max_ms: u64,
}

impl Default for WindowConfig {
    fn default() -> Self {
        WindowConfig {
            adaptive: true,
            min: 2,
            max: 32,
            rto_min_ms: 300,
            rto_max_ms: 4000,
        }
    }
}

/// Resolver selection strategy and stall-racing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverPolicy {
    /// Selection strategy: "weighted" (favor low-RTT resolvers) or "roundrobin".
    pub strategy: String,
    /// When a query stalls past an RTT-derived threshold, send a duplicate to a
    /// second resolver and take the first reply. Duplicates cost extra uplink,
    /// so this only fires on a stall.
    pub race_on_stall: bool,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        ResolverPolicy {
            strategy: "weighted".to_string(),
            race_on_stall: true,
        }
    }
}

/// Optional local caching DNS resolver served to the operating system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDnsConfig {
    /// Enable the local DNS listener.
    pub enabled: bool,
    /// UDP address to listen on, e.g. "127.0.0.1:5300".
    pub listen: String,
    /// Upstream DNS server (reached over the tunnel via TCP), e.g. "1.1.1.1:53".
    pub upstream: String,
    /// Maximum cached records.
    pub cache_capacity: usize,
    /// Cap on cache TTL in seconds (answers with longer TTLs are clamped).
    pub max_ttl_secs: u32,
}

impl Default for LocalDnsConfig {
    fn default() -> Self {
        LocalDnsConfig {
            enabled: false,
            listen: "127.0.0.1:5300".to_string(),
            upstream: "1.1.1.1:53".to_string(),
            cache_capacity: 4096,
            max_ttl_secs: 3600,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            socks_listen: "127.0.0.1:18080".to_string(),
            http_listen: "127.0.0.1:18081".to_string(),
            domain: "t.example.com".to_string(),
            domains: Vec::new(),
            key_hex: "".to_string(),
            resolvers: vec![
                "8.8.8.8:53".to_string(),
                "1.1.1.1:53".to_string(),
                "9.9.9.9:53".to_string(),
            ],
            resolvers_file: "".to_string(),
            max_response: 1232,
            in_flight: 8,
            window: WindowConfig::default(),
            resolvers_policy: ResolverPolicy::default(),
            idle_poll_ms: 60,
            query_timeout_ms: 4000,
            max_uplink_chunk: 1024,
            local_dns: LocalDnsConfig::default(),
            probe: ProbeConfig::default(),
            log_level: "info".to_string(),
        }
    }
}

impl ClientConfig {
    pub fn load(path: &str) -> Result<ClientConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading client config {path}"))?;
        let cfg: ClientConfig =
            toml::from_str(&text).with_context(|| format!("parsing client config {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.domain.is_empty(), "domain must not be empty");
        anyhow::ensure!(!self.key_hex.is_empty(), "key_hex must be set");
        anyhow::ensure!(self.in_flight >= 1, "in_flight must be >= 1");
        anyhow::ensure!(self.max_response >= 512, "max_response must be >= 512");
        anyhow::ensure!(self.window.min >= 1, "window.min must be >= 1");
        anyhow::ensure!(
            self.window.max >= self.window.min,
            "window.max must be >= window.min"
        );
        anyhow::ensure!(
            self.window.rto_max_ms >= self.window.rto_min_ms && self.window.rto_min_ms >= 1,
            "window.rto_max_ms must be >= rto_min_ms >= 1"
        );
        Ok(())
    }

    pub fn write_template(path: &str) -> Result<()> {
        let cfg = ClientConfig::default();
        let text = toml::to_string_pretty(&cfg)?;
        std::fs::write(path, text).with_context(|| format!("writing template {path}"))?;
        Ok(())
    }

    /// Resolve the effective resolver address list from inline entries and/or
    /// the resolver file. Supports IP, IP:port, IPv4 CIDR, and CIDR:port.
    pub fn resolver_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut raw: Vec<String> = self.resolvers.clone();
        if !self.resolvers_file.is_empty() {
            if let Ok(text) = std::fs::read_to_string(&self.resolvers_file) {
                for line in text.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        raw.push(line.to_string());
                    }
                }
            }
        }
        let mut out = Vec::new();
        for entry in raw {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            parse_resolver_entry(entry, &mut out);
        }
        // Deduplicate while preserving order (CIDR ranges can overlap inline IPs).
        let mut seen = std::collections::HashSet::new();
        out.retain(|a| seen.insert(*a));
        anyhow::ensure!(!out.is_empty(), "no valid resolvers configured");
        Ok(out)
    }

    pub fn key_bytes(&self) -> Result<Vec<u8>> {
        crate::hexutil::decode_hex(&self.key_hex)
    }

    /// The effective list of tunnel domains: `domains` if set, else `[domain]`.
    pub fn effective_domains(&self) -> Vec<String> {
        if self.domains.is_empty() {
            vec![self.domain.clone()]
        } else {
            self.domains.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_resolvers(entries: &[&str]) -> ClientConfig {
        let mut c = ClientConfig {
            key_hex: "ab".to_string(),
            ..Default::default()
        };
        c.resolvers = entries.iter().map(|s| s.to_string()).collect();
        c
    }

    #[test]
    fn parses_plain_ip_and_port() {
        let c = cfg_with_resolvers(&["8.8.8.8", "1.1.1.1:5353"]);
        let addrs = c.resolver_addrs().unwrap();
        assert!(addrs.contains(&"8.8.8.8:53".parse().unwrap()));
        assert!(addrs.contains(&"1.1.1.1:5353".parse().unwrap()));
    }

    #[test]
    fn expands_ipv4_cidr() {
        let c = cfg_with_resolvers(&["192.168.1.0/30"]);
        let addrs = c.resolver_addrs().unwrap();
        // /30 -> 4 addresses, all port 53.
        assert_eq!(addrs.len(), 4);
        assert!(addrs.contains(&"192.168.1.0:53".parse().unwrap()));
        assert!(addrs.contains(&"192.168.1.3:53".parse().unwrap()));
    }

    #[test]
    fn expands_cidr_with_port() {
        let c = cfg_with_resolvers(&["10.0.0.0/30:5353"]);
        let addrs = c.resolver_addrs().unwrap();
        assert_eq!(addrs.len(), 4);
        assert!(addrs.iter().all(|a| a.port() == 5353));
    }

    #[test]
    fn caps_huge_cidr() {
        let c = cfg_with_resolvers(&["10.0.0.0/8"]);
        let addrs = c.resolver_addrs().unwrap();
        assert_eq!(addrs.len(), MAX_CIDR_HOSTS as usize);
    }

    #[test]
    fn dedupes_overlapping_entries() {
        let c = cfg_with_resolvers(&["1.2.3.4", "1.2.3.4:53", "1.2.3.0/30"]);
        let addrs = c.resolver_addrs().unwrap();
        // 1.2.3.4 (twice, same) + 1.2.3.0..3 (4) with 1.2.3.4 not in /30 range.
        let count_134 = addrs.iter().filter(|a| a.ip().to_string() == "1.2.3.4").count();
        assert_eq!(count_134, 1);
    }

    #[test]
    fn effective_domains_prefers_list() {
        let mut c = ClientConfig::default();
        c.domain = "single.example".to_string();
        assert_eq!(c.effective_domains(), vec!["single.example".to_string()]);
        c.domains = vec!["a.example".to_string(), "b.example".to_string()];
        assert_eq!(
            c.effective_domains(),
            vec!["a.example".to_string(), "b.example".to_string()]
        );
    }
}

/// Parse one resolver entry into one or more socket addresses. Supports:
/// `IP`, `IP:port`, IPv4 `CIDR`, and IPv4 `CIDR:port`. Bare entries get port 53.
fn parse_resolver_entry(entry: &str, out: &mut Vec<SocketAddr>) {
    // CIDR (IPv4 only): "a.b.c.d/len" optionally followed by ":port".
    if let Some((ip_part, rest)) = entry.split_once('/') {
        let (plen_str, port) = match rest.split_once(':') {
            Some((p, port_str)) => (p, port_str.trim().parse::<u16>().unwrap_or(53)),
            None => (rest, 53u16),
        };
        match (ip_part.trim().parse::<Ipv4Addr>(), plen_str.trim().parse::<u32>()) {
            (Ok(base), Ok(plen)) if plen <= 32 => expand_ipv4_cidr(base, plen, port, out),
            _ => tracing::warn!("ignoring invalid CIDR resolver '{entry}'"),
        }
        return;
    }

    // Single address: "IP" or "IP:port" (IPv4 or IPv6).
    let with_port = if entry.contains(':') && !entry.contains("::") {
        // already has a port (and not a bare IPv6)
        entry.to_string()
    } else if entry.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{entry}]:53")
    } else if entry.contains(':') {
        entry.to_string()
    } else {
        format!("{entry}:53")
    };
    match with_port.parse::<SocketAddr>() {
        Ok(addr) => out.push(addr),
        Err(e) => tracing::warn!("ignoring invalid resolver '{entry}': {e}"),
    }
}

/// Expand an IPv4 CIDR into individual resolver addresses (capped).
fn expand_ipv4_cidr(base: Ipv4Addr, prefix: u32, port: u16, out: &mut Vec<SocketAddr>) {
    let host_bits = 32 - prefix;
    let count = 1u64 << host_bits; // 1..=2^32
    if count > MAX_CIDR_HOSTS as u64 {
        tracing::warn!("CIDR /{prefix} too large ({count} hosts); capping at {MAX_CIDR_HOSTS}");
    }
    let count = count.min(MAX_CIDR_HOSTS as u64) as u32;
    let mask = if host_bits == 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = u32::from(base) & mask;
    for i in 0..count {
        let ip = Ipv4Addr::from(network.wrapping_add(i));
        out.push(SocketAddr::new(ip.into(), port));
    }
}
