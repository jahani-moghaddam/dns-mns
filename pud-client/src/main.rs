//! PersianUltraDNS client — local SOCKS5 proxy + multipath DNS tunnel + cache.

mod config;
mod engine;
mod http_proxy;
mod hexutil;
mod localdns;
mod resolver;
mod socks;
mod transport;

use crate::config::ClientConfig;
use crate::engine::Engine;
use anyhow::{Context, Result};
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pud-client", version, about = "PersianUltraDNS client")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "client_config.toml")]
    config: String,
    /// Write a default configuration template to the config path and exit.
    #[arg(long)]
    init: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.init {
        ClientConfig::write_template(&cli.config)?;
        println!("Wrote default client config to {}", cli.config);
        return Ok(());
    }

    let cfg = ClientConfig::load(&cli.config)
        .with_context(|| format!("loading config (try --init to create {})", cli.config))?;

    init_tracing(&cfg.log_level);

    let key = cfg.key_bytes().context("decoding key_hex")?;
    let resolvers = cfg.resolver_addrs()?;
    let domains = cfg.effective_domains();
    tracing::info!(
        "PersianUltraDNS client v{} starting; domains={:?} resolvers={} in_flight={}",
        env!("CARGO_PKG_VERSION"),
        domains,
        resolvers.len(),
        cfg.in_flight
    );

    let engine = Engine::new(&key, domains, &cfg);
    tracing::debug!("session id = 0x{:08x}", engine.session_id());

    // Drive the multipath query pump.
    {
        let engine = engine.clone();
        let resolvers = resolvers.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            engine.run(resolvers, cfg).await;
        });
    }

    // Optional local caching DNS resolver.
    if cfg.local_dns.enabled {
        let engine = engine.clone();
        let dns_cfg = cfg.local_dns.clone();
        tokio::spawn(async move {
            if let Err(e) = localdns::serve(dns_cfg, engine).await {
                tracing::error!("local DNS resolver stopped: {e}");
            }
        });
    }

    let open_timeout = Duration::from_secs(15);

    // Optional local HTTP CONNECT proxy.
    if !cfg.http_listen.is_empty() {
        let engine = engine.clone();
        let listen = cfg.http_listen.clone();
        tokio::spawn(async move {
            if let Err(e) = http_proxy::serve(&listen, engine, open_timeout).await {
                tracing::error!("HTTP proxy stopped: {e}");
            }
        });
    }

    // Run the SOCKS server in the foreground; Ctrl-C ends the process.
    tokio::select! {
        res = socks::serve(&cfg.socks_listen, engine.clone(), open_timeout) => {
            if let Err(e) = res {
                tracing::error!("SOCKS server stopped: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    Ok(())
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "pud_client={level},pud_core={level}"
        ))
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
