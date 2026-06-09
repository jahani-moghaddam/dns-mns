<div align="center">

# 🌐 PersianUltraDNS

### The ultimate censorship-resilient DNS tunnel — built for the harshest networks on Earth

**When the internet goes dark, PersianUltraDNS stays lit.** 🔥

| [🇬🇧 English](#-english) | [🇮🇷 نسخه فارسی](#-نسخه-فارسی) |
| :---: | :---: |

*Forward-secret. FEC-powered. Multipath. Self-healing. Blazing fast.*

</div>

---

## 🇬🇧 English

### What is PersianUltraDNS?

PersianUltraDNS is a **next-generation DNS tunnel** that smuggles your TCP traffic inside ordinary-looking DNS queries — so it slips through firewalls that block everything else. It was engineered from the ground up for one mission: **keep people connected to the free internet even during a total shutdown.**

Where classic tunnels stumble on packet loss, high latency, and aggressive DPI, PersianUltraDNS thrives. It combines a **forward-secret cryptographic core**, **forward-error-correction**, **adaptive multipath routing**, and **self-healing sessions** into a single, ruthless, no-compromise package.

> 💡 If DNS resolves on your network — and it almost always does — PersianUltraDNS can get you out.

---

### ✨ Why it's a game-changer

- 🛡️ **Forward-secret by design.** Every session gets fresh ephemeral X25519 keys. Steal the password tomorrow? You *still* can't decrypt what was captured today. This is security that even mature rivals don't offer.
- ⚡ **FEC instead of waiting.** Reed–Solomon forward error correction reconstructs lost data *without a single retransmission round-trip* — the killer feature on a high-latency, lossy path during a shutdown.
- 🧠 **Adaptive everything.** The congestion window, the per-resolver MTU, the FEC parity, and the retransmit timers all **tune themselves in real time** to the network you're actually on.
- 📡 **Massively multipath.** Spreads traffic across dozens of resolvers (entire CIDR ranges supported), races stalled queries, and routes around dead paths automatically.
- 🔁 **Self-healing.** If the session dies, it detects the stall, rotates to a fresh session, re-handshakes, and recovers — all on its own.
- 🌍 **Multi-domain rotation.** Blacklist one tunnel domain? It just rotates to the next. Good luck blocking them all.
- 🔌 **Plug-and-play proxies.** Exposes **both SOCKS5 and HTTP** locally — point any browser or app at it and go.
- 🦀 **Built in Rust.** Memory-safe, blisteringly fast, and tiny on the wire (just ~16 bytes of framing overhead per message).

---

### 📊 How it stacks up

| Capability | Classic DNSTT | PersianUltraDNS |
| :--- | :---: | :---: |
| Forward secrecy | ❌ | ✅ **Yes** |
| Loss recovery without round-trips (FEC) | ❌ | ✅ **Yes** |
| Adaptive congestion window | ❌ | ✅ **Yes** |
| Per-resolver MTU discovery | ❌ | ✅ **Yes** |
| Multipath + CIDR resolver expansion | ❌ | ✅ **Yes** |
| Automatic reconnect / self-heal | ❌ | ✅ **Yes** |
| Multi-domain rotation | ❌ | ✅ **Yes** |
| SOCKS5 **and** HTTP proxy | ⚠️ partial | ✅ **Both** |

> ⚠️ **Honest note:** PersianUltraDNS is a young, ambitious project. Its *engine* is arguably best-in-class, but it has not yet seen the years of real-world battle-testing that some older tools have. Treat it as a powerful research-grade tool — and help us harden it.


---

### 🚀 Quick start

#### 1. DNS setup (one time)

Delegate a subdomain to your VPS with two records at your DNS provider:

```
A    ns.example.com   ->  <your VPS public IP>     (DNS only — not proxied)
NS   v.example.com    ->  ns.example.com
```

Now every query for `*.v.example.com` reaches your server. (Tip: keep the domain short — more room for data.)

#### 2. Server (on your Linux VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/jahani-moghaddam/dns-mns/master/install_server.sh -o install_server.sh
sudo bash install_server.sh
```

The installer updates the system, installs Rust if needed, builds the server, frees UDP/53, generates your pre-shared key, installs a systemd service, and **prints the key**. Allow UDP/53 through the firewall:

```bash
sudo ufw allow 53/udp
```

#### 3. Client (on your machine)

```bash
curl -fsSL https://raw.githubusercontent.com/jahani-moghaddam/dns-mns/master/build_client.sh -o build_client.sh
bash build_client.sh
```

Or clone and run:

```bash
git clone https://github.com/jahani-moghaddam/dns-mns.git
cd dns-mns
bash build_client.sh
```

```bash
./target/release/pud-client --config client_config.toml
```

#### 4. Point your apps at it

- **SOCKS5:** `127.0.0.1:18080` (in `proxychains`: `socks5h://127.0.0.1:18080`)
- **HTTP proxy:** `127.0.0.1:18081`

> In your browser, enable **"Proxy DNS when using SOCKS"** to avoid DNS leaks.

---

### ⚙️ Configuration highlights

**Client** (`client_config.toml`):

```toml
domains = ["v.example.com", "v2.example.net"]   # rotate across these
key_hex = "....."                               # from the server
resolvers = ["8.8.8.8", "1.1.1.1", "10.0.0.0/24"]  # IPs and CIDR ranges
socks_listen = "127.0.0.1:18080"
http_listen  = "127.0.0.1:18081"
```

**Server** (`server_config.toml`):

```toml
domains = ["v.example.com", "v2.example.net"]
max_response = 1232   # raise it (e.g. 4096) for more speed if your path allows
```

> 🔑 **Keep `pud_key.hex` secret.** Anyone with it can use your server.

---

### 🔒 Security model (straight talk)

- **Authenticated encryption:** ChaCha20-Poly1305 on every frame, header bound as associated data, with anti-replay protection.
- **Forward secrecy + mutual auth:** an X25519 handshake bound to your pre-shared key — a passive recorder can't decrypt later, and an active attacker without the key can't impersonate either side.
- **Local proxies have no auth** and bind to `127.0.0.1` by design. Do **not** expose them on `0.0.0.0` without adding your own access control.

---

### ⚡ Built for speed

DNS tunnels are famously slow — **PersianUltraDNS rewrites that rule.** Thanks to FEC (no waiting on retransmissions), an adaptive congestion window that keeps the pipe full, per-resolver MTU discovery, and aggressive multipath, it's engineered to leave classic tunnels in the dust.

- 🏎️ **Designed to reach up to ~5 Mbps** download on a healthy multi-resolver path — *several times faster* than classic DNSTT.
- 🌩️ **Stays usable on the worst paths** — keeps flowing at tens of KB/s through heavy packet loss and high latency where other tunnels stall completely.
- 🪶 **Featherweight on the wire** — only ~16 bytes of framing overhead per message, so more of every DNS packet carries *your* data.

> 📈 *These are engineering design targets, not a lab certificate.* Real-world speed depends on your resolvers, your server's `max_response` setting, and the network between you and freedom. Your mileage will vary — usually pleasantly.

---

### ⚠️ Disclaimer

PersianUltraDNS is provided for **educational and research purposes**, "AS-IS", without warranty of any kind. You are solely responsible for how you use it and for complying with the laws of your jurisdiction. The authors accept no liability for any damage or legal consequence arising from its use.

