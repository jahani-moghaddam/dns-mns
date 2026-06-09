#!/usr/bin/env bash
# =============================================================================
# PersianUltraDNS — server installer for Linux (Debian/Ubuntu)
#
# Installs prerequisites (git, build tools, Rust), builds pud-server, frees
# UDP/53, generates the pre-shared key, writes the config, installs a systemd
# service, and prints the key for the client.
#
# Usage:  sudo bash install_server.sh
# =============================================================================
set -euo pipefail

# --- Settings (override via environment) -------------------------------------
REPO_URL="${REPO_URL:-https://github.com/jahani-moghaddam/dns-mns.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/persianultradns}"
SERVICE_NAME="${SERVICE_NAME:-pud-server}"
BIND_ADDR="${BIND_ADDR:-0.0.0.0:53}"
MAX_RESPONSE="${MAX_RESPONSE:-1232}"

# --- Pretty output -----------------------------------------------------------
c_green=$'\033[0;32m'; c_red=$'\033[0;31m'; c_yellow=$'\033[1;33m'
c_cyan=$'\033[0;36m';  c_reset=$'\033[0m'
info()  { echo "${c_cyan}[*]${c_reset} $*"; }
ok()    { echo "${c_green}[+]${c_reset} $*"; }
warn()  { echo "${c_yellow}[!]${c_reset} $*"; }
die()   { echo "${c_red}[x]${c_reset} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Please run as root (sudo bash install_server.sh)."

# --- Collect the tunnel domain(s) --------------------------------------------
# Guard: if stdin is not a terminal (piped from curl), print instructions and exit.
if [ ! -t 0 ]; then
  echo
  echo "ERROR: This script must be run directly, not piped from curl."
  echo
  echo "  Please download it first, then run it:"
  echo "    curl -fsSL https://raw.githubusercontent.com/jahani-moghaddam/dns-mns/master/install_server.sh -o install_server.sh"
  echo "    sudo bash install_server.sh"
  echo
  exit 1
fi

echo
echo "Enter your delegated tunnel domain(s)."
echo "  - One or more, comma- or space-separated (e.g. v.example.com, v2.example.net)."
echo "  - Each must have an NS record delegating it to this server's A record."
read -r -p "Domain(s): " DOMAIN_INPUT
[ -n "${DOMAIN_INPUT// /}" ] || die "At least one domain is required."

# Normalise into a TOML array: ["a", "b"]  — pure bash, no xargs
DOMAINS_TOML="["
first=1
for d in $(echo "$DOMAIN_INPUT" | tr ',' ' '); do
  d="${d#"${d%%[![:space:]]*}"}"; d="${d%"${d##*[![:space:]]}"}"  # trim whitespace
  [ -z "$d" ] && continue
  if [ $first -eq 1 ]; then first=0; else DOMAINS_TOML+=", "; fi
  DOMAINS_TOML+="\"$d\""
done
DOMAINS_TOML+="]"
ok "Using domains: $DOMAINS_TOML"

# --- Install prerequisites ---------------------------------------------------
info "Updating apt and installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git curl build-essential pkg-config ca-certificates openssl iproute2

# Rust (rustup) — install for root if cargo is missing.
if ! command -v cargo >/dev/null 2>&1; then
  info "Rust not found; installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
command -v cargo >/dev/null 2>&1 || die "cargo still not on PATH; open a new shell and re-run."
ok "Rust toolchain ready: $(cargo --version)"

# --- Fetch the source --------------------------------------------------------
# If the script is run from inside the repo, build here; otherwise clone.
if [ -f "Cargo.toml" ] && grep -q "pud-server" Cargo.toml 2>/dev/null; then
  SRC_DIR="$(pwd)"
  info "Building from current directory: $SRC_DIR"
elif [ -d "$INSTALL_DIR/.git" ]; then
  SRC_DIR="$INSTALL_DIR"
  info "Updating existing checkout in $INSTALL_DIR..."
  git -C "$INSTALL_DIR" pull --ff-only || warn "git pull failed; building existing checkout."
else
  info "Cloning $REPO_URL into $INSTALL_DIR..."
  mkdir -p "$INSTALL_DIR"
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  SRC_DIR="$INSTALL_DIR"
fi

# Some repos nest the workspace one level down; locate the pud-server crate.
if [ ! -f "$SRC_DIR/Cargo.toml" ] || ! grep -q "pud-server" "$SRC_DIR/Cargo.toml" 2>/dev/null; then
  found="$(find "$SRC_DIR" -maxdepth 3 -name Cargo.toml -exec grep -l 'pud-server' {} \; 2>/dev/null | head -n1 || true)"
  [ -n "$found" ] && SRC_DIR="$(dirname "$found")"
fi
ok "Workspace: $SRC_DIR"

# --- Build -------------------------------------------------------------------
info "Building pud-server (release)... this can take a few minutes."
( cd "$SRC_DIR" && cargo build --release -p pud-server )
BIN="$SRC_DIR/target/release/pud-server"
[ -x "$BIN" ] || die "Build did not produce $BIN"
ok "Built: $BIN"

# --- Free UDP/53 -------------------------------------------------------------
info "Checking that UDP/53 is free..."
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  warn "systemd-resolved is using :53; disabling its stub listener."
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/persianultradns.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
  # Keep working DNS for the host while resolved no longer owns :53.
  if [ -L /etc/resolv.conf ] || ! grep -q '^nameserver' /etc/resolv.conf 2>/dev/null; then
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
  fi
  systemctl restart systemd-resolved || warn "could not restart systemd-resolved"
  sleep 1
fi

# Anything else still on :53?
if ss -lunp 2>/dev/null | grep -q ':53 '; then
  warn "Something is still listening on UDP/53:"
  ss -lunp | grep ':53 ' || true
  warn "Stop the conflicting service, then re-run, or the server bind will fail."
fi

# --- Generate the pre-shared key + config ------------------------------------
KEY_FILE="$INSTALL_DIR/pud_key.hex"
CONF_FILE="$INSTALL_DIR/server_config.toml"
mkdir -p "$INSTALL_DIR"

if [ -f "$KEY_FILE" ]; then
  warn "Existing key found at $KEY_FILE; keeping it."
else
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "$KEY_FILE"
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$KEY_FILE"
  fi
  chmod 600 "$KEY_FILE"
fi
KEY_HEX="$(cat "$KEY_FILE")"

cat > "$CONF_FILE" <<EOF
# PersianUltraDNS server config (generated by install_server.sh)
bind = "$BIND_ADDR"
domain = "$(echo "$DOMAIN_INPUT" | tr ',' ' ' | awk '{print $1}')"
domains = $DOMAINS_TOML
key_file = "$KEY_FILE"
max_response = $MAX_RESPONSE
data_shards = 8
min_parity = 1
max_parity = 16
session_timeout_secs = 120
connect_timeout_secs = 10
log_level = "info"
EOF
ok "Wrote config: $CONF_FILE"

# --- systemd service ---------------------------------------------------------
info "Installing systemd service '$SERVICE_NAME'..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=PersianUltraDNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN --config $CONF_FILE
Restart=on-failure
RestartSec=3
# Allow binding the privileged port 53 without full root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME"
sleep 2

# --- Verify + report ---------------------------------------------------------
echo
if systemctl is-active --quiet "$SERVICE_NAME" && ss -lunp 2>/dev/null | grep -q ':53 '; then
  ok "PersianUltraDNS server is running and listening on UDP/53."
  SETUP_OK=1
else
  warn "Service did not come up cleanly. Recent logs:"
  journalctl -u "$SERVICE_NAME" -n 20 --no-pager || true
  SETUP_OK=0
fi

echo
echo "============================================================"
if [ "${SETUP_OK:-0}" -eq 1 ]; then
  echo "${c_green}  SETUP SUCCESSFUL${c_reset}"
else
  echo "${c_red}  SETUP INCOMPLETE — see logs above${c_reset}"
fi
echo "============================================================"
echo "  Domains   : $DOMAINS_TOML"
echo "  Config    : $CONF_FILE"
echo "  Service   : systemctl status $SERVICE_NAME"
echo
echo "  ${c_yellow}PRE-SHARED KEY (give this to the client):${c_reset}"
echo "  ${c_cyan}$KEY_HEX${c_reset}"
echo
echo "  Reminder — DNS records required:"
echo "    A   ns.<domain>   -> <this server's public IP>   (DNS only / not proxied)"
echo "    NS  <tunnel sub>  -> ns.<domain>"
echo
echo "  Firewall: allow inbound UDP/53 (e.g. 'ufw allow 53/udp')."
echo "============================================================"
