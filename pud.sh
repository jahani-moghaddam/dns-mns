#!/usr/bin/env bash
# =============================================================================
# pud — PersianUltraDNS management menu
#
# Install:  sudo cp pud.sh /usr/local/bin/pud && chmod +x /usr/local/bin/pud
# Usage:    pud
# =============================================================================

# --- Paths (must match install_server.sh) ------------------------------------
INSTALL_DIR="/opt/persianultradns"
SERVICE_NAME="pud-server"
CONF_FILE="$INSTALL_DIR/server_config.toml"
KEY_FILE="$INSTALL_DIR/pud_key.hex"
REPO_URL="https://github.com/jahani-moghaddam/dns-mns.git"
BIN="$INSTALL_DIR/target/release/pud-server"

# --- Colours -----------------------------------------------------------------
R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[1;33m'
C=$'\033[0;36m'; B=$'\033[1;34m'; W=$'\033[1;37m'; X=$'\033[0m'

# --- Helpers -----------------------------------------------------------------
requires_root() {
    [ "$(id -u)" -eq 0 ] || { echo "${R}[x]${X} Run as root: sudo pud"; exit 1; }
}

service_status() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo "${G}● running${X}"
    else
        echo "${R}● stopped${X}"
    fi
}

press_enter() {
    echo; read -r -p "  Press Enter to return to menu..." _
}

# --- Banner ------------------------------------------------------------------
show_banner() {
    clear
    echo
    echo "${C}  ██████╗ ██╗   ██╗██████╗ ${X}"
    echo "${C}  ██╔══██╗██║   ██║██╔══██╗${X}"
    echo "${C}  ██████╔╝██║   ██║██║  ██║${X}"
    echo "${C}  ██╔═══╝ ██║   ██║██║  ██║${X}"
    echo "${C}  ██║     ╚██████╔╝██████╔╝${X}"
    echo "${C}  ╚═╝      ╚═════╝ ╚═════╝ ${X}"
    echo
    echo "  ${W}PersianUltraDNS — Management Console${X}"
    echo "  ─────────────────────────────────────"
    echo "  Service : $(service_status)"
    echo "  Config  : $CONF_FILE"
    echo "  ─────────────────────────────────────"
    echo
}

# --- Menu actions ------------------------------------------------------------

do_status() {
    echo
    echo "${W}── Service status ──────────────────────────────${X}"
    systemctl status "$SERVICE_NAME" --no-pager -l 2>/dev/null || echo "${R}Service not found.${X}"
    echo
    echo "${W}── Recent logs (last 30 lines) ─────────────────${X}"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager 2>/dev/null || true
    press_enter
}

do_show_key() {
    echo
    if [ -f "$KEY_FILE" ]; then
        KEY="$(cat "$KEY_FILE")"
        echo "${W}── Pre-shared key ──────────────────────────────${X}"
        echo
        echo "  ${Y}$KEY${X}"
        echo
        echo "  Copy this into your client_config.toml:"
        echo "  ${C}key_hex = \"$KEY\"${X}"
    else
        echo "${R}Key file not found: $KEY_FILE${X}"
        echo "Run the installer first."
    fi
    press_enter
}

do_start() {
    requires_root
    echo; echo "${C}[*]${X} Starting $SERVICE_NAME..."
    systemctl start "$SERVICE_NAME" && echo "${G}[+]${X} Started." || echo "${R}[x]${X} Failed."
    press_enter
}

do_stop() {
    requires_root
    echo; echo "${Y}[!]${X} Stopping $SERVICE_NAME..."
    systemctl stop "$SERVICE_NAME" && echo "${G}[+]${X} Stopped." || echo "${R}[x]${X} Failed."
    press_enter
}

do_restart() {
    requires_root
    echo; echo "${C}[*]${X} Restarting $SERVICE_NAME..."
    systemctl restart "$SERVICE_NAME" && echo "${G}[+]${X} Restarted." || echo "${R}[x]${X} Failed."
    press_enter
}

do_update() {
    requires_root
    echo
    echo "${W}── Update PersianUltraDNS ──────────────────────${X}"
    echo

    # Locate the source directory (cloned repo)
    if [ -d "$INSTALL_DIR/.git" ]; then
        SRC_DIR="$INSTALL_DIR"
    else
        # Find nested workspace
        SRC_DIR="$(find "$INSTALL_DIR" -maxdepth 3 -name Cargo.toml -exec grep -l 'pud-server' {} \; 2>/dev/null | head -n1 | xargs -r dirname)"
    fi

    if [ -z "$SRC_DIR" ] || [ ! -d "$SRC_DIR" ]; then
        echo "${R}[x]${X} Source directory not found under $INSTALL_DIR."
        echo "    Please re-run install_server.sh to set up from scratch."
        press_enter; return
    fi

    echo "${C}[*]${X} Pulling latest code from $REPO_URL ..."
    if git -C "$SRC_DIR" pull --ff-only; then
        echo "${G}[+]${X} Source updated."
    else
        echo "${Y}[!]${X} git pull failed — building existing checkout."
    fi

    # Make sure cargo is on PATH (rustup installs to ~/.cargo/bin)
    [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
    command -v cargo >/dev/null 2>&1 || { echo "${R}[x]${X} cargo not found. Is Rust installed?"; press_enter; return; }

    echo "${C}[*]${X} Building pud-server (release)..."
    if ( cd "$SRC_DIR" && cargo build --release -p pud-server ); then
        echo "${G}[+]${X} Build complete."
        echo "${C}[*]${X} Restarting service..."
        systemctl restart "$SERVICE_NAME" && echo "${G}[+]${X} Service restarted with new binary." || echo "${R}[x]${X} Restart failed."
    else
        echo "${R}[x]${X} Build failed — old binary still running."
    fi
    press_enter
}

do_uninstall() {
    requires_root
    echo
    echo "${R}── Uninstall PersianUltraDNS ───────────────────${X}"
    echo
    echo "  This will:"
    echo "    • Stop and disable the systemd service"
    echo "    • Remove /etc/systemd/system/${SERVICE_NAME}.service"
    echo "    • Remove $INSTALL_DIR  (including your key!)"
    echo "    • Remove /usr/local/bin/pud"
    echo
    read -r -p "  ${R}Are you sure? Type YES to confirm:${X} " confirm
    if [ "$confirm" != "YES" ]; then
        echo "  Cancelled."; press_enter; return
    fi

    systemctl stop "$SERVICE_NAME"    2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload           2>/dev/null || true

    # Remove resolved stub override if we added it
    rm -f /etc/systemd/resolved.conf.d/persianultradns.conf
    systemctl restart systemd-resolved 2>/dev/null || true

    rm -rf "$INSTALL_DIR"
    rm -f /usr/local/bin/pud

    echo
    echo "${G}[+]${X} PersianUltraDNS has been removed."
    echo "    Your DNS records (A / NS) at your registrar still need manual removal."
    echo
    exit 0
}

# --- Main menu loop ----------------------------------------------------------
while true; do
    show_banner
    echo "  ${W}1)${X} Status & recent logs"
    echo "  ${W}2)${X} Show pre-shared key"
    echo "  ${W}3)${X} Start service"
    echo "  ${W}4)${X} Stop service"
    echo "  ${W}5)${X} Restart service"
    echo "  ${W}6)${X} Update  (git pull + rebuild + restart)"
    echo "  ${W}7)${X} Uninstall"
    echo "  ${W}0)${X} Exit"
    echo
    read -r -p "  Select option: " choice
    case "$choice" in
        1) do_status    ;;
        2) do_show_key  ;;
        3) do_start     ;;
        4) do_stop      ;;
        5) do_restart   ;;
        6) do_update    ;;
        7) do_uninstall ;;
        0) echo; echo "  Bye."; echo; exit 0 ;;
        *) echo "${Y}  Invalid option.${X}"; sleep 1 ;;
    esac
done
