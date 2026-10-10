#!/usr/bin/env bash
set -euo pipefail

# ScreenGuard agent installer for macOS (Apple silicon and Intel).
#
# Deliberately separate from install.sh: that script installs the server, web
# UI and tray as well, and every one of its mechanisms (systemd units, D-Bus
# policy, nftables, nsswitch.conf) is Linux-only. This one installs the agent
# and nothing else.

REPO="adambie/screenguard"
RELEASES_URL="https://github.com/${REPO}/releases/latest/download"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/screenguard"
DATA_DIR="/var/lib/screenguard"
LOG_FILE="/var/log/screenguard-agent.log"
PLIST="/Library/LaunchDaemons/org.screenguard.agent.plist"
LABEL="org.screenguard.agent"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; RESET='\033[0m'

info()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $*"; }
error()  { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }
header() { echo -e "\n${BOLD}$*${RESET}"; }

usage() {
    cat <<EOF
Usage: sudo ./install-macos.sh [options]

  --server-url URL        self-hosted server, e.g. ws://192.168.1.10:8765/ws
  --cloud-account EMAIL   use the hosted server at screenguard.cc
  --from PATH             install this locally built binary instead of
                          downloading a release (target/release/agent)
  --uninstall             remove the agent, its config and its data
  -h, --help              show this

Exactly one of --server-url or --cloud-account is required on a first install:
macOS does no mDNS discovery, so the agent has to be told where its server is.
EOF
    exit "${1:-0}"
}

SERVER_URL=""
CLOUD_ACCOUNT=""
FROM_BINARY=""
UNINSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)      SERVER_URL="${2:-}"; shift 2 ;;
        --server-url=*)    SERVER_URL="${1#*=}"; shift ;;
        --cloud-account)   CLOUD_ACCOUNT="${2:-}"; shift 2 ;;
        --cloud-account=*) CLOUD_ACCOUNT="${1#*=}"; shift ;;
        --from)            FROM_BINARY="${2:-}"; shift 2 ;;
        --from=*)          FROM_BINARY="${1#*=}"; shift ;;
        --uninstall)       UNINSTALL=1; shift ;;
        -h|--help)         usage 0 ;;
        *)                 warn "Unknown option: $1"; usage 1 ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || error "This installer is for macOS. On Linux use install.sh."
[[ $EUID -eq 0 ]] || error "Run as root: sudo $0 $*"

# ── uninstall ─────────────────────────────────────────────────────────────────

if [[ $UNINSTALL -eq 1 ]]; then
    header "Uninstalling the ScreenGuard agent"
    if launchctl print "system/${LABEL}" &>/dev/null; then
        launchctl bootout "system/${LABEL}" 2>/dev/null || true
        info "Stopped ${LABEL}"
    fi
    rm -f "$PLIST" && info "Removed $PLIST"
    rm -f "${INSTALL_DIR}/screenguard-agent" && info "Removed the agent binary"
    rm -rf "$CONFIG_DIR" "$DATA_DIR" && info "Removed config and data"
    rm -f /etc/newsyslog.d/screenguard.conf
    warn "Left $LOG_FILE in place; delete it yourself if you want it gone."
    info "Done. This machine will show as offline on the server until you remove it there."
    exit 0
fi

# ── checks ────────────────────────────────────────────────────────────────────

ALREADY_PAIRED=0
[[ -f "${DATA_DIR}/agent.db" ]] && ALREADY_PAIRED=1

if [[ -n "$SERVER_URL" && -n "$CLOUD_ACCOUNT" ]]; then
    error "Pass either --server-url or --cloud-account, not both."
fi
if [[ -z "$SERVER_URL" && -z "$CLOUD_ACCOUNT" && $ALREADY_PAIRED -eq 0 ]]; then
    warn "No server given, and this machine has never been paired."
    usage 1
fi

# Enforcement rests on the managed account not being able to unload a
# LaunchDaemon, which an administrator can.
CONSOLE_USER="$(stat -f %Su /dev/console 2>/dev/null || echo "")"
if [[ -n "$CONSOLE_USER" ]] && dseditgroup -o checkmember -m "$CONSOLE_USER" admin &>/dev/null; then
    warn "The logged-in user '${CONSOLE_USER}' is an administrator and can therefore"
    warn "stop the agent at will. Make the managed account a Standard user in"
    warn "System Settings → Users & Groups before relying on enforcement."
fi

# ── binary ────────────────────────────────────────────────────────────────────

header "Installing the agent binary"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"

if [[ -n "$FROM_BINARY" ]]; then
    [[ -f "$FROM_BINARY" ]] || error "No such file: $FROM_BINARY"
    install -m 755 "$FROM_BINARY" "${INSTALL_DIR}/screenguard-agent"
    info "Installed ${FROM_BINARY} → ${INSTALL_DIR}/screenguard-agent"
else
    case "$(uname -m)" in
        arm64)  ASSET="screenguard-agent-macos-arm64" ;;
        x86_64) ASSET="screenguard-agent-macos-x86_64" ;;
        *)      error "Unsupported architecture: $(uname -m)" ;;
    esac
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    info "Downloading ${ASSET}"
    curl -fsSL "${RELEASES_URL}/${ASSET}" -o "${TMP}/agent" \
        || error "Download failed. Build locally instead: cargo build --release -p agent && sudo $0 --from target/release/agent ..."
    install -m 755 "${TMP}/agent" "${INSTALL_DIR}/screenguard-agent"
    info "Installed ${INSTALL_DIR}/screenguard-agent"
fi

# ── config ────────────────────────────────────────────────────────────────────

if [[ -n "$SERVER_URL" || -n "$CLOUD_ACCOUNT" ]]; then
    header "Writing ${CONFIG_DIR}/agent.toml"
    {
        echo "# Written by install-macos.sh. Edit and then:"
        echo "#   sudo launchctl kickstart -k system/${LABEL}"
        [[ -n "$SERVER_URL" ]]    && echo "server_url = \"${SERVER_URL}\""
        [[ -n "$CLOUD_ACCOUNT" ]] && echo "cloud_account = \"${CLOUD_ACCOUNT}\""
    } > "${CONFIG_DIR}/agent.toml"
    chmod 644 "${CONFIG_DIR}/agent.toml"
    info "Server: ${SERVER_URL}${CLOUD_ACCOUNT}"
fi

# ── log rotation ──────────────────────────────────────────────────────────────

mkdir -p /etc/newsyslog.d
cat > /etc/newsyslog.d/screenguard.conf <<EOF
# logfilename                  [owner:group]  mode count size(KB) when flags
${LOG_FILE}                                   644  5     1000     *    J
EOF
info "Log rotation configured (5 × 1 MB, gzipped)"

# ── daemon ────────────────────────────────────────────────────────────────────

header "Installing the LaunchDaemon"
PLIST_SRC=""
for candidate in "$(dirname "$0")/deploy/org.screenguard.agent.plist" \
                 "${RELEASES_URL}/org.screenguard.agent.plist"; do
    if [[ "$candidate" == http* ]]; then
        TMP_PLIST="$(mktemp)"
        if curl -fsSL "$candidate" -o "$TMP_PLIST"; then PLIST_SRC="$TMP_PLIST"; break; fi
    elif [[ -f "$candidate" ]]; then
        PLIST_SRC="$candidate"; break
    fi
done
[[ -n "$PLIST_SRC" ]] || error "Could not find org.screenguard.agent.plist"

launchctl bootout "system/${LABEL}" 2>/dev/null || true
install -m 644 -o root -g wheel "$PLIST_SRC" "$PLIST"
launchctl bootstrap system "$PLIST"
info "Loaded ${LABEL}"

sleep 2
if launchctl print "system/${LABEL}" &>/dev/null; then
    info "Agent is running"
else
    error "Agent failed to start — check $LOG_FILE"
fi

header "Done"
cat <<EOF
  Logs:    tail -f ${LOG_FILE}
  Restart: sudo launchctl kickstart -k system/${LABEL}
  Remove:  sudo $0 --uninstall

The machine now shows up as pending on the server; approve it there and it is
managed. Web filtering is not available on macOS, so the server hides that
feature for this device.
EOF
