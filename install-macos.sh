#!/bin/bash
# =============================================================================
# Sentari Agent — macOS Installation Script
# =============================================================================
#
# This script downloads, verifies, and installs the Sentari agent as a
# launchd daemon on macOS systems. It is the macOS analogue of install.sh
# (Linux/systemd) and install.ps1 (Windows service).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install-macos.sh | sudo bash -s -- \
#     --version 0.1.1 \
#     --server-url https://sentari.example.com:8000 \
#     --enroll-token YOUR_TOKEN
#
# Or download and run manually:
#   chmod +x install-macos.sh
#   sudo ./install-macos.sh --version 0.1.1 --server-url https://sentari.example.com:8000 --enroll-token YOUR_TOKEN
#
# Requirements:
#   - macOS 12+ (Monterey or later)
#   - curl, shasum, launchctl (preinstalled on macOS)
#   - Root privileges (sudo)
#
# What this script does:
#   1. Downloads the agent binary for your architecture (Intel or Apple Silicon)
#   2. Verifies the SHA256 checksum
#   3. Strips the Gatekeeper quarantine attribute (binaries from the internet)
#   4. Installs the binary to /usr/local/bin/sentari-agent
#   5. Creates the config file at /etc/sentari/agent.conf
#   6. Writes the enrollment token to /etc/sentari/enroll-token (mode 600)
#   7. Creates a launchd daemon at /Library/LaunchDaemons/dev.sentari.agent.plist
#   8. Loads and starts the daemon
#
# Note on unsigned binaries:
#   The released macOS binaries are not signed with an Apple Developer ID.
#   Gatekeeper normally blocks unsigned binaries downloaded from the internet,
#   but this installer strips the quarantine attribute so the daemon runs
#   without user intervention. A signed .pkg installer is on the roadmap.
#
# =============================================================================

set -euo pipefail

# --- Defaults ----------------------------------------------------------------

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sentari"
DATA_DIR="/var/lib/sentari"
LOG_DIR="/var/log"
BINARY_NAME="sentari-agent"
LAUNCHD_LABEL="dev.sentari.agent"
LAUNCHD_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
GITHUB_REPO="sentari-dev/sentari-agent"

# --- Parse arguments ---------------------------------------------------------

VERSION=""
SERVER_URL=""
ENROLL_TOKEN=""
EDITION="enterprise"  # "enterprise" or "oss"
SCAN_INTERVAL="3600"
SCAN_ROOT="/"

usage() {
    cat <<EOF
Usage: sudo $0 --version VERSION --server-url URL --enroll-token TOKEN [OPTIONS]

Required:
  --version VERSION        Agent version to install (e.g., 0.1.1)
  --server-url URL         Sentari server URL (e.g., https://sentari.example.com:8000)
  --enroll-token TOKEN     One-time enrollment token from your Sentari admin

Optional:
  --edition EDITION        'enterprise' (default) or 'oss'
  --scan-interval SECONDS  Time between scans in seconds (default: 3600)
  --scan-root PATH         Filesystem root to scan (default: /)
  --help                   Show this help message
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)       VERSION="$2"; shift 2 ;;
        --server-url)    SERVER_URL="$2"; shift 2 ;;
        --enroll-token)  ENROLL_TOKEN="$2"; shift 2 ;;
        --edition)       EDITION="$2"; shift 2 ;;
        --scan-interval) SCAN_INTERVAL="$2"; shift 2 ;;
        --scan-root)     SCAN_ROOT="$2"; shift 2 ;;
        --help)          usage ;;
        *)               echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "Error: --version is required"
    usage
fi
if [[ -z "$SERVER_URL" && "$EDITION" == "enterprise" ]]; then
    echo "Error: --server-url is required for enterprise edition"
    usage
fi
if [[ -z "$ENROLL_TOKEN" && "$EDITION" == "enterprise" ]]; then
    echo "Error: --enroll-token is required for enterprise edition"
    usage
fi

# --- Detect architecture -----------------------------------------------------

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "$OS" != "darwin" ]]; then
    echo "Error: This install script is for macOS only. Got: $OS"
    echo "For Linux, use install.sh"
    echo "For Windows, use install.ps1"
    exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) GOARCH="amd64" ;;
    arm64)  GOARCH="arm64" ;;
    *)      echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "============================================"
echo "  Sentari Agent Installer (macOS)"
echo "============================================"
echo ""
echo "  Version:    v${VERSION}"
echo "  Edition:    ${EDITION}"
echo "  OS/Arch:    ${OS}/${GOARCH}"
echo "  Server:     ${SERVER_URL:-N/A (OSS)}"
echo ""

# --- Check prerequisites -----------------------------------------------------

echo "[1/8] Checking prerequisites..."

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

for cmd in curl shasum launchctl xattr; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command not found: $cmd"
        exit 1
    fi
done

echo "  OK — root privileges, curl, shasum, launchctl, xattr"

# --- Download binary ----------------------------------------------------------

echo ""
echo "[2/8] Downloading agent binary..."

if [[ "$EDITION" == "oss" ]]; then
    BINARY_FILE="sentari-agent-oss-${OS}-${GOARCH}"
else
    BINARY_FILE="sentari-agent-${OS}-${GOARCH}"
fi

DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${BINARY_FILE}"
CHECKSUMS_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/SHA256SUMS.txt"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "  Downloading ${BINARY_FILE}..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "${TMPDIR}/${BINARY_FILE}"; then
    echo "Error: Failed to download from ${DOWNLOAD_URL}"
    echo "Check that version v${VERSION} exists at: https://github.com/${GITHUB_REPO}/releases"
    exit 1
fi

echo "  Downloading SHA256SUMS.txt..."
if ! curl -fsSL "$CHECKSUMS_URL" -o "${TMPDIR}/SHA256SUMS.txt"; then
    echo "Warning: Could not download checksums — skipping verification"
else
    echo ""
    echo "[3/8] Verifying checksum..."
    cd "$TMPDIR"
    if grep "${BINARY_FILE}" SHA256SUMS.txt | shasum -a 256 -c - --status 2>/dev/null; then
        echo "  OK — checksum verified"
    else
        echo "Error: Checksum verification FAILED"
        echo "The downloaded binary does not match the expected checksum."
        echo "This could indicate a corrupted download or a tampered binary."
        exit 1
    fi
    cd - > /dev/null
fi

# --- Strip Gatekeeper quarantine ---------------------------------------------

echo ""
echo "[4/8] Stripping Gatekeeper quarantine attribute..."
# The binary is unsigned and downloaded via curl, so macOS attaches a
# com.apple.quarantine xattr that would cause launchd to refuse to start it.
# Removing it is the supported way to approve unsigned binaries deployed by
# an administrator.
xattr -d com.apple.quarantine "${TMPDIR}/${BINARY_FILE}" 2>/dev/null || true
echo "  OK"

# --- Install binary -----------------------------------------------------------

echo ""
echo "[5/8] Installing binary..."

install -m 755 "${TMPDIR}/${BINARY_FILE}" "${INSTALL_DIR}/${BINARY_NAME}"
echo "  Installed: ${INSTALL_DIR}/${BINARY_NAME}"

# Verify it runs
if ! "${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null; then
    echo "Warning: Could not verify binary — it may not be executable on this system"
fi

# --- Create configuration -----------------------------------------------------

echo ""
echo "[6/8] Creating configuration..."

mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Write config file
cat > "${CONFIG_DIR}/agent.conf" <<CONF
# Sentari Agent Configuration
# Generated by install-macos.sh on $(date -Iseconds 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S%z")

[server]
url = ${SERVER_URL}

[scanner]
scan_root = ${SCAN_ROOT}
max_depth = 12
interval = ${SCAN_INTERVAL}
CONF

chmod 644 "${CONFIG_DIR}/agent.conf"
echo "  Config: ${CONFIG_DIR}/agent.conf"

# Write enrollment token to a file (not in config, not on command line)
if [[ -n "$ENROLL_TOKEN" ]]; then
    printf '%s' "$ENROLL_TOKEN" > "${CONFIG_DIR}/enroll-token"
    chmod 600 "${CONFIG_DIR}/enroll-token"
    echo "  Token:  ${CONFIG_DIR}/enroll-token (permissions: 600)"
fi

echo "  Data:   ${DATA_DIR}/"

# --- Create launchd daemon ----------------------------------------------------

echo ""
echo "[7/8] Creating launchd daemon..."

cat > "$LAUNCHD_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>--serve</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/agent.conf</string>
        <string>--enroll-token-file</string>
        <string>${CONFIG_DIR}/enroll-token</string>
        <string>--data-dir</string>
        <string>${DATA_DIR}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/sentari-agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/sentari-agent.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

chown root:wheel "$LAUNCHD_PLIST"
chmod 644 "$LAUNCHD_PLIST"
echo "  Created: ${LAUNCHD_PLIST}"

# --- Load and start the daemon -----------------------------------------------

echo ""
echo "[8/8] Starting the daemon..."

# Unload any existing instance (idempotent re-install).
if launchctl print "system/${LAUNCHD_LABEL}" &> /dev/null; then
    echo "  Unloading existing daemon..."
    launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || true
fi

# Load the daemon into the system domain. "bootstrap" is the modern API
# (replaces "load" on macOS 10.11+).
launchctl bootstrap system "$LAUNCHD_PLIST"
launchctl enable "system/${LAUNCHD_LABEL}"

# Give it a moment to register
sleep 2

if launchctl print "system/${LAUNCHD_LABEL}" &> /dev/null; then
    echo "  OK — ${LAUNCHD_LABEL} is loaded"
else
    echo "  Warning: Daemon may not have started correctly"
    echo "  Check logs: sudo tail -f ${LOG_DIR}/sentari-agent.log"
fi

# --- Done ---------------------------------------------------------------------

echo ""
echo "============================================"
echo "  Installation complete!"
echo "============================================"
echo ""
echo "  Binary:   ${INSTALL_DIR}/${BINARY_NAME}"
echo "  Config:   ${CONFIG_DIR}/agent.conf"
echo "  Data:     ${DATA_DIR}/"
echo "  Logs:     ${LOG_DIR}/sentari-agent.log"
echo "  Daemon:   ${LAUNCHD_LABEL}"
echo ""
echo "  Useful commands:"
echo "    sudo launchctl print system/${LAUNCHD_LABEL}       # Daemon status"
echo "    sudo tail -f ${LOG_DIR}/sentari-agent.log          # Follow logs"
echo "    sudo launchctl kickstart -k system/${LAUNCHD_LABEL} # Restart"
echo "    sudo launchctl bootout system/${LAUNCHD_LABEL}     # Stop and unload"
echo ""
echo "  The agent will register with the server on its first scan"
echo "  and then scan every ${SCAN_INTERVAL} seconds."
echo ""
