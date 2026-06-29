#!/bin/bash
# =============================================================================
# Sentari Agent — Installation Script
# =============================================================================
#
# This script downloads, verifies, and installs the Sentari agent as a
# systemd service on Linux systems.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh | bash -s -- \
#     --version 0.1.0 \
#     --server-url https://sentari.example.com:8000 \
#     --enroll-token YOUR_TOKEN
#
# Or download and run manually:
#   chmod +x install.sh
#   sudo ./install.sh --version 0.1.0 --server-url https://sentari.example.com:8000 --enroll-token YOUR_TOKEN
#
# Requirements:
#   - Linux (amd64 or arm64)
#   - curl
#   - sha256sum
#   - systemd
#   - Root privileges (sudo)
#
# What this script does:
#   1. Downloads the agent binary from GitHub Releases
#   2. Verifies the SHA256 checksum
#   3. Installs the binary to /usr/local/bin/sentari-agent
#   4. Creates the config file at /etc/sentari/agent.conf
#   5. Writes the enrollment token to /etc/sentari/enroll-token (restricted permissions)
#   6. Creates a systemd service (sentari-agent.service)
#   7. Starts the agent in daemon mode
#
# =============================================================================

set -euo pipefail

# --- Defaults ----------------------------------------------------------------

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sentari"
DATA_DIR="/var/lib/sentari"
BINARY_NAME="sentari-agent"
GITHUB_REPO="sentari-dev/sentari-agent"

# --- Parse arguments ---------------------------------------------------------

VERSION=""
SERVER_URL=""
ENROLL_TOKEN=""
EDITION="enterprise"  # "enterprise" or "oss"
SCAN_INTERVAL="3600"
SCAN_ROOT="/"

usage() {
    echo "Usage: $0 --version VERSION --server-url URL --enroll-token TOKEN [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --version VERSION        Agent version to install (e.g., 0.1.0)"
    echo "  --server-url URL         Sentari server URL (e.g., https://sentari.example.com:8000)"
    echo "  --enroll-token TOKEN     One-time enrollment token from your Sentari admin"
    echo ""
    echo "Optional:"
    echo "  --edition EDITION        'enterprise' (default) or 'oss'"
    echo "  --scan-interval SECONDS  Time between scans in seconds (default: 3600)"
    echo "  --scan-root PATH         Filesystem root to scan (default: /)"
    echo "  --help                   Show this help message"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      VERSION="$2"; shift 2 ;;
        --server-url)   SERVER_URL="$2"; shift 2 ;;
        --enroll-token) ENROLL_TOKEN="$2"; shift 2 ;;
        --edition)      EDITION="$2"; shift 2 ;;
        --scan-interval) SCAN_INTERVAL="$2"; shift 2 ;;
        --scan-root)    SCAN_ROOT="$2"; shift 2 ;;
        --help)         usage ;;
        *)              echo "Unknown option: $1"; usage ;;
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

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    arm64)   GOARCH="arm64" ;;  # macOS-style
    *)       echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "$OS" != "linux" ]]; then
    echo "Error: This install script is for Linux only. Got: $OS"
    echo "For Windows, use deploy/installer/windows/install.ps1"
    exit 1
fi

echo "============================================"
echo "  Sentari Agent Installer"
echo "============================================"
echo ""
echo "  Version:    v${VERSION}"
echo "  Edition:    ${EDITION}"
echo "  OS/Arch:    ${OS}/${GOARCH}"
echo "  Server:     ${SERVER_URL:-N/A (OSS)}"
echo ""

# --- Check prerequisites -----------------------------------------------------

echo "[1/7] Checking prerequisites..."

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

for cmd in curl sha256sum systemctl; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Required command not found: $cmd"
        exit 1
    fi
done

echo "  OK — root privileges, curl, sha256sum, systemd"

# --- Download binary ----------------------------------------------------------

echo ""
echo "[2/7] Downloading agent binary..."

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
    echo "[3/7] Verifying checksum..."
    cd "$TMPDIR"
    if grep "${BINARY_FILE}" SHA256SUMS.txt | sha256sum -c - --status 2>/dev/null; then
        echo "  OK — checksum verified"
    else
        echo "Error: Checksum verification FAILED"
        echo "The downloaded binary does not match the expected checksum."
        echo "This could indicate a corrupted download or a tampered binary."
        exit 1
    fi
    cd - > /dev/null
fi

# --- Install binary -----------------------------------------------------------

echo ""
echo "[4/7] Installing binary..."

install -m 755 "${TMPDIR}/${BINARY_FILE}" "${INSTALL_DIR}/${BINARY_NAME}"
echo "  Installed: ${INSTALL_DIR}/${BINARY_NAME}"

# Verify it runs
if ! "${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null; then
    echo "Warning: Could not verify binary — it may not be executable on this system"
fi

# --- Create configuration -----------------------------------------------------

echo ""
echo "[5/7] Creating configuration..."

mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Write config file
cat > "${CONFIG_DIR}/agent.conf" <<CONF
# Sentari Agent Configuration
# Generated by install.sh on $(date -Iseconds)

[server]
url = ${SERVER_URL}

[scanner]
scan_root = ${SCAN_ROOT}
scan_max_depth = 12
interval = ${SCAN_INTERVAL}
CONF

chmod 644 "${CONFIG_DIR}/agent.conf"
echo "  Config: ${CONFIG_DIR}/agent.conf"

# Write enrollment token to a file (not in config, not on command line)
if [[ -n "$ENROLL_TOKEN" ]]; then
    echo -n "$ENROLL_TOKEN" > "${CONFIG_DIR}/enroll-token"
    chmod 600 "${CONFIG_DIR}/enroll-token"
    echo "  Token:  ${CONFIG_DIR}/enroll-token (permissions: 600)"
fi

echo "  Data:   ${DATA_DIR}/"

# --- Create systemd service ---------------------------------------------------

echo ""
echo "[6/7] Creating systemd service..."

cat > /etc/systemd/system/sentari-agent.service <<SERVICE
[Unit]
Description=Sentari Agent — Python environment scanner
Documentation=https://github.com/${GITHUB_REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} \\
    --serve \\
    --config ${CONFIG_DIR}/agent.conf \\
    --enroll-token-file ${CONFIG_DIR}/enroll-token \\
    --data-dir ${DATA_DIR}
Restart=always
RestartSec=10
# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${DATA_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
echo "  Created: /etc/systemd/system/sentari-agent.service"

# --- Start the service --------------------------------------------------------

echo ""
echo "[7/7] Starting the agent..."

systemctl enable sentari-agent
systemctl start sentari-agent

# Give it a moment to register
sleep 2

if systemctl is-active --quiet sentari-agent; then
    echo "  OK — sentari-agent is running"
else
    echo "  Warning: Service may not have started correctly"
    echo "  Check logs with: journalctl -u sentari-agent -f"
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
echo "  Service:  sentari-agent.service"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl status sentari-agent    # Check status"
echo "    sudo journalctl -u sentari-agent -f    # Follow logs"
echo "    sudo systemctl restart sentari-agent   # Restart"
echo "    sudo systemctl stop sentari-agent      # Stop"
echo ""
echo "  The agent will register with the server on its first scan"
echo "  and then scan every ${SCAN_INTERVAL} seconds."
echo ""
