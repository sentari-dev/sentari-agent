# Sentari Agent — Installation Guide

This guide walks you through installing the Sentari agent on your devices. The agent scans each device for Python environments and packages, then uploads the results to your Sentari server.

---

## Table of Contents

1. [Before You Start](#before-you-start)
2. [Quick Install (Single Device)](#quick-install-single-device)
3. [Fleet Install (Multiple Devices)](#fleet-install-multiple-devices)
4. [Windows Installation](#windows-installation)
5. [Verify the Installation](#verify-the-installation)
6. [Troubleshooting](#troubleshooting)
7. [Uninstall](#uninstall)

---

## Before You Start

You need three things from your Sentari administrator:

1. **Server URL** — The address of your Sentari server (e.g., `https://sentari.yourcompany.com:8000`)
2. **Enrollment token** — A one-time token that authorizes new agents to register. Found in the Sentari dashboard under **Settings > General > Enrollment Token**.
3. **Agent version** — The version to install (e.g., `0.1.0`). Check the [Releases page](https://github.com/sentari-dev/sentari-agent/releases) for the latest version.

### System requirements

| | Linux | Windows |
|---|---|---|
| OS | RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+, SLES 15+ | Windows 10 / Server 2016+ |
| Architecture | x86_64 (amd64) or ARM64 | x86_64 (amd64) |
| Disk space | 50 MB (binary) + 500 MB (data) | Same |
| Network | Outbound HTTPS to the Sentari server | Same |
| Permissions | Root recommended for full filesystem scan | Administrator recommended |
| Dependencies | **None** — single static binary | **None** — single static binary |

---

## Quick Install (Single Device)

### Step 1: Download and run the install script

Open a terminal on the device and run:

```bash
curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh -o install.sh
chmod +x install.sh
```

### Step 2: Run the installer

Replace the three values with your own:

```bash
sudo ./install.sh \
  --version 0.1.0 \
  --server-url https://sentari.yourcompany.com:8000 \
  --enroll-token YOUR_ENROLLMENT_TOKEN
```

You should see output like:

```
============================================
  Sentari Agent Installer
============================================

  Version:    v0.1.0
  Edition:    enterprise
  OS/Arch:    linux/amd64
  Server:     https://sentari.yourcompany.com:8000

[1/7] Checking prerequisites...
  OK — root privileges, curl, sha256sum, systemd
[2/7] Downloading agent binary...
[3/7] Verifying checksum...
  OK — checksum verified
[4/7] Installing binary...
  sentari-agent 0.1.0 (enterprise)
[5/7] Creating configuration...
[6/7] Creating systemd service...
[7/7] Starting the agent...
  OK — sentari-agent is running

============================================
  Installation complete!
============================================
```

### Step 3: Verify it is running

```bash
sudo systemctl status sentari-agent
```

You should see `active (running)`. The agent will perform its first scan immediately and then repeat on the configured interval (default: every hour).

### Step 4: Check the Sentari dashboard

Open your Sentari dashboard and go to **Fleet > Devices**. Your device should appear within a few minutes.

---

## Fleet Install (Multiple Devices)

For installing across many devices, use one of these methods:

### Method A: Ansible (recommended)

**Step 1:** Copy the install script to your Ansible control node:

```bash
curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh \
  -o roles/sentari-agent/files/install.sh
```

**Step 2:** Create the Ansible playbook:

```yaml
# deploy-sentari-agent.yml
---
- name: Install Sentari Agent
  hosts: all
  become: true
  vars:
    sentari_version: "0.1.0"
    sentari_server_url: "https://sentari.yourcompany.com:8000"
    sentari_enroll_token: "YOUR_ENROLLMENT_TOKEN"

  tasks:
    - name: Copy install script
      copy:
        src: install.sh
        dest: /tmp/sentari-install.sh
        mode: "0755"

    - name: Run installer
      command: >
        /tmp/sentari-install.sh
        --version {{ sentari_version }}
        --server-url {{ sentari_server_url }}
        --enroll-token {{ sentari_enroll_token }}
      args:
        creates: /usr/local/bin/sentari-agent

    - name: Ensure agent is running
      systemd:
        name: sentari-agent
        state: started
        enabled: true

    - name: Clean up installer
      file:
        path: /tmp/sentari-install.sh
        state: absent
```

**Step 3:** Run the playbook:

```bash
ansible-playbook -i inventory.ini deploy-sentari-agent.yml
```

This installs the agent on every host in your inventory. Each device registers independently with the server using the enrollment token.

### Method B: Shell script over SSH

If you have a list of hostnames and SSH access:

**Step 1:** Create a file with one hostname per line:

```
# devices.txt
server-01.internal
server-02.internal
db-prod-01.internal
web-01.internal
```

**Step 2:** Run the install script on each device:

```bash
#!/bin/bash
# deploy-to-fleet.sh

VERSION="0.1.0"
SERVER_URL="https://sentari.yourcompany.com:8000"
ENROLL_TOKEN="YOUR_ENROLLMENT_TOKEN"

while read -r HOST; do
    echo "--- Installing on ${HOST} ---"
    ssh root@"${HOST}" "
        curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh -o /tmp/install.sh
        chmod +x /tmp/install.sh
        /tmp/install.sh --version ${VERSION} --server-url ${SERVER_URL} --enroll-token ${ENROLL_TOKEN}
        rm /tmp/install.sh
    "
    echo "--- Done: ${HOST} ---"
    echo ""
done < devices.txt
```

**Step 3:** Run it:

```bash
chmod +x deploy-to-fleet.sh
./deploy-to-fleet.sh
```

### Method C: Manual download (air-gapped environments)

For devices without internet access:

**Step 1:** On a machine with internet, download the binary and checksum:

```bash
VERSION="0.1.0"

# Download for Linux amd64
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/sentari-agent-linux-amd64"
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/SHA256SUMS.txt"

# Verify checksum
grep "sentari-agent-linux-amd64" SHA256SUMS.txt | sha256sum -c -
```

**Step 2:** Transfer the binary to the target device (USB, shared drive, scp, etc.):

```bash
scp sentari-agent-linux-amd64 root@target-device:/tmp/
```

**Step 3:** On the target device, install manually:

```bash
# Install the binary
sudo install -m 755 /tmp/sentari-agent-linux-amd64 /usr/local/bin/sentari-agent

# Create directories
sudo mkdir -p /etc/sentari /var/lib/sentari
sudo chmod 700 /var/lib/sentari

# Create the config file
sudo tee /etc/sentari/agent.conf > /dev/null <<EOF
[server]
url = https://sentari.yourcompany.com:8000

[scanner]
scan_root = /
max_depth = 12
interval = 3600
EOF

# Write the enrollment token (restricted permissions)
echo -n "YOUR_ENROLLMENT_TOKEN" | sudo tee /etc/sentari/enroll-token > /dev/null
sudo chmod 600 /etc/sentari/enroll-token

# Create the systemd service
sudo tee /etc/systemd/system/sentari-agent.service > /dev/null <<EOF
[Unit]
Description=Sentari Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentari-agent --serve --config /etc/sentari/agent.conf --enroll-token-file /etc/sentari/enroll-token --data-dir /var/lib/sentari
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/sentari
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Start the service
sudo systemctl daemon-reload
sudo systemctl enable --now sentari-agent
```

**Step 4:** Verify:

```bash
sudo systemctl status sentari-agent
```

---

## Windows Installation

### Step 1: Download the binary

Open PowerShell as Administrator and run:

```powershell
$VERSION = "0.1.0"
$URL = "https://github.com/sentari-dev/sentari-agent/releases/download/v$VERSION/sentari-agent-windows-amd64.exe"
$DEST = "C:\Program Files\Sentari"

New-Item -ItemType Directory -Force -Path $DEST
Invoke-WebRequest -Uri $URL -OutFile "$DEST\sentari-agent.exe"
```

### Step 2: Run a one-shot scan

```powershell
& "C:\Program Files\Sentari\sentari-agent.exe" `
    --server-url "https://sentari.yourcompany.com:8000" `
    --enroll-token "YOUR_ENROLLMENT_TOKEN" `
    --upload
```

### Step 3: Install as a Windows service (for continuous scanning)

Use the Windows installer script:

```powershell
# Download the installer
$INSTALLER_URL = "https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/deploy/installer/windows/install.ps1"
Invoke-WebRequest -Uri $INSTALLER_URL -OutFile install.ps1

# Run it
.\install.ps1 -ServerUrl "https://sentari.yourcompany.com:8000" -EnrollToken "YOUR_ENROLLMENT_TOKEN"
```

This creates a Windows service called `SentariAgent` that starts automatically.

---

## Verify the Installation

After installation, verify the agent is working correctly:

### Check the service status

```bash
# Linux
sudo systemctl status sentari-agent

# Expected output:
#   Active: active (running) since ...
#   Main PID: 12345 (sentari-agent)
```

```powershell
# Windows
Get-Service SentariAgent

# Expected output:
#   Status   Name           DisplayName
#   ------   ----           -----------
#   Running  SentariAgent   Sentari Agent
```

### Check the logs

```bash
# Linux — follow logs in real time
sudo journalctl -u sentari-agent -f

# You should see:
#   Registering agent and obtaining certificates...
#   Certificates saved to /var/lib/sentari/certs
#   scan.started hostname=your-hostname
#   scan.completed packages=142
#   upload.success packages=142
```

### Check the dashboard

1. Open your Sentari dashboard
2. Go to **Fleet > Devices**
3. Your device should appear with its hostname, OS, and package count
4. Click on the device to see the full package inventory

### Check the certificate

After successful registration, the agent has a certificate:

```bash
ls -la /var/lib/sentari/certs/
# Should contain: ca.crt, device.crt, device.key, device_id
```

---

## Troubleshooting

### "Registration failed: connection refused"

The agent cannot reach the server. Check:
- Is the server URL correct? (including the port)
- Is there a firewall blocking outbound HTTPS?
- If behind a proxy, configure it in `/etc/sentari/agent.conf`:

```ini
[proxy]
https_proxy = http://proxy.yourcompany.com:3128
```

### "Registration failed: invalid enrollment token"

The token is wrong or has been rotated. Get a new token from your Sentari administrator (Settings > General > Enrollment Token).

### "scan.completed packages=0"

The agent found no Python environments. This is normal if:
- The device has no Python installed
- Python is installed in a non-standard location — increase `max_depth` in the config
- The agent doesn't have read access to the directories — run as root

### Agent is not starting

Check the logs:

```bash
sudo journalctl -u sentari-agent --no-pager -n 50
```

Common issues:
- Binary is not executable: `sudo chmod +x /usr/local/bin/sentari-agent`
- Config file syntax error: check `/etc/sentari/agent.conf`
- Data directory permissions: `sudo chmod 700 /var/lib/sentari`

---

## Uninstall

### Linux

```bash
# Stop and disable the service
sudo systemctl stop sentari-agent
sudo systemctl disable sentari-agent

# Remove files
sudo rm /etc/systemd/system/sentari-agent.service
sudo rm /usr/local/bin/sentari-agent
sudo rm -rf /etc/sentari
sudo rm -rf /var/lib/sentari

# Reload systemd
sudo systemctl daemon-reload
```

### Windows

```powershell
# If installed via install.ps1:
.\uninstall.ps1

# Or manually:
Stop-Service SentariAgent
sc.exe delete SentariAgent
Remove-Item -Recurse "C:\Program Files\Sentari"
Remove-Item -Recurse "C:\ProgramData\Sentari"
```
