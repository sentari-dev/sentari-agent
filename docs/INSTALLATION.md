# Sentari Agent — Installation Guide

This guide walks you through installing the Sentari agent on your devices.

---

## Table of Contents

1. [Choose Your Edition](#choose-your-edition)
2. [Community Edition (OSS)](#community-edition-oss)
3. [Enterprise Edition](#enterprise-edition)
4. [Verify the Installation](#verify-the-installation)
5. [Troubleshooting](#troubleshooting)

---

## Choose Your Edition

The Sentari agent comes in two editions. Both use the same scanning engine and detect the same Python environments.

| | Community Edition (OSS) | Enterprise Edition |
|---|---|---|
| **Use case** | One-off audits, CI pipelines, local scans | Fleet-wide monitoring with a Sentari server |
| **Server required** | No | Yes |
| **Output** | JSON or CSV file saved locally | Uploaded to Sentari server automatically |
| **Installation** | Download binary, run manually | Install script sets up a background service |
| **Scheduled scanning** | No (run manually or via cron) | Yes (configurable interval, default 1 hour) |
| **Offline scan queue** | No | Yes (queues locally, drains on reconnection) |
| **mTLS encryption** | No | Yes (automatic certificate provisioning) |
| **Audit trail** | No | Yes (SHA-256 hash-chained local log) |
| **License** | Apache 2.0 (free) | Commercial (requires Sentari subscription) |
| **Binary name** | `sentari-agent-oss-*` | `sentari-agent-*` |

**Not sure?** Start with the Community Edition -- it requires nothing except the binary. You can switch to Enterprise later by installing the Enterprise binary and pointing it at a server.

### System requirements (both editions)

| | Linux | Windows | macOS |
|---|---|---|---|
| OS | RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+, SLES 15+ | Windows 10 / Server 2016+ | macOS 12+ (Monterey) |
| Architecture | x86_64 (amd64) or ARM64 | x86_64 (amd64) | x86_64 (amd64) or ARM64 (Apple Silicon) |
| Disk space | 50 MB (binary) | 50 MB (binary) | 50 MB (binary) |
| Network | None (OSS) / Outbound HTTPS (Enterprise) | Same | Same |
| Permissions | Root recommended for full filesystem scan | Administrator recommended | Admin recommended |
| Dependencies | **None** -- single static binary | **None** -- single static binary | **None** -- single static binary |

---

## Community Edition (OSS)

The Community Edition is a standalone scanner. Download the binary, run it, and get a JSON or CSV report of all Python packages on the device. No server, no registration, no configuration.

### Linux / macOS

```bash
# Download (replace linux-amd64 with your platform: linux-arm64, darwin-amd64, darwin-arm64)
VERSION="0.1.0"
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/sentari-agent-oss-linux-amd64"
chmod +x sentari-agent-oss-linux-amd64

# Scan and save results as JSON
./sentari-agent-oss-linux-amd64 --scan --output scan-result.json

# Or output as CSV
./sentari-agent-oss-linux-amd64 --scan --format csv --output packages.csv
```

### Windows

```powershell
# Download
$VERSION = "0.1.0"
Invoke-WebRequest -Uri "https://github.com/sentari-dev/sentari-agent/releases/download/v$VERSION/sentari-agent-oss-windows-amd64.exe" -OutFile sentari-agent.exe

# Scan and save results
.\sentari-agent.exe --scan --output scan-result.json
```

### What the output looks like

The JSON output contains every discovered Python package:

```json
{
  "device_id": "a1b2c3d4",
  "hostname": "dev-laptop",
  "os": "linux",
  "scanned_at": "2026-04-06T12:00:00Z",
  "packages": [
    {
      "name": "requests",
      "version": "2.31.0",
      "env_type": "pip",
      "interpreter_version": "3.12.0",
      "install_path": "/usr/lib/python3.12/site-packages/requests-2.31.0.dist-info",
      "environment": "/usr/lib/python3.12"
    }
  ]
}
```

### Running on a schedule (without Enterprise)

Use cron to scan periodically and save results:

```bash
# Add to crontab (scan every 6 hours)
echo "0 */6 * * * /usr/local/bin/sentari-agent-oss --scan --output /var/log/sentari/scan-\$(date +\%Y\%m\%d-\%H\%M).json" | sudo crontab -
```

### Building from source

```bash
git clone https://github.com/sentari-dev/sentari-agent.git
cd sentari-agent
CGO_ENABLED=0 go build -o sentari-agent-oss ./cmd/sentari-agent/
```

---

## Enterprise Edition

The Enterprise Edition connects to a Sentari server for centralized fleet management. It registers automatically via mTLS, uploads scan results, and runs as a background service with scheduled scanning.

**You need from your Sentari administrator:**
1. **Server URL** -- The address of your Sentari server (e.g., `https://sentari.yourcompany.com:8000`)
2. **Enrollment token** -- A one-time token that authorizes new agents to register. Found in the Sentari dashboard under **Settings > General > Enrollment Token**.
3. **Agent version** -- The version to install (e.g., `0.1.0`). Check the [Releases page](https://github.com/sentari-dev/sentari-agent/releases) for the latest version.

### Linux

#### Quick Install

Open a terminal on the device and run (replace the three values with your own):

```bash
curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh | \
  sudo bash -s -- --version 0.1.0 --server-url https://sentari.yourcompany.com:8000 --enroll-token YOUR_TOKEN
```

Or download and inspect the script first:

```bash
curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh -o install.sh
chmod +x install.sh
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
  Installed: /usr/local/bin/sentari-agent
[5/7] Creating configuration...
[6/7] Creating systemd service...
[7/7] Starting the agent...
  OK — sentari-agent is running

============================================
  Installation complete!
============================================
```

#### Install script options

| Flag | Required | Default | Description |
|---|---|---|---|
| `--version` | Yes | -- | Agent version (e.g., `0.1.0`) |
| `--server-url` | Yes (enterprise) | -- | Sentari server URL |
| `--enroll-token` | Yes (enterprise) | -- | One-time enrollment token |
| `--edition` | No | `enterprise` | `enterprise` or `oss` |
| `--scan-interval` | No | `3600` | Seconds between scans |
| `--scan-root` | No | `/` | Filesystem root to scan |

#### Fleet Install (Ansible)

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

#### Fleet Install (SSH)

If you have a list of hostnames and SSH access:

**Step 1:** Create a file with one hostname per line:

```
# devices.txt
server-01.internal
server-02.internal
db-prod-01.internal
web-01.internal
```

**Step 2:** Create and run the deployment script:

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

```bash
chmod +x deploy-to-fleet.sh
./deploy-to-fleet.sh
```

#### Air-gapped Install

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
scan_max_depth = 12
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

#### Managing the Service

```bash
# Check status
sudo systemctl status sentari-agent

# Follow logs in real time
sudo journalctl -u sentari-agent -f

# Restart the agent
sudo systemctl restart sentari-agent

# Stop the agent
sudo systemctl stop sentari-agent

# Disable on boot
sudo systemctl disable sentari-agent
```

#### Uninstall

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

#### Quick Install

Open PowerShell as Administrator and run:

```powershell
irm https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.ps1 -OutFile install.ps1
.\install.ps1 -Version 0.1.0 -ServerURL https://sentari.yourcompany.com:8000 -EnrollToken YOUR_TOKEN
```

Or download and inspect the script first:

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.ps1 -OutFile install.ps1
Get-Content install.ps1  # Review the script
.\install.ps1 -Version 0.1.0 -ServerURL https://sentari.yourcompany.com:8000 -EnrollToken YOUR_TOKEN
```

#### Install script parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-Version` | Yes | -- | Agent version (e.g., `0.1.0`) |
| `-ServerURL` | Yes | -- | Sentari server URL |
| `-EnrollToken` | Yes | -- | One-time enrollment token |
| `-Edition` | No | `enterprise` | `enterprise` or `oss` |
| `-ScanInterval` | No | `3600` | Seconds between scans |
| `-InstallDir` | No | `C:\Program Files\Sentari` | Installation directory |
| `-ServiceName` | No | `SentariAgent` | Windows service name |

#### Fleet Install (GPO / SCCM)

For deploying across many Windows machines, use Group Policy or SCCM to run the installer silently.

**Option A: Group Policy startup script**

1. Download `install.ps1` and the agent binary to a network share (e.g., `\\fileserver\sentari\`)
2. Create a Group Policy Object (GPO) targeting the desired OUs
3. Under **Computer Configuration > Policies > Windows Settings > Scripts > Startup**, add a PowerShell script:

```powershell
# GPO startup script — runs as SYSTEM
powershell.exe -ExecutionPolicy Bypass -File "\\fileserver\sentari\install.ps1" `
  -Version 0.1.0 `
  -ServerURL https://sentari.yourcompany.com:8000 `
  -EnrollToken YOUR_TOKEN
```

**Option B: SCCM/MECM application deployment**

1. Create an Application in SCCM with the following install command:

```
powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Version 0.1.0 -ServerURL https://sentari.yourcompany.com:8000 -EnrollToken YOUR_TOKEN
```

2. Set the detection rule to check for the existence of `C:\Program Files\Sentari\sentari-agent.exe`
3. Deploy to the target device collection

**Option C: PowerShell remoting**

```powershell
$devices = Get-Content devices.txt
$version = "0.1.0"
$serverUrl = "https://sentari.yourcompany.com:8000"
$enrollToken = "YOUR_TOKEN"

foreach ($device in $devices) {
    Write-Host "--- Installing on $device ---"
    Invoke-Command -ComputerName $device -ScriptBlock {
        param($v, $s, $t)
        irm https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.ps1 -OutFile C:\Windows\Temp\install.ps1
        & C:\Windows\Temp\install.ps1 -Version $v -ServerURL $s -EnrollToken $t
        Remove-Item C:\Windows\Temp\install.ps1
    } -ArgumentList $version, $serverUrl, $enrollToken
    Write-Host "--- Done: $device ---"
}
```

#### Air-gapped Install

For machines without internet access:

**Step 1:** On a machine with internet, download the binary and checksum:

```powershell
$VERSION = "0.1.0"
Invoke-WebRequest -Uri "https://github.com/sentari-dev/sentari-agent/releases/download/v$VERSION/sentari-agent-windows-amd64.exe" -OutFile sentari-agent-windows-amd64.exe
Invoke-WebRequest -Uri "https://github.com/sentari-dev/sentari-agent/releases/download/v$VERSION/SHA256SUMS.txt" -OutFile SHA256SUMS.txt
```

**Step 2:** Verify the checksum:

```powershell
$expected = (Get-Content SHA256SUMS.txt | Select-String 'sentari-agent-windows-amd64.exe') -replace '\s+.*',''
$actual = (Get-FileHash sentari-agent-windows-amd64.exe -Algorithm SHA256).Hash
if ($actual -eq $expected) { Write-Host "Checksum OK" } else { Write-Host "CHECKSUM MISMATCH" -ForegroundColor Red }
```

**Step 3:** Transfer the binary to the target machine (USB, network share, etc.)

**Step 4:** On the target machine, install manually (PowerShell as Administrator):

```powershell
# Create directories
$InstallDir = "C:\Program Files\Sentari"
$ConfigDir = "$InstallDir\config"
$DataDir = "C:\ProgramData\Sentari"

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir, $DataDir | Out-Null

# Copy binary
Copy-Item sentari-agent-windows-amd64.exe "$InstallDir\sentari-agent.exe"

# Write config
@"
[server]
url = https://sentari.yourcompany.com:8000

[scanner]
scan_root = C:\
scan_max_depth = 12
interval = 3600
"@ | Set-Content "$ConfigDir\agent.conf" -Encoding UTF8

# Write enrollment token (restricted permissions)
Set-Content "$ConfigDir\enroll-token" -Value "YOUR_TOKEN" -NoNewline -Encoding UTF8
$tokenAcl = Get-Acl "$ConfigDir\enroll-token"
$tokenAcl.SetAccessRuleProtection($true, $false)
$tokenAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','FullControl','None','None','Allow')))
$tokenAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','None','None','Allow')))
Set-Acl "$ConfigDir\enroll-token" $tokenAcl

# Restrict data directory ACL
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl $DataDir $acl

# Register service
$binPath = "`"$InstallDir\sentari-agent.exe`" --serve --config `"$ConfigDir\agent.conf`" --enroll-token-file `"$ConfigDir\enroll-token`" --data-dir `"$DataDir`""
New-Service -Name SentariAgent -BinaryPathName $binPath -DisplayName "Sentari Agent" -StartupType Automatic | Out-Null
sc.exe failure SentariAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# Start the service
Start-Service SentariAgent
```

#### Managing the Service

```powershell
# Check status
Get-Service SentariAgent

# View recent logs
Get-EventLog -LogName Application -Source SentariAgent -Newest 20

# Restart the agent
Restart-Service SentariAgent

# Stop the agent
Stop-Service SentariAgent

# Disable on boot
Set-Service SentariAgent -StartupType Disabled
```

#### Uninstall

```powershell
# Stop and remove the service
Stop-Service SentariAgent -Force
sc.exe delete SentariAgent

# Remove files
Remove-Item -Recurse -Force "C:\Program Files\Sentari"
Remove-Item -Recurse -Force "C:\ProgramData\Sentari"

# Remove from system PATH (optional)
$path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
$path = ($path -split ';' | Where-Object { $_ -ne 'C:\Program Files\Sentari' }) -join ';'
[System.Environment]::SetEnvironmentVariable('Path', $path, 'Machine')
```

### macOS

macOS is supported via an `install-macos.sh` script that mirrors the Linux and Windows installers. It configures the agent as a **launchd system daemon** so it runs in the background across reboots, with automatic restart on failure. Both **Intel Macs** and **Apple Silicon** (M1/M2/M3/M4) are supported.

> **Note on unsigned binaries.** The macOS binaries are not currently signed with an Apple Developer ID. The installer strips the Gatekeeper `com.apple.quarantine` attribute so the daemon can start without user interaction — this is the supported way for administrators to approve internally-distributed binaries. A signed `.pkg` installer is on the roadmap (see [ROADMAP.md](../ROADMAP.md)).

#### Quick Install

One command — downloads the right binary for your architecture, verifies the checksum, writes the config, and registers the launchd daemon:

```bash
curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install-macos.sh | sudo bash -s -- \
  --version 0.1.1 \
  --server-url https://sentari.yourcompany.com:8000 \
  --enroll-token YOUR_TOKEN
```

Or download first, inspect, then run:

```bash
curl -LO https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install-macos.sh
chmod +x install-macos.sh
sudo ./install-macos.sh \
  --version 0.1.1 \
  --server-url https://sentari.yourcompany.com:8000 \
  --enroll-token YOUR_TOKEN
```

#### Install script options

| Flag | Required | Description |
|---|---|---|
| `--version` | Yes | Agent version to install (e.g., `0.1.1`) |
| `--server-url` | Yes (enterprise) | Sentari server URL |
| `--enroll-token` | Yes (enterprise) | One-time enrollment token from your Sentari admin |
| `--edition` | No | `enterprise` (default) or `oss` |
| `--scan-interval` | No | Seconds between scans (default: `3600`) |
| `--scan-root` | No | Filesystem root to scan (default: `/`) |

The installer writes these locations:

| Path | Purpose |
|---|---|
| `/usr/local/bin/sentari-agent` | Binary |
| `/etc/sentari/agent.conf` | Config (server URL, scanner settings) |
| `/etc/sentari/enroll-token` | Enrollment token, mode 600, root only |
| `/var/lib/sentari/` | Data dir (SQLite cache, audit log, mTLS certs) |
| `/Library/LaunchDaemons/dev.sentari.agent.plist` | launchd daemon definition |
| `/var/log/sentari-agent.log` | stdout + stderr log |

#### Fleet Install (Ansible)

For enterprise deployment across many Macs, use Ansible to push the installer:

```yaml
# Inventory: a macOS group with the hosts you want to manage
# ansible-playbook -i inventory.yml install-sentari.yml --ask-become-pass

- name: Install Sentari agent on macOS fleet
  hosts: macos
  become: true
  vars:
    sentari_version: "0.1.1"
    sentari_server_url: "https://sentari.yourcompany.com:8000"
    sentari_enroll_token: "{{ lookup('env', 'SENTARI_ENROLL_TOKEN') }}"
  tasks:
    - name: Download install script
      ansible.builtin.get_url:
        url: "https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install-macos.sh"
        dest: /tmp/install-macos.sh
        mode: "0755"

    - name: Run installer
      ansible.builtin.command:
        cmd: >
          /tmp/install-macos.sh
          --version {{ sentari_version }}
          --server-url {{ sentari_server_url }}
          --enroll-token {{ sentari_enroll_token }}
        creates: /usr/local/bin/sentari-agent

    - name: Clean up install script
      ansible.builtin.file:
        path: /tmp/install-macos.sh
        state: absent
```

#### Fleet Install (Jamf / Intune / Kandji)

Most MDM products support running shell scripts as a policy. Upload `install-macos.sh` as the policy script and pass the installer flags as arguments. Example for **Jamf Pro**:

1. **Settings → Computer Management → Scripts**: upload `install-macos.sh`
2. Set **Script Parameter 4** to the version (e.g., `0.1.1`)
3. Set **Script Parameter 5** to the server URL
4. Set **Script Parameter 6** to the enrollment token
5. Wrap the script call in a tiny bootstrap:
   ```bash
   #!/bin/bash
   exec /usr/local/sentari/install-macos.sh \
     --version "$4" \
     --server-url "$5" \
     --enroll-token "$6"
   ```
6. Create a **Policy** that runs the script on your target scope

The same pattern applies to Intune (Shell scripts), Kandji (Custom Scripts), and Addigy (Custom Facts).

#### Managing the daemon

```bash
# Check status
sudo launchctl print system/dev.sentari.agent

# Follow logs in real-time
sudo tail -f /var/log/sentari-agent.log

# Restart the daemon
sudo launchctl kickstart -k system/dev.sentari.agent

# Stop (unload) the daemon
sudo launchctl bootout system/dev.sentari.agent

# Manually run a one-shot scan (outside the daemon)
sudo /usr/local/bin/sentari-agent \
  --config /etc/sentari/agent.conf \
  --data-dir /var/lib/sentari \
  --upload
```

#### Uninstall

```bash
# Stop and unload the daemon
sudo launchctl bootout system/dev.sentari.agent 2>/dev/null || true

# Remove files
sudo rm -f /Library/LaunchDaemons/dev.sentari.agent.plist
sudo rm -f /usr/local/bin/sentari-agent
sudo rm -rf /etc/sentari
sudo rm -rf /var/lib/sentari
sudo rm -f /var/log/sentari-agent.log
```

#### Manual install (no installer script)

If you prefer to inspect and deploy each step yourself, follow this path — it's what the installer script automates:

**Step 1:** Download the binary for your architecture:

```bash
VERSION="0.1.1"

# Apple Silicon (M1/M2/M3/M4)
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/sentari-agent-darwin-arm64"

# Intel Macs
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/sentari-agent-darwin-amd64"
```

**Step 2:** Verify the checksum:

```bash
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/SHA256SUMS.txt"
grep "sentari-agent-darwin" SHA256SUMS.txt | shasum -a 256 -c -
```

**Step 3:** Strip Gatekeeper quarantine and install:

```bash
xattr -d com.apple.quarantine sentari-agent-darwin-arm64 2>/dev/null || true
sudo mkdir -p /usr/local/bin /etc/sentari /var/lib/sentari
sudo install -m 755 sentari-agent-darwin-arm64 /usr/local/bin/sentari-agent
```

**Step 4:** Write the config and token, then the launchd plist, then load it — the full sequence is embedded in [`install-macos.sh`](../install-macos.sh). Read the script; every step is commented.

#### One-shot scans (no daemon)

If you only want to run an ad-hoc scan without registering a persistent daemon — for example on a developer's laptop or for one-time auditing — skip the installer entirely:

```bash
VERSION="0.1.1"
curl -LO "https://github.com/sentari-dev/sentari-agent/releases/download/v${VERSION}/sentari-agent-darwin-arm64"
chmod +x sentari-agent-darwin-arm64
xattr -d com.apple.quarantine sentari-agent-darwin-arm64 2>/dev/null || true

./sentari-agent-darwin-arm64 \
  --server-url https://sentari.yourcompany.com:8000 \
  --enroll-token YOUR_TOKEN \
  --data-dir /tmp/sentari-agent \
  --upload
```

When done, delete the binary and `/tmp/sentari-agent/`. Nothing is installed system-wide.

---

## Verify the Installation

After installation on any platform, verify the agent is working correctly:

### Check the service status

```bash
# Linux
sudo systemctl status sentari-agent
```

```powershell
# Windows
Get-Service SentariAgent
```

```bash
# macOS (if using launchd)
sudo launchctl print system/dev.sentari.agent
```

### Check the logs

```bash
# Linux -- follow logs in real time
sudo journalctl -u sentari-agent -f

# You should see:
#   Registering agent and obtaining certificates...
#   Certificates saved to /var/lib/sentari/certs
#   scan.started hostname=your-hostname
#   scan.completed packages=142
#   upload.success packages=142
```

```powershell
# Windows
Get-EventLog -LogName Application -Source SentariAgent -Newest 20
```

```bash
# macOS (if using launchd)
tail -f /var/log/sentari-agent.log
```

### Check the dashboard

1. Open your Sentari dashboard
2. Go to **Fleet > Devices**
3. Your device should appear with its hostname, OS, and package count
4. Click on the device to see the full package inventory

### Check the certificate

After successful registration, the agent has an mTLS certificate:

```bash
# Linux / macOS
ls -la /var/lib/sentari/certs/
# Should contain: ca.crt, device.crt, device.key, device_id
```

```powershell
# Windows
Get-ChildItem "C:\ProgramData\Sentari\certs"
# Should contain: ca.crt, device.crt, device.key, device_id
```

---

## Troubleshooting

### Connection issues

**"Registration failed: connection refused"**

The agent cannot reach the server. Check:
- Is the server URL correct? (including the port)
- Is there a firewall blocking outbound HTTPS?
- Can you reach the server from the device?

```bash
# Linux / macOS
curl -v https://sentari.yourcompany.com:8000/health
```

```powershell
# Windows
Invoke-WebRequest -Uri https://sentari.yourcompany.com:8000/health -UseBasicParsing
```

If behind a proxy, configure it in the agent config:

```ini
[proxy]
https_proxy = http://proxy.yourcompany.com:3128
```

### Authentication issues

**"Registration failed: invalid enrollment token"**

The token is wrong or has been rotated. Get a new token from your Sentari administrator (Settings > General > Enrollment Token).

### Scanning issues

**"scan.completed packages=0"**

The agent found no Python environments. This is normal if:
- The device has no Python installed
- Python is installed in a non-standard location -- increase `scan_max_depth` in the config
- The agent doesn't have read access to the directories -- run as root/Administrator

### Linux-specific

**Agent is not starting:**

```bash
sudo journalctl -u sentari-agent --no-pager -n 50
```

Common issues:
- Binary is not executable: `sudo chmod +x /usr/local/bin/sentari-agent`
- Config file syntax error: check `/etc/sentari/agent.conf`
- Data directory permissions: `sudo chmod 700 /var/lib/sentari`

### Windows-specific

**Service fails to start:**

```powershell
# Check Event Viewer
Get-EventLog -LogName Application -Source SentariAgent -Newest 10
```

Common issues:
- The install directory or binary was deleted -- reinstall
- Config file syntax error: check `C:\Program Files\Sentari\config\agent.conf`
- Port conflict: ensure no other service is using the same local port
- Antivirus quarantined the binary: add an exclusion for `C:\Program Files\Sentari\`

### macOS-specific

**launchd service not starting:**

```bash
sudo launchctl print system/dev.sentari.agent
# If the "last exit code" is non-zero, check the log:
sudo tail -f /var/log/sentari-agent.log
```

Common issues:
- Binary not signed: macOS Gatekeeper may block unsigned binaries. Remove the quarantine attribute:
  ```bash
  sudo xattr -d com.apple.quarantine /usr/local/bin/sentari-agent
  ```
- Permissions: ensure `/var/lib/sentari` is writable
