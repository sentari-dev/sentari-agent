# Sentari Agent

The Sentari agent scans endpoints for installed software across multiple ecosystems — Python, npm, NuGet, JVM (Maven/Gradle), and OS packages — plus language runtimes and AI-agent tooling. It is a single statically-linked binary with zero runtime dependencies — no Python, no package manager, no runtime required.

## Quick start

### Community Edition -- standalone scan, no server needed

Download the binary and scan locally. Results are saved as JSON or CSV.

```bash
# Linux / macOS
curl -LO https://github.com/sentari-dev/sentari-agent/releases/download/v0.1.0/sentari-agent-oss-linux-amd64
chmod +x sentari-agent-oss-linux-amd64
./sentari-agent-oss-linux-amd64 --scan --output scan-result.json
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/sentari-dev/sentari-agent/releases/download/v0.1.0/sentari-agent-oss-windows-amd64.exe -OutFile sentari-agent.exe
.\sentari-agent.exe --scan --output scan-result.json
```

### Enterprise Edition -- fleet management with Sentari server

Installs as a background service, registers with your Sentari server, and uploads scan results automatically. Requires a server URL and enrollment token from your administrator.

```bash
# Linux
curl -fsSL https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.sh | \
  sudo bash -s -- --version 0.1.0 --server-url https://sentari.example.com:8000 --enroll-token YOUR_TOKEN
```

```powershell
# Windows (PowerShell as Administrator)
irm https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.ps1 -OutFile install.ps1
.\install.ps1 -Version 0.1.0 -ServerURL https://sentari.example.com:8000 -EnrollToken YOUR_TOKEN
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for the full guide including edition comparison, fleet deployment (Ansible, GPO/SCCM), air-gapped install, and service management.

## What it does

The agent walks the filesystem and extracts package metadata across several
ecosystems, all by reading files only — never by invoking a package manager.

**Python**

- **pip / venv** — `.dist-info/METADATA` and `.egg-info/PKG-INFO`
- **conda** — `conda-meta/` JSON metadata
- **Poetry** — `poetry.lock` (TOML)
- **Pipenv** — `Pipfile.lock` (JSON)
- **pyenv / asdf** — explicit version manager directory discovery
- **Windows Registry** — `HKLM/HKCU\SOFTWARE\Python\PythonCore`
- **Legacy editable installs** — `.egg-link` files

**Other ecosystems**

- **npm** — `node_modules/*/package.json` (npm classic, yarn classic, pnpm hoisted)
- **NuGet** — global-packages `<id>/<version>/<id>.nuspec`
- **JVM** — Maven/Gradle caches, JDK runtimes, and app-server library trees (Tomcat, JBoss/WildFly, WebLogic, WebSphere, Jetty, GlassFish/Payara)
- **System packages** — Debian `/var/lib/dpkg/status`, RPM `/var/lib/rpm/rpmdb.sqlite`

**Beyond packages**

- **Language runtimes** — Python / Node / JDK versions for end-of-life correlation
- **Container images** — Docker / Podman / CRI-O image layers (opt-in via `[scanner] containers = true`)
- **AI-agent tooling** — MCP server configs, Claude Code agents/skills/plugins, and AI-oriented IDE extensions

The agent **never executes** `pip`, `conda`, `python`, `npm`, or any other binary. All data is read directly from the filesystem.

## Editions

### Community Edition (open source)

Standalone scanner. Outputs results as JSON or CSV. No server required.

```bash
sentari-agent --scan --output scan-result.json
```

### Enterprise Edition (commercial license)

Adds server connectivity, mTLS registration, scheduled scanning, offline scan queuing, and tamper-evident audit logging. Requires a [Sentari Server](https://sentari.dev) subscription.

```bash
sentari-agent-enterprise --server-url https://sentari.example.com --serve
```

Key operator flags:

- `--bootstrap-ca-fingerprint <sha256>` — pin the server's TLS certificate
  fingerprint (hex, colon-separated) for the first registration, so trust is
  not anchored solely through the OS trust store.
- `--enroll-token <token>` / `--enroll-token-file <path>` — enrollment token
  for first-time registration; the `-file` form avoids exposing the token via
  `/proc/cmdline`.
- `--update-check` — probe the server for a newer signed agent release and
  print the plan (no mutation, no service restart).
- `--update-apply` — download, verify, atomically replace this binary, and
  restart the agent service.
- `--update-rollback` — restore the previous binary (kept at
  `<install-path>.prev` by `--update-apply`) and restart the service.

## Building from source

```bash
# Community Edition
go build -o sentari-agent ./cmd/sentari-agent/

# Enterprise Edition
go build -tags enterprise -o sentari-agent-enterprise ./cmd/sentari-agent/
```

Requires Go 1.23+. The binary is fully static (`CGO_ENABLED=0`).

### Cross-compilation

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o sentari-agent-linux-arm64 ./cmd/sentari-agent/
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o sentari-agent.exe ./cmd/sentari-agent/
```

## Testing

```bash
go test ./... -v
go vet ./...
```

## System requirements

| | Linux | Windows |
|---|---|---|
| OS | RHEL/CentOS 7+, Ubuntu 18.04+, Debian 10+ | Windows 10 / Server 2016+ |
| Architecture | amd64, arm64 | amd64 |
| Disk | 50 MB (binary) + 500 MB (data directory) | Same |
| Dependencies | None | None |

## Security

- Zero binary invocation — reads metadata files only
- mTLS with ECDSA P-256 certificates (Enterprise)
- Private key never leaves the endpoint
- SHA-256 hash-chained audit log (Enterprise)
- Bootstrap CA fingerprint pinning for first registration

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

The Enterprise Edition binary includes additional features under a commercial license. The source code for enterprise features is visible in this repository (under the `enterprise` build tag) for audit purposes.
