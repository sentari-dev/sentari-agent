# Sentari Agent

The Sentari agent scans endpoints for Python environments and packages. It is a single statically-linked binary with zero runtime dependencies — no Python, no package manager, no runtime required.

## What it does

The agent walks the filesystem and extracts package metadata from:

- **pip / venv** — `.dist-info/METADATA` and `.egg-info/PKG-INFO`
- **conda** — `conda-meta/` JSON metadata
- **Poetry** — `poetry.lock` (TOML)
- **Pipenv** — `Pipfile.lock` (JSON)
- **System (Debian)** — `/var/lib/dpkg/status`
- **System (RPM)** — `/var/lib/rpm/rpmdb.sqlite`
- **pyenv / asdf** — explicit version manager directory discovery
- **Windows Registry** — `HKLM/HKCU\SOFTWARE\Python\PythonCore`
- **Legacy editable installs** — `.egg-link` files

The agent **never executes** `pip`, `conda`, `python`, or any other binary. All data is read directly from the filesystem.

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
