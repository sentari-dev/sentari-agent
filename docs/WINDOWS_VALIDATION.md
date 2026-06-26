# Windows / cross-platform validation checklist

The agent is developed and exercised primarily on macOS and Linux. This branch
(`fix/cross-platform-windows-hardening`) closes a set of Windows-specific
correctness and hardening gaps. Every change is compile-verified for
`windows/amd64` + `windows/arm64` and unit-tested where the logic is
host-independent, but a handful of items use Windows syscalls or service-control
behaviour that can only be **confirmed on a real Windows host**.

This document lists what changed and exactly what to verify on Windows.

## Build a Windows binary

From the repo root:

```bash
# Enterprise (registration, mTLS, install-gate, self-update)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags enterprise -o sentari-agent.exe ./cmd/sentari-agent

# OSS (scan-only)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o sentari-agent.exe ./cmd/sentari-agent
```

For ARM64 Windows use `GOARCH=arm64`.

## What changed, and how to validate each on Windows

Legend: **[auto]** covered by unit tests / compile checks · **[host]** needs a
real Windows device.

### 1. Forward-slash payload paths — **[auto + host]**
`scanner.NormalizePaths` rewrites every filesystem-path field (`install_path`,
`environment`, scan-error `path`, lockfile `path`, runtime `install_path`) to
forward slashes before a scan result leaves the agent, so a Windows host no
longer ships `C:\Users\...` backslash paths that fragment package-location
grouping across a mixed-OS fleet.

- **Verify:** run a scan and inspect the JSON (`--scan --format json`). Every
  `install_path` must use `/` (e.g. `C:/Users/alice/...`), never `\`.
- Confirm the same on the server/dashboard: package locations render with `/`.

### 2. Private-key / cert ACL hardening — **[host — primary]**
On Windows, Unix mode bits (`0600`) are ignored, so cert files were created
world-readable. The new `common/secureperm` package sets a protected DACL
granting access only to **LocalSystem, Builtin\Administrators, and the install
account** on the data dir (inheritable) and on the cert/key files.

- **Verify** after registration, in an elevated PowerShell:
  ```powershell
  (Get-Acl "C:\ProgramData\Sentari\certs\device.key").Access |
    Select-Object IdentityReference, FileSystemRights, AccessControlType
  ```
  Expected: only `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, and the
  service/install account. **`BUILTIN\Users` must NOT appear.**
- Repeat for `device.crt`, `ca.crt`, and the data dir itself
  (`C:\ProgramData\Sentari`).
- Negative test: log in as a standard (non-admin) user and confirm
  `Get-Content device.key` is **Access Denied**.

### 3. Default data directory — **[host]**
The enterprise agent no longer defaults to the POSIX `/var/lib/sentari` on
Windows; it uses `%ProgramData%\Sentari` (falling back to
`C:\ProgramData\Sentari`).

- **Verify:** run the enterprise agent with **no** `--data-dir` flag and confirm
  it creates and uses `C:\ProgramData\Sentari` (audit DB, scan cache, `certs/`).
- `--data-dir D:\custom\path` override still works.

### 4. Scan-root denylist — **[auto + host]**
`isScanRootDenied` now rejects Windows system trees (`C:\Windows`,
`C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`) case-insensitively
and separator-agnostically, mirroring the POSIX denylist. This blocks a
compromised server from directing a Windows agent to scan system directories.

- **Verify:** a server-pushed config with `scan_root = C:\Windows\System32` must
  be refused; a normal root (e.g. `C:\Users` or a project dir) is accepted.

### 5. Container-image path trim — **[auto]** (niche on Windows hosts)
`trimRootPrefix` compares the materialised-root prefix in forward-slash space so
the temp extraction dir is correctly stripped from in-container paths even when
the host (Windows) uses backslashes and the sub-scan emits normalised slashes.

- **Verify** (only if you scan container images on a Windows host): in-container
  package paths read `/usr/lib/...`, not `C:/Users/.../Temp/sc-xxxx/usr/lib/...`.

### 6. Runtime-detection coverage — **[host]**
Windows runtime discovery was extended beyond the standard MSI installers:
- **Node:** nvm-windows (`%APPDATA%\nvm`), fnm (`%FNM_DIR%` / `%LOCALAPPDATA%\fnm`),
  Scoop, Chocolatey, plus `Program Files (x86)`.
- **Python (system):** Chocolatey / all-users `C:\Python<XY>` installs.
- **JDK:** Eclipse Adoptium, Zulu, Microsoft Build of OpenJDK, Amazon Corretto,
  `Program Files (x86)`.

- **Verify:** on a box with Node via nvm-windows (and/or Python via Chocolatey,
  a non-Oracle JDK), run a scan and confirm those runtimes appear in
  `installed_runtimes` and on the Runtime-EOL dashboard.
- **Known remaining gap (documented, not fixed):** Microsoft Store Python
  (`%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.*` behind an app-execution
  alias) needs a dedicated detector branch and is still invisible.

### 7. Windows service auto-restart — **[host — needs field validation]**
`restart_windows.go` implements service restart via a **detached `cmd.exe`
helper** (`sc stop … & timeout … & sc start …`) so the helper survives the SCM
terminating the agent process mid-stop. The service name defaults to
`SentariAgent` and is overridable via `SENTARI_AGENT_SERVICE_NAME` (validated
against an allow-list before it reaches `sc.exe`).

- **Verify:** install the agent as a Windows service named `SentariAgent`,
  trigger a self-update (or the restart code path), and confirm the service
  **stops and comes back up** on its own.
- This is the one path explicitly flagged in-code as needing real-Windows
  confirmation — if the detached-helper timing proves unreliable, fall back to
  documenting manual restart.

## Regression surface already covered by CI (Linux, go 1.23)
`go vet ./...`, `go test ./... -race`, and OSS + enterprise builds all pass. The
full test suite — including the new `common/secureperm`, path-normalisation, and
denylist tests — runs green. Windows/macOS builds are cross-compiled but not
unit-run in CI; this checklist covers the Windows-only runtime behaviour.
