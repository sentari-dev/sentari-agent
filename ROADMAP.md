# Sentari Agent Roadmap

Living document tracking deferred work and future improvements. Items here are intentional — they were evaluated and postponed with a reason, not forgotten. Remove an item when it ships or when the decision is revisited and closed out.

---

## Recently shipped

- **2026-05-05 — Agent tags + runtime emit.** Agent now reads `[agent] tags = …` from `agent.conf` and emits operator-supplied tags on every `/scan`. Also auto-detects host runtime (`bare_metal` / `container` / `k8s` / `unknown`) via env + cgroup probes and emits it on every scan.
- **2026-05-04 — Install-gate disable-header reaction.** Agent now reacts to the server's `X-Sentari-Install-Gate-Disabled: true` response on `/policy-map` by tearing down host configs immediately + persisting a marker so a process restart between disable and re-enable doesn't re-write configs from a stale local cache. Also: when an operator flips `[install_gate] enabled = false` in `agent.conf`, the agent now actively removes any pre-existing Sentari-managed configs (previously it just no-op'd until the 7-day fail-open grace expired).

---

## Design decisions

Conventions that govern agent-side work:

1. **Ecosystem expansion before install-gate.** npm + NuGet scanners land first; install-gate follows.
2. **OSS ⊆ Enterprise.** Every feature in the `!enterprise` build is also in the `enterprise` build. Enterprise adds modes (upload, serve, cert bootstrap, signed-map trust) but never diverges the other way. Practically: shared helpers (e.g. `runOneShot`) live in un-tagged `.go` files used by both mains.
3. **Install-gate default is fail-open.** Policy unavailable ⇒ installs proceed with a loud log entry. Fail-closed is opt-in.
4. **Install-gate rolls out CLI-only first.** IDE plugins (VS Code, JetBrains) come later; core enforcement must stabilise before fanning out to IDE integrations.
5. **Install-gate emergency override is dashboard-driven.** Host-raises → admin-approves → signed scoped-override envelope. Reuses the existing signed-envelope primitive; no new admin-to-host trust path.
6. **Community CLI ships under Apache 2.0 AS IS.** No custom SLA; the standard no-warranty clause applies. SLAs attach only to Enterprise contracts.

---

## Planned

### Community CLI polish + OSS distribution (Size: M)

**Status:** Shipping — the first iteration is in:

- New `scanner/output` package with `Write(w, result, format)` supporting `json` / `csv` / `pretty` / `explain`.
- New `--explain` flag, a new `--format` value `pretty`, pretty-by-default on stdout, JSON-by-default when `--output` is a file.
- Shared `runOneShot` helper in `cmd/sentari-agent/oneshot.go` (no build tag) used by both the community and enterprise builds, so `--scan` / `--format` / `--explain` are available in both per the OSS ⊆ Enterprise decision.
- Explain mode surfaces recent-install highlights (packages installed in the last 48h), an AI-agent surface summary (MCP servers, Claude Code artefacts, IDE AI extensions), and an in-line scan-errors block capped at 10 items.

**Still on the backlog for the next CLI iteration:**

- Homebrew tap (see [§Homebrew tap](#homebrew-tap) below — promote from deferred when this block is scheduled).
- `curl | sh` install script symmetric with the Linux `install.sh` but aimed at laptops, not fleets.
- Sub-3-second default scan on a typical dev laptop (trimmed depth, skip high-entropy dirs like `node_modules`/`venv` by default).
- Dev-oriented README + CLI man page.

**Why:** A polished community CLI is the cheapest way to grow OSS adoption. Agent-side only — server unaffected.

### npm scanner plugin (Size: M)

**What:** New `scanner/npm/` plugin following the existing `Scanner` plugin pattern used by `scanner/jvm/` and `scanner/aiagents/` (self-registers at `init()`, produces `PackageRecord` values with a distinct `env_type`). Reads `node_modules/*/package.json` + `package-lock.json` + workspace manifests.

- Discoverer: walks from `ScanRoot`, marker-matches on `package.json` + `node_modules/`.
- Extractor: emits one PackageRecord per dependency with `EnvType="npm"`.
- Test fixtures: simple `node_modules`, workspace monorepo, pnpm hoisted, yarn-pnp.

**Why:** Ecosystem-agnostic coverage. npm is the ecosystem where most 2025–2026 supply-chain attacks landed (typosquats, maintainer hijacks).

**When:** Next sprint after community CLI polish ships.

### NuGet scanner plugin (Size: M)

**What:** `scanner/nuget/` plugin reading `~/.nuget/packages/<id>/<version>/<id>.nuspec` on Linux/macOS and `%UserProfile%\.nuget\packages\...` on Windows. Global-packages directory is the standard NuGet convention since v3.

**Why:** Broad .NET fleet coverage. Same plugin shape as npm — cheap once the npm one exists as a pattern.

**When:** After npm lands so the dispatch pattern is proven.

### Install-gate mode (Size: S for design, XL for impl)

**What:** Agent-resident enforcement layer that blocks disallowed installs before they land. Per-ecosystem wrappers (pip, npm, Maven, NuGet), signed policy delivery from server, company-wide configurable at install-time + server-push, local audit of every block, dashboard-driven emergency override, fail-mode (fail-open or fail-closed) selectable per policy-map.

**Status:** Shipping. The agent fetches the policy-map as a signed ed25519 envelope and verifies it against a pinned key (`scanner/install_gate.go`), per-ecosystem config writers consume the verified map, per-registry credentials are injected into each native config, and the agent reacts to the server's disable header by tearing down managed configs (see Recently shipped, 2026-05-04). Off by default; only fetches and applies when the operator enables `[install_gate]`.

**Decisions pinned for this work** (see Design decisions above):

- Fail-open default; fail-closed is opt-in.
- CLI rollout first; IDE plugins later.
- Emergency override flows through the dashboard, using the existing signed-envelope primitive.
- Configurability is layered: install-time config sets the trust anchor + initial enablement, server-push updates policy day-to-day, per-host emergency override is admin-granted + time-bounded.

### Offline malicious-package feed consumer (Size: M)

**What:** Agent-side consumer of the signed deny-list feed the server publishes (companion to the vuln-map push channel). Agent verifies signature against pinned pubkey learned at register-time, caches locally, applies as a detective rule.

**Prerequisite for install-gate** — the same feed becomes the preventive deny-list when the gate ships. Shipping this as detective-only first means the gate can reuse the verified cache path instead of rebuilding it.

**When:** After the server ships the signed deny-list feed endpoint.

### Safe Chain interop export (Size: S)

**What:** `sentari-agent --export-policy safechain` emits Sentari's deny/allow lists in a format Safe Chain (and similar ecosystem gates) can consume. No runtime dependency on any third-party tool; positions Sentari as the source of truth feeding whichever gate the customer chooses.

**When:** Customer-pull triggered. Not a priority until someone asks.

### `openat2 RESOLVE_BENEATH` primitive in `safeio` (Size: M)

**What:** Linux-specific defense-in-depth primitive for the container-scanner's layer walker. Today we drop all symlinks as a blanket rule; with `RESOLVE_BENEATH`, we can walk symlinks that stay inside the layer root and drop only those that escape. Closes the gap where a legitimate in-layer symlink (e.g. `/usr/bin/python3 → python3.12`) is invisible in container scans.

**Why:** Completeness for the container-scanning story, and a more defensible symlink-handling posture for security audits.

**When:** Low priority; blanket-drop is safe and matches what we ship today.

### CycloneDX VEX attachment (Size: M)

**What:** Emit VEX (Vulnerability-EXploitability-eXchange) statements alongside the existing CycloneDX SBOM output.

**Why:** CRA-relevant. Once a scan has `(package, cve, status=affected|not_affected|fixed|under_investigation)`, VEX is a 1:1 serialization.

---

## Deferred

### Signed macOS `.pkg` installer

**What:** Ship a proper Apple Developer ID signed and notarized `.pkg` installer alongside the current `install-macos.sh` script. The `.pkg` would:

- Copy `sentari-agent` to `/usr/local/bin`
- Create `/etc/sentari/` and `/var/lib/sentari/`
- Install and load the `dev.sentari.agent.plist` launchd daemon
- Be deployable via Jamf / Intune / Kandji as a standard package policy (no script wrapper needed)
- Install cleanly without any Gatekeeper warnings, xattr stripping, or manual approval
- Support silent uninstall via `pkgutil --forget` + payload manifest

**Why deferred:**

- Requires an **Apple Developer account** ($99/year recurring)
- Requires a **Developer ID Application certificate** + **Developer ID Installer certificate** generated through Apple's portal
- Notarization requires Apple ID credentials (or an App Store Connect API key) stored as GitHub Actions secrets
- Workflow complexity: ~300 lines to build, sign with `productbuild`, notarize with `xcrun notarytool`, staple with `xcrun stapler`, and upload
- Current unsigned `.sh` installer works fine for administrators pushing via MDM or Ansible — the `xattr -d com.apple.quarantine` trick is a well-known admin-approved path for internally-distributed binaries

**When to revisit:** when macOS-fleet demand or a specific compliance requirement justifies the recurring cost and workflow.

**Tracking:** No issue yet — create one (`feat(macos): signed and notarized .pkg installer`) when revisiting.

---

### Homebrew tap

**What:** Publish a `sentari-dev/homebrew-tap` repository containing a Formula file so users can install the agent with:

```bash
brew tap sentari-dev/tap
brew install sentari-agent
```

Homebrew handles the Gatekeeper quarantine attribute automatically, updates work like any other brew package (`brew upgrade sentari-agent`), and users don't need to know about version numbers or architectures.

**Why deferred:**

- Maintaining a separate `homebrew-tap` repo with a Formula that downloads and verifies each release
- Formula needs to be updated on every release (can be automated via a GitHub Action that bumps the SHA)
- Only useful once enough developers run the agent on personal Macs to justify it
- Current install-macos.sh path is sufficient for enterprise deployment

**When to revisit:** when Mac installs start happening outside controlled fleets — individual developers, contractors, OSS users who want a simpler install path.

**Tracking:** No issue yet — create one (`feat(macos): publish Homebrew tap`) when revisiting.

---

## Recently shipped

### JVM + containers + AI-agent (2026-04-23 / 2026-04-24)

- **JVM scanner plugin** — Maven caches, Gradle caches, JDK runtimes (OpenJDK/Oracle/Adoptium/Zulu/GraalVM), six app-servers (Tomcat, JBoss/WildFly/EAP, WebLogic, WebSphere, Jetty, GlassFish/Payara), shaded uber-jar + Spring Boot recursive descent.
- **Container-image scanner** — Docker/Podman/CRI-O discovery, virtual overlay walker with OCI whiteout semantics, per-container materialised merged rootfs, existing plugin registry dispatched against each. Opt-in via `[scanner] containers = true`.
- **Shadow-AI scanner** (`ai_agent` env_type) — MCP server configs (Claude Desktop, Cursor, Claude Code CLI), Claude Code agents/skills/plugins, AI-oriented IDE extensions (Copilot, Continue, Cody, Cline, Codeium, etc.). Filter allowlist to stay targeted.

### v0.1.1 — macOS support

- Added `darwin/amd64` and `darwin/arm64` to the release matrix
- `install-macos.sh`: installer mirroring the Linux `install.sh` and Windows `install.ps1`, configures agent as a `launchd` system daemon
- `docs/INSTALLATION.md`: macOS section with Quick Install, Ansible fleet deployment, Jamf/Intune/Kandji guidance, manual install path, one-shot scan path
