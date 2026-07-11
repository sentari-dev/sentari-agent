# Sentari Agent Roadmap

Living document tracking deferred work and future improvements. Items here are intentional — they were evaluated and postponed with a reason, not forgotten. Remove an item when it ships or when the decision is revisited and closed out.

Server-side work is tracked separately in the server repository.

**Sizes:** S ≤ 3 days, M ≤ 1.5 weeks, L ≤ a full sprint, XL multi-sprint.

---

## Engineering conventions

A few standing rules that shape how items below are built. They are plain conventions, not one-off decisions:

- **OSS ⊆ Enterprise build.** Every feature in the `!enterprise` build is also in the `enterprise` build. Enterprise adds modes (upload, serve, cert bootstrap, signed-map trust) but never diverges the other way. Practically: shared helpers (e.g. `runOneShot` in `cmd/sentari-agent/oneshot.go`) live in un-tagged `.go` files used by both mains, so flags like `--scan` / `--format` / `--explain` are available in both builds.
- **Install-gate defaults to fail-open.** When policy is unavailable, installs proceed with a loud log entry. Fail-closed is opt-in per policy-map.
- **Install-gate rolls out CLI-first.** Core enforcement must stabilise on the CLI before any IDE integrations (VS Code, JetBrains) are considered.

---

## Recently shipped

- **npm scanner plugin** (`scanner/npm/`). Self-registering `Scanner` plugin following the same shape as `scanner/jvm/` and `scanner/aiagents/`. Discovers `node_modules` during the shared filesystem walk and emits one `PackageRecord` per package (`env_type="npm"`). Covers npm classic, yarn classic, pnpm `shamefully-hoist` mode, scoped packages, and the nested version-conflict layout (bounded recursion). Server-side ecosystem mapping: `env_type="npm" → ecosystem="npm"` (OSV / PURL convention). Known v1 gaps (pnpm default mode, Yarn PnP) are tracked under Backlog below.
- **NuGet scanner plugin** (`scanner/nuget/`). Reads the global-packages directory — `~/.nuget/packages/<id>/<version>/<id>.nuspec` on Linux/macOS and `%UserProfile%\.nuget\packages\...` on Windows (the standard NuGet convention since v3). Same plugin shape as npm.
- **Install-gate enforcement** (`scanner/install_gate.go`). Agent-resident enforcement layer that blocks disallowed installs before they land. The agent fetches the policy-map as a signed ed25519 envelope, verifies it against a pinned key, and per-ecosystem config writers consume the verified map (with per-registry credentials injected into each native config). Off by default; only fetches and applies when the operator enables `[install_gate]`. Fail-open by default, fail-closed opt-in. Emergency override is dashboard-driven (host raises → admin approves → signed scoped-override envelope, reusing the existing signed-envelope primitive). See the install-gate disable-reaction item below for teardown behaviour.
- **2026-05-05 — Agent tags + runtime emit.** Agent now reads `[agent] tags = …` from `agent.conf` and emits operator-supplied tags on every `/scan`. Also auto-detects host runtime (`bare_metal` / `container` / `k8s` / `unknown`) via env + cgroup probes and emits it on every scan. Plan: [`docs/plans/2026-05-05-agent-tags-runtime-emit.md`](docs/plans/2026-05-05-agent-tags-runtime-emit.md).
- **2026-05-04 — Install-gate disable-header reaction.** Agent reacts to the server's `X-Sentari-Install-Gate-Disabled: true` response on `/policy-map` by tearing down host configs immediately and persisting a marker so a process restart between disable and re-enable doesn't re-write configs from a stale local cache. When an operator flips `[install_gate] enabled = false` in `agent.conf`, the agent actively removes any pre-existing Sentari-managed configs (previously it no-op'd until the fail-open grace expired). Plan: [`docs/plans/2026-05-04-install-gate-disable-reaction.md`](docs/plans/2026-05-04-install-gate-disable-reaction.md).
- **Community CLI output package** (`scanner/output`). `Write(w, result, format)` supporting `json` / `csv` / `pretty` / `explain`; a `--explain` flag; a `pretty` `--format` value (pretty-by-default on stdout, JSON-by-default when `--output` is a file). Explain mode surfaces recent-install highlights (packages installed in the last 48h), an AI-agent surface summary (MCP servers, Claude Code artefacts, IDE AI extensions), and an in-line scan-errors block capped at 10 items.

### Earlier releases

**Sprint 17 — JVM + containers + AI-agent (2026-04-23 / 2026-04-24)**

- **JVM scanner plugin** — Maven caches, Gradle caches, JDK runtimes (OpenJDK/Oracle/Adoptium/Zulu/GraalVM), six app-servers (Tomcat, JBoss/WildFly/EAP, WebLogic, WebSphere, Jetty, GlassFish/Payara), shaded uber-jar + Spring Boot recursive descent. Landed across PRs #5–#10.
- **Container-image scanner** — Docker/Podman/CRI-O discovery, virtual overlay walker with OCI whiteout semantics, per-container materialised merged rootfs, existing plugin registry dispatched against each. Opt-in via `[scanner] containers = true`. Landed across PRs #11–#13.
- **Shadow-AI scanner** (`ai_agent` env_type) — MCP server configs (Claude Desktop, Cursor, Claude Code CLI), Claude Code agents/skills/plugins, AI-oriented IDE extensions (Copilot, Continue, Cody, Cline, Codeium, etc.). Filter allowlist to stay targeted. Landed as PR #14.

**v0.1.1 — macOS support**

- Added `darwin/amd64` and `darwin/arm64` to the release matrix.
- `install-macos.sh`: installer mirroring the Linux `install.sh` and Windows `install.ps1`, configures agent as a `launchd` system daemon.
- `docs/INSTALLATION.md`: macOS section with Quick Install, Ansible fleet deployment, Jamf/Intune/Kandji guidance, manual install path, one-shot scan path.

---

## Backlog

### npm: pnpm default mode + Yarn PnP support (Size: M)

**What:** Close the two known npm v1 coverage gaps documented in the `scanner/npm` package doc.

- **pnpm default mode.** In pnpm's default layout, `node_modules/<pkg>` is a symlink into `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>`. The plugin currently skips symlinked directory entries during its walk, so those packages produce no records. The fix wants an `openat2 RESOLVE_BENEATH` primitive in `safeio` plus a resolve-then-verify path that keeps the symlink target inside the `node_modules` root. Until then, operators can set `shamefully-hoist=true` in `.npmrc`.
- **Yarn Plug'n'Play.** Yarn PnP ships a generated `.pnp.cjs` manifest with bundled packages instead of a `node_modules` tree. Supporting it means parsing that generated JS manifest — its own sprint of work.

**When:** On demand — prioritise when pnpm-default or PnP fleets show up in scan telemetry or a deployment needs the coverage.

### `openat2 RESOLVE_BENEATH` primitive in `safeio` (Size: M)

**What:** Linux-specific defense-in-depth primitive shared by the container-scanner's layer walker and the npm pnpm-default fix above. Today the container walker drops all symlinks as a blanket rule; with `RESOLVE_BENEATH`, it can walk symlinks that stay inside the layer root and drop only those that escape. Closes the "legitimate `/usr/bin/python3 → python3.12` symlink is invisible in container scans" gap.

**Why:** Completeness for the container-scanning story, and the enabling primitive for pnpm default-mode support. Blanket-drop is safe and matches what we ship today, so this is low priority.

### Offline malicious-package feed consumer (Size: M)

**What:** Agent-side consumer of the signed deny-list feed the server publishes (companion to the vuln-map push channel). Agent verifies the signature against a pinned pubkey learned at register-time, caches locally, and applies it as a detective rule. Shipping this detective-only first means the install-gate can later reuse the verified cache path as its preventive deny-list instead of rebuilding it.

**When:** After the server ships the signed deny-list feed endpoint.

### Ecosystem-gate interop export (Size: S)

**What:** `sentari-agent --export-policy <format>` emits Sentari's deny/allow lists in a format that third-party ecosystem gates can consume, positioning Sentari as the source of truth that feeds whatever gate a customer already runs. No runtime dependency on any external tool.

**When:** On demand — not a priority until a deployment asks for it.

### CycloneDX VEX attachment (Size: M)

**What:** Emit VEX (Vulnerability-EXploitability-eXchange) statements alongside the existing CycloneDX SBOM output.

**Why:** CRA-relevant. Once a scan has `(package, cve, status=affected|not_affected|fixed|under_investigation)`, VEX is a 1:1 serialization.

**When:** Tied to the corresponding server-side status work.

### Community CLI polish (Size: M)

Next iteration of the community CLI beyond the shipped output package:

- Homebrew tap (see Deferred below — promote when this block is scheduled).
- `curl | sh` install script symmetric with the Linux `install.sh` but aimed at individual laptops, not fleets.
- Sub-3-second default scan on a typical dev laptop (trimmed depth, skip high-entropy dirs like `node_modules`/`venv` by default).
- Dev-oriented README + CLI man page.

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

- Requires an **Apple Developer account** and both a **Developer ID Application certificate** and a **Developer ID Installer certificate** generated through Apple's portal.
- Notarization requires Apple ID credentials (or an App Store Connect API key) stored as GitHub Actions secrets.
- Workflow complexity: ~300 lines to build, sign with `productbuild`, notarize with `xcrun notarytool`, staple with `xcrun stapler`, and upload.
- The current unsigned `.sh` installer works fine for administrators pushing via MDM or Ansible — the `xattr -d com.apple.quarantine` trick is a well-known admin-approved path for internally-distributed binaries.

**When to revisit:** On demand — when a deployment requests it for compliance reasons, or when macOS fleet usage grows enough to justify the recurring cost and workflow.

**Tracking:** No issue yet — create one (`feat(macos): signed and notarized .pkg installer`) when revisiting.

### Homebrew tap

**What:** Publish a `homebrew-tap` repository containing a Formula file so users can install the agent with:

```bash
brew tap sentari-dev/tap
brew install sentari-agent
```

Homebrew handles the Gatekeeper quarantine attribute automatically, updates work like any other brew package (`brew upgrade sentari-agent`), and users don't need to know about version numbers or architectures.

**Why deferred:**

- Maintaining a separate `homebrew-tap` repo with a Formula that downloads and verifies each release.
- The Formula needs updating on every release (automatable via a GitHub Action that bumps the SHA).
- Only useful once the agent is installed outside controlled fleets — individual developers, contractors, OSS users who want a simpler install path.
- The current `install-macos.sh` path is sufficient for enterprise deployment.

**When to revisit:** On demand — when Mac installs start happening outside controlled fleets and a simpler install path is in demand.

**Tracking:** No issue yet — create one (`feat(macos): publish Homebrew tap`) when revisiting.
