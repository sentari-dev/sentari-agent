# Sentari Agent Roadmap

Living document tracking deferred work and future improvements. Items here are intentional — they were evaluated and postponed with a reason, not forgotten. Remove an item when it ships or when the decision is revisited and closed out.

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

**When to revisit:**

- When we have **5+ paying customers** deploying on macOS fleets
- OR when any single customer explicitly requests it for compliance reasons
- OR when internal Mac usage at Sentari itself exceeds ~20 devices

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
- Only useful if we expect more than a handful of developers using the agent on their personal Macs
- Current install-macos.sh path is sufficient for enterprise deployment

**When to revisit:**

- When Mac installs start happening **outside controlled fleets** — individual developers, contractors, OSS users who want a simpler install path
- OR when our OSS traffic on macOS exceeds ~100 downloads/month and we start getting "why not brew?" questions

**Tracking:** No issue yet — create one (`feat(macos): publish Homebrew tap`) when revisiting.

---

## Recently shipped

### v0.1.1 — macOS support

- Added `darwin/amd64` and `darwin/arm64` to the release matrix
- `install-macos.sh`: installer mirroring the Linux `install.sh` and Windows `install.ps1`, configures agent as a `launchd` system daemon
- `docs/INSTALLATION.md`: macOS section with Quick Install, Ansible fleet deployment, Jamf/Intune/Kandji guidance, manual install path, one-shot scan path
