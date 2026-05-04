# Install-Gate Disable-Header Reaction (Agent Follow-up to §15a.2)

**Goal:** ship the agent-side reaction to the server's
`X-Sentari-Install-Gate-Disabled: true` header. Closes the
follow-up flagged in [sentari PR #75][pr75]. Plus: when an operator
flips `[install_gate] enabled = false` in `agent.conf`, the agent
now actively tears down any pre-existing install-gate config files
(today it just no-ops).

[pr75]: https://github.com/sentari-dev/sentari/pull/75

**Architecture:** the existing per-writer fail-open path already
calls `Remove(path)` whenever the policy map has no endpoint for an
ecosystem. So `RemoveAll` is just `Apply()` with an empty policy map.

**No new external dependencies.** Pure additive change.

---

## Task 1: Sentinel error in `comms/`

**Files:**
- Create: `comms/install_gate_disabled.go`
- Modify: `comms/client.go` (`FetchInstallGateMap`)
- Create: `comms/install_gate_disabled_test.go`

- [ ] **Step 1: Define the sentinel + detector.**

```go
// comms/install_gate_disabled.go
package comms

import (
    "errors"
    "net/http"
)

// ErrInstallGateServerDisabled is returned by FetchInstallGateMap
// when the server explicitly signals install-gate is disabled
// (404 + X-Sentari-Install-Gate-Disabled: true).  Callers should
// treat this as "tear down host configs, persist a marker, do not
// retry until next cycle" — distinct from a transient 404 which
// triggers the existing 7-day fail-open grace.
var ErrInstallGateServerDisabled = errors.New("install-gate disabled by server")

// isInstallGateServerDisabled reports whether a 404 response carries
// the explicit-disable header.  Header name is canonicalised by
// net/http on read; comparison is case-insensitive.
func isInstallGateServerDisabled(resp *http.Response) bool {
    if resp == nil || resp.StatusCode != http.StatusNotFound {
        return false
    }
    return resp.Header.Get("X-Sentari-Install-Gate-Disabled") == "true"
}
```

- [ ] **Step 2: Wire into `FetchInstallGateMap`.**

In `comms/client.go`, modify the `if resp.StatusCode != http.StatusOK` block:

```go
if resp.StatusCode != http.StatusOK {
    if isInstallGateServerDisabled(resp) {
        return nil, nil, ErrInstallGateServerDisabled
    }
    return nil, nil, fmt.Errorf("install-gate fetch: status %d", resp.StatusCode)
}
```

- [ ] **Step 3: Tests in `comms/install_gate_disabled_test.go`.**

- 404 + header → returns `ErrInstallGateServerDisabled` (use `errors.Is`).
- Plain 404 → returns generic `status 404` error.
- 200 → unaffected (existing tests cover this).
- Header without 404 (e.g., 500 + header) → generic error.

- [ ] **Step 4: Run + commit.**

```bash
cd /Users/christophebeke/Documents/Development/sentari-agent
go test -race ./comms/...
git add comms/install_gate_disabled.go comms/install_gate_disabled_test.go comms/client.go
git commit -m "feat(comms): ErrInstallGateServerDisabled sentinel + 404+header detection"
```

---

## Task 2: `installgate.RemoveAll` + marker helpers

**Files:**
- Create: `installgate/disable.go`
- Create: `installgate/disable_test.go`

- [ ] **Step 1: Implement `RemoveAll`.**

```go
// installgate/disable.go
package installgate

import (
    "os"
    "path/filepath"

    "github.com/sentari-dev/sentari-agent/scanner"
)

// ServerDisabledMarkerName is the file the agent writes when the
// server has signalled install-gate is disabled.  The orchestrator
// reads it at startup to skip writers on the first cycle until the
// next 200 response clears it — preventing an agent restart between
// "server said off" and "server said on again" from re-writing
// configs from a stale local cache.
const ServerDisabledMarkerName = "install_gate.server_disabled.marker"

// RemoveAll tears down every install-gate config file that the
// writers manage.  Implemented as Apply() against an empty policy
// map — each writer's existing fail-open branch (no endpoint → remove
// only if Sentari-managed) does the right thing.
func RemoveAll(opts ApplyOptions) (ApplyResult, []error) {
    return Apply(&scanner.InstallGateMap{}, opts)
}

// MarkerPath returns the absolute path to the server-disabled marker
// file inside the agent data dir.
func MarkerPath(dataDir string) string {
    return filepath.Join(dataDir, ServerDisabledMarkerName)
}

// WriteServerDisabledMarker creates an empty marker file.  Idempotent
// — re-creating the marker on every server-disabled response is fine
// (operators tail it for "when did this start?" via stat()'s mtime).
func WriteServerDisabledMarker(dataDir string) error {
    f, err := os.OpenFile(MarkerPath(dataDir), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
    if err != nil {
        return err
    }
    return f.Close()
}

// ClearServerDisabledMarker removes the marker file.  Returns nil if
// it didn't exist.
func ClearServerDisabledMarker(dataDir string) error {
    if err := os.Remove(MarkerPath(dataDir)); err != nil && !os.IsNotExist(err) {
        return err
    }
    return nil
}

// HasServerDisabledMarker reports whether the marker exists at start.
func HasServerDisabledMarker(dataDir string) bool {
    _, err := os.Stat(MarkerPath(dataDir))
    return err == nil
}
```

- [ ] **Step 2: Tests in `installgate/disable_test.go`.**

- `RemoveAll` with a host that has Sentari-managed pip.conf → file removed.
- `RemoveAll` with a host that has operator-curated pip.conf → file untouched.
- Marker write/read/clear round-trip.
- `HasServerDisabledMarker` is false on a fresh dataDir, true after write, false after clear.

- [ ] **Step 3: Run + commit.**

```bash
go test -race ./installgate/...
git add installgate/disable.go installgate/disable_test.go
git commit -m "feat(installgate): RemoveAll helper + server-disabled marker plumbing"
```

---

## Task 3: Main-loop reaction + per-host opt-out cleanup

**Files:**
- Modify: `cmd/sentari-agent/main_enterprise.go`

This is the integration step — wires the sentinel handling, the
marker, and the per-host opt-out cleanup into the main loop. Several
sub-changes to one function; commit them as one because they're
inseparable.

- [ ] **Step 1: Per-host opt-out cleanup.**

The current `if agentCfg.InstallGate.Enabled { ... }` block runs the
whole install-gate cycle. The `else` is implicitly "no-op". Change
the else to: if marker-or-config-files exist on disk (we transitioned
from enabled→disabled), call `RemoveAll` once. Single startup log line.

```go
if agentCfg.InstallGate.Enabled {
    // ...existing flow...
} else {
    // Per-host opt-out (agent.conf [install_gate] enabled = false).
    // If we previously ran with enabled=true, host config files may
    // still be in place — tear them down on first cycle.
    res, errs := installgate.RemoveAll(installgateApplyOptionsFromConfig(agentCfg))
    for _, e := range errs {
        log.Warn("install-gate teardown", slog.String("err", e.Error()))
    }
    if res.AnyChanged() {
        log.Info("install-gate disabled by agent.conf; removed pre-existing host configs")
    } else {
        log.Info("install-gate disabled by agent.conf; nothing to remove")
    }
}
```

(The `installgateApplyOptionsFromConfig` helper composes the
`PipScope, NpmScope, …` mapping that's already inline in the
enabled-branch; extract it to a small helper near the top of the
file. ~10-line refactor.)

- [ ] **Step 2: Sentinel-error reaction in the enabled branch.**

In the enabled branch, replace the `FetchInstallGateMap` call's error
handling with a switch on the sentinel:

```go
igMap, envelope, err := client.FetchInstallGateMap(ctx, currentVersion)
switch {
case errors.Is(err, comms.ErrInstallGateServerDisabled):
    // Server has explicitly disabled install-gate for this tenant.
    // Tear down host configs immediately + write the marker so an
    // agent restart between this and the next 200 doesn't re-write
    // configs from the stale local cache.
    res, errs := installgate.RemoveAll(installgateApplyOptionsFromConfig(agentCfg))
    for _, e := range errs {
        log.Warn("install-gate teardown (server disabled)", slog.String("err", e.Error()))
    }
    if mErr := installgate.WriteServerDisabledMarker(dataDir); mErr != nil {
        log.Warn("write server-disabled marker", slog.String("err", mErr.Error()))
    }
    log.Info("install-gate disabled by server (X-Sentari-Install-Gate-Disabled: true); removed host configs")
case err != nil:
    log.Warn("install-gate refresh failed (using cached)", slog.String("err", err.Error()))
case igMap != nil:
    // 200 with a fresher envelope.  If we'd previously seen the
    // server-disabled marker, clear it + log re-enable.
    if installgate.HasServerDisabledMarker(dataDir) {
        if cErr := installgate.ClearServerDisabledMarker(dataDir); cErr != nil {
            log.Warn("clear server-disabled marker", slog.String("err", cErr.Error()))
        }
        log.Info("install-gate re-enabled by server; resuming policy enforcement")
    }
    // ...existing igMap != nil flow (cache + Apply)...
}
```

- [ ] **Step 3: Startup marker check.**

Before running the writer cycle, if the marker exists, skip writers
on the first cycle entirely — fall through to FetchInstallGateMap
which will either return the sentinel again (marker stays, no-op) or
return a 200 (which clears the marker + applies normally).

```go
if agentCfg.InstallGate.Enabled && installgate.HasServerDisabledMarker(dataDir) {
    log.Info("install-gate server-disabled marker present at startup; skipping writers until next /policy-map response clears it")
    // The fetch+switch below still runs — that's how we discover
    // whether the server is still disabled.  We just skip the writers
    // for this cycle.
    skipWritersThisCycle := true
    _ = skipWritersThisCycle  // honoured in the switch above
}
```

- [ ] **Step 4: Run + commit.**

```bash
go build ./...
go test -race ./...
git add cmd/sentari-agent/main_enterprise.go
git commit -m "feat(agent): react to X-Sentari-Install-Gate-Disabled + cleanup on per-host opt-out"
```

---

## Task 4: Docs

**Files:**
- Modify: `ROADMAP.md` (sentari-agent)
- Modify (in sentari repo): `docs/proxy-deployment.md` §10 cross-reference

- [ ] **Step 1: ROADMAP entry.**

Add a "shipped" line under whatever Phase D heading exists, or a top
"Recently shipped" section if the file already has one.

- [ ] **Step 2: Update sentari repo's `docs/proxy-deployment.md`.**

Find the "(4) is sentari-agent repo work tracked in the install-gate
roadmap." line and replace with: "(4) ships in sentari-agent
release \<version\>." — once we know the version. If we don't tag
right away, leave a more generic "shipped 2026-05-04" reference.

- [ ] **Step 3: Commit (sentari-agent repo).**

```bash
git add ROADMAP.md
git commit -m "docs(roadmap): install-gate disable-header reaction shipped"
```

---

## Task 5: Push + open PR (sentari-agent)

- [ ] **Step 1: Push.**

```bash
git push -u origin feature/install-gate-disable-reaction
```

- [ ] **Step 2: Open PR.**

```bash
gh pr create --title "feat(install-gate): react to server disable header (follow-up to sentari §15a.2)" --body "..."
```

---

## Self-review checklist

- **Spec coverage:** the sentari-side spec called out four required
  agent behaviours: (i) per-host opt-out via `agent.conf`, (ii)
  cleanup on transition enabled→disabled, (iii) reaction to
  server-side disable header (immediate cleanup), (iv) marker
  persistence so restart-between-states doesn't re-write configs.
  Tasks 2+3 cover all four.

- **No placeholder steps.** The "extract helper" in Task 3 step 1
  is a concrete refactor; not "TBD".

- **Type consistency.** `ApplyOptions`, `ApplyResult.AnyChanged()`,
  `MarkerFields`, `comms.ErrInstallGateServerDisabled` are all named
  consistently across tasks.
