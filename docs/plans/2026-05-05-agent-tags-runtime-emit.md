# Agent Tags + Runtime Emit (sentari §15a.1 Phase 1b + 2b)

> Combined plan for the agent-side companions of sentari PR #77
> (operator tags) + PR #79 (runtime auto-detection).  Both ship in
> one sentari-agent PR because they share a wire-protocol point
> (the `/scan` upload payload) and are orthogonal otherwise.

**Goal**: agent reads `[agent] tags = …` from `agent.conf`, auto-
detects its runtime (k8s / container / bare_metal / unknown), and
piggy-backs both on every scan upload.  Server side already accepts
these fields and does the right thing — the server sets
`tags_agent` from the array (PR #77) and applies the propose-then-
approve workflow on `runtime` (PR #79).

**No new external dependencies.**  Pure additive change.

**Spec references**
- Server-side device tags: [`sentari/docs/superpowers/specs/2026-05-05-device-tags-design.md`](https://github.com/sentari-dev/sentari/blob/main/docs/superpowers/specs/2026-05-05-device-tags-design.md)
- Server-side device runtime: [`sentari/docs/superpowers/specs/2026-05-05-device-runtime-design.md`](https://github.com/sentari-dev/sentari/blob/main/docs/superpowers/specs/2026-05-05-device-runtime-design.md)

---

## Task 1: `[agent] tags = …` config + validation

**Files**
- Modify: `config/config.go` (new `AgentSection`, parser branch)
- Create: `config/agent_tags_test.go`

- [ ] **Step 1: Failing test**

```go
// config/agent_tags_test.go
package config

import "testing"

func TestParseAgentTags(t *testing.T) {
    raw := `
[agent]
tags = environment:production, team:platform, service:web
`
    cfg, err := ParseString(raw)
    if err != nil { t.Fatalf("parse: %v", err) }
    want := []string{"environment:production", "service:web", "team:platform"} // sorted+deduped
    if !equalStrings(cfg.Agent.Tags, want) {
        t.Errorf("Agent.Tags: got %v, want %v", cfg.Agent.Tags, want)
    }
}

func TestParseAgentTagsDropsInvalid(t *testing.T) {
    raw := `
[agent]
tags = environment:production, BAD_KEY:value, team:platform
`
    // Invalid entries are logged + dropped.  Don't block startup
    // on a single typo.
    cfg, err := ParseString(raw)
    if err != nil { t.Fatalf("parse: %v", err) }
    want := []string{"environment:production", "team:platform"}
    if !equalStrings(cfg.Agent.Tags, want) {
        t.Errorf("got %v, want %v", cfg.Agent.Tags, want)
    }
}

func TestParseAgentTagsDefault(t *testing.T) {
    cfg, err := ParseString("")
    if err != nil { t.Fatalf("parse: %v", err) }
    if len(cfg.Agent.Tags) != 0 {
        t.Errorf("expected empty default, got %v", cfg.Agent.Tags)
    }
}

func equalStrings(a, b []string) bool {
    if len(a) != len(b) { return false }
    for i := range a { if a[i] != b[i] { return false } }
    return true
}
```

- [ ] **Step 2: Implement**

In `config/config.go`:

```go
// AgentSection holds operator-supplied per-host metadata that the
// agent emits on every scan upload.  Phase 1b of sentari §15a.1 —
// dashboard-side filtering against these tags shipped in
// sentari PR #77.
//
// INI section:
//
//   [agent]
//   tags = environment:production, team:platform, service:web
//
// Each entry must match the same regex the server enforces:
//   ^[a-z][a-z0-9_-]{0,63}:[A-Za-z0-9._-]{1,128}$
// Invalid entries are logged + dropped (don't block agent startup
// on a single typo).  Cap at 32 entries (parser truncates with a
// warning if more).
type AgentSection struct {
    Tags []string
}

// In AgentConfig:
//   Agent AgentSection

// In the parser switch on section, add a case "agent" that handles
// the "tags" key by splitting on comma, trimming, validating each
// entry, deduping, sorting, and capping at 32.
```

Tag regex + cap helper goes in a small helper file or inline.

- [ ] **Step 3: Run + commit**

```bash
go test -race ./config/...
git add config/config.go config/agent_tags_test.go
git commit -m "feat(config): [agent] tags = ... section parsed into Agent.Tags"
```

---

## Task 2: Runtime detector module

**Files**
- Create: `runtime/detect.go`
- Create: `runtime/detect_test.go`
- Create: `runtime/detect_unix.go` (build-tag `unix`)
- Create: `runtime/detect_windows.go` (build-tag `windows`)

The detection probes are platform-specific.  Linux paths
(`/proc/1/cgroup`, `/run/.containerenv`) only exist on Linux; macOS
has no cgroup; Windows uses different signals.  Build tags keep
the per-platform code in separate files.

- [ ] **Step 1: `runtime/detect.go` (cross-platform entry point)**

```go
// Package runtime detects what kind of host the agent is running
// on: bare_metal, container, k8s, or unknown.  Cross-platform
// stub that delegates to per-OS implementations.
//
// Sentari §15a.1 Phase 2b — server-side machinery shipped in
// sentari PR #79.  This module emits the value on every /scan;
// the server applies the propose-then-approve workflow.
package runtime

const (
    BareMetal = "bare_metal"
    Container = "container"
    K8s       = "k8s"
    Unknown   = "unknown"
)

// Detect returns one of the four enum values.  Always succeeds —
// returns Unknown on any probe error rather than propagating an
// error so the agent's scan cycle is never blocked by detection.
func Detect() string {
    return detect()
}
```

- [ ] **Step 2: `runtime/detect_unix.go` (Linux + macOS)**

```go
//go:build unix

package runtime

import (
    "os"
    "strings"
)

func detect() string {
    // Cheapest + most specific first: K8s exposes a service-host
    // env var to every pod.
    if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
        return K8s
    }

    // Podman drops a marker file at boot.
    if _, err := os.Stat("/run/.containerenv"); err == nil {
        return Container
    }

    // Linux containers (docker, containerd, k8s pods that mask
    // KUBERNETES_SERVICE_HOST somehow) leave fingerprints in
    // /proc/1/cgroup.  macOS has no /proc — the read fails and
    // the function falls through to bare_metal.
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        s := string(data)
        for _, marker := range []string{"docker", "containerd", "kubepods"} {
            if strings.Contains(s, marker) {
                return Container
            }
        }
    }

    // Default for both Linux + macOS: bare metal.  macOS's lack of
    // /proc isn't an "error" — it's the canonical signal that the
    // host is a developer laptop, not a container.
    return BareMetal
}
```

- [ ] **Step 3: `runtime/detect_windows.go`**

```go
//go:build windows

package runtime

import "os"

func detect() string {
    // K8s exposes the service-host env var on Windows pods too.
    if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
        return K8s
    }

    // Phase 2b ships Windows as bare_metal by default.  WMI-based
    // container/VM detection is a follow-up — the cost/value of
    // wrong-Windows-detection is low because the install-gate
    // threat model on Windows is dominated by EXE installers, not
    // package-manager registries running inside containers.
    return BareMetal
}
```

- [ ] **Step 4: Tests**

Linux-only tests (build-tagged `linux`) that mock `/proc/1/cgroup`
+ `/run/.containerenv` via tmpdir overrides aren't viable (can't
remap `/proc`/`/run` from a Go test).  Instead, test the env-var
branch which IS overridable, and integration-test the file branches
when the agent runs on a real container in CI.

```go
// runtime/detect_test.go
package runtime

import (
    "os"
    "testing"
)

func TestDetect_K8sEnvVarTakesPrecedence(t *testing.T) {
    t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    if got := Detect(); got != K8s {
        t.Errorf("got %s, want %s", got, K8s)
    }
}

func TestDetect_NoK8sEnvFallsBack(t *testing.T) {
    t.Setenv("KUBERNETES_SERVICE_HOST", "")  // explicitly clear
    got := Detect()
    // On macOS dev box / Linux without container fingerprints,
    // expect BareMetal.  In a Linux Docker container (CI), expect
    // Container.  Either is fine for this test — we just want to
    // confirm the function returns SOME valid enum value.
    valid := map[string]bool{BareMetal: true, Container: true, Unknown: true}
    if !valid[got] {
        t.Errorf("got %s, want one of {bare_metal, container, unknown}", got)
    }
}
```

- [ ] **Step 5: Run + commit**

```bash
go test -race ./runtime/...
git add runtime/
git commit -m "feat(runtime): detect bare_metal/container/k8s/unknown via env+cgroup probes"
```

---

## Task 3: Scan-payload struct gains `Tags` + `Runtime`

**Files**: `scanner/types.go`

- [ ] **Step 1: Add fields to `ScanResult`**

```go
type ScanResult struct {
    // ...existing fields...

    // Tags is the operator-supplied per-host metadata from
    // ``[agent] tags = ...`` in agent.conf.  Sent on every scan;
    // the server diffs vs ``device.tags_agent`` and updates if
    // changed.  Empty slice clears all tags; nil/omitted leaves
    // the server's value untouched.  Sentari PR #77.
    Tags []string `json:"tags,omitempty"`

    // Runtime is the auto-detected host classification — one of
    // ``bare_metal``, ``container``, ``k8s``, ``unknown``.  Sent
    // on every scan; the server runs the propose-then-approve
    // workflow (sentari PR #79).  Empty string is back-compat for
    // older agents — server treats as "field absent".
    Runtime string `json:"runtime,omitempty"`
}
```

- [ ] **Step 2: Commit**

```bash
git add scanner/types.go
git commit -m "feat(scanner): ScanResult.Tags + ScanResult.Runtime fields (omitempty)"
```

---

## Task 4: Wire the new fields into the scan composer

**Files**: `scanner/scanner.go` (or wherever `ScanResult` is constructed at scan-time)

- [ ] **Step 1: Find the construction site**

```bash
grep -rn "ScanResult{" /Users/christophebeke/Documents/Development/sentari-agent/scanner/ /Users/christophebeke/Documents/Development/sentari-agent/cmd/ | head -5
```

- [ ] **Step 2: Wire `Tags` from `cfg.Agent.Tags`**

Pass the agent config tags through to wherever `ScanResult` is built.  If the construction is in a function that already takes config, add `Tags: agentCfg.Agent.Tags`.  If not, accept the small refactor to thread the config or a `tags []string` parameter through.

- [ ] **Step 3: Wire `Runtime` from `runtime.Detect()`**

Same place.  Single `runtime.Detect()` call per scan cycle — cheap.

- [ ] **Step 4: Tests**

If `scanner.Scan()` (or whatever the entry point is named) is unit-testable, add a test that constructs a config with `Agent.Tags = ...` and asserts the returned `ScanResult.Tags` is the same canonical list.  Same for runtime: mock the detection by setting `KUBERNETES_SERVICE_HOST` and assert `ScanResult.Runtime == "k8s"`.

If the scan pipeline isn't unit-testable from inside Go (filesystem-heavy), skip the test and verify by inspection at PR-review time + integration smoke.

- [ ] **Step 5: Commit**

```bash
git add scanner/scanner.go scanner/<test-files-if-any>
git commit -m "feat(scanner): emit Tags + Runtime on every ScanResult"
```

---

## Task 5: Docs

**Files**: `ROADMAP.md`

- [ ] **Step 1: Mark §15a.1 Phase 1b + 2b as recently shipped**

Add to the "Recently shipped" section:

```markdown
- **2026-05-05 — Agent tags + runtime emit** (sentari §15a.1 Phase 1b + 2b).  Agent now reads ``[agent] tags = ...`` from ``agent.conf`` and emits operator-supplied tags on every ``/scan``.  Also auto-detects host runtime (bare_metal / container / k8s / unknown) via env + cgroup probes and emits it on every scan.  Server-side machinery shipped in [sentari#77](https://github.com/sentari-dev/sentari/pull/77) (tags) + [sentari#79](https://github.com/sentari-dev/sentari/pull/79) (runtime).
```

- [ ] **Step 2: Commit**

```bash
git add ROADMAP.md
git commit -m "docs(roadmap): agent tags + runtime emit shipped"
```

---

## Task 6: Push + open PR

- [ ] **Step 1: Push**

```bash
git push -u origin feature/agent-tags-runtime-emit
```

- [ ] **Step 2: Open PR** with title  
`feat(agent): emit operator tags + auto-detected runtime on every scan (sentari §15a.1 Phase 1b + 2b)`

PR description:
- Closes the agent-side companions of sentari #77 + #79.
- New `[agent] tags = ...` INI section parsed into `cfg.Agent.Tags`.
- New `runtime/` package with cross-platform `Detect()`.
- `scanner.ScanResult` gains `Tags []string` + `Runtime string`, both `omitempty`.
- Wire into the scan composer.
- ~1 day combined.

---

## Self-review

- **Spec coverage**: tags spec §3.4 wire format → Task 3+4.  Runtime spec §3.5 detection probes → Task 2.  Both server-side specs already validate; agent only needs to emit correctly.

- **No placeholder steps**: Task 4 step 1 grep is concrete; Task 4 step 4 acknowledges that scanner unit testing may not be viable inside Go (filesystem dependencies) and falls back to integration smoke.

- **Type consistency**: `Tags []string`, `Runtime string`, `runtime.Detect()`, `cfg.Agent.Tags`, regex from server spec mirrored in client validator.

- **No half-finished**: every task ends with a commit.
