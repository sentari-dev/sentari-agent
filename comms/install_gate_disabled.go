// Sentinel + helper for the server-side install-gate disable signal.
//
// When the Sentari server has install-gate disabled tenant-wide
// (system_config.install_gate.enabled = false, or
// SENTARI_INSTALL_GATE_ENABLED=false on a fresh-install fallback),
// /api/v1/agent/policy-map returns 404 with the response header
// X-Sentari-Install-Gate-Disabled: true.  This is intentionally
// distinguishable from a transient 404 — agents tear down host
// configs immediately. A plain/transient 404 or unreachable server,
// by contrast, leaves the last-good cached policy enforced (fail-closed).

package comms

import (
	"errors"
	"net/http"
)

// ErrInstallGateServerDisabled is returned by FetchInstallGateMap
// when the server explicitly signals install-gate is disabled.
// Callers should treat this as "tear down host configs, persist a
// marker, do not retry until next cycle" — distinct from a transient
// 404, which leaves the last-good cached policy enforced (fail-closed).
var ErrInstallGateServerDisabled = errors.New("install-gate disabled by server")

// isInstallGateServerDisabled reports whether a 404 response carries
// the explicit-disable header.  net/http canonicalises the header
// name on read; the value compare is case-sensitive ("true" only)
// to match the contract sentari serves.
func isInstallGateServerDisabled(resp *http.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		return false
	}
	return resp.Header.Get("X-Sentari-Install-Gate-Disabled") == "true"
}

// defaultInstallGateDisableThreshold is how many CONSECUTIVE disable
// responses must be observed across scan cycles before the agent tears
// down host package-manager configs.  Tearing down on a single 404 +
// X-Sentari-Install-Gate-Disabled header lets one transient or buggy
// server response wipe every managed host config fleet-wide; requiring
// a short streak makes the teardown deliberate without materially
// delaying a genuine tenant-wide disable (a few scan cycles).
const defaultInstallGateDisableThreshold = 3

// InstallGateDisableDebouncer debounces the server-side install-gate
// disable signal.  The caller (serve loop) feeds it the per-cycle
// outcome; teardown only fires once the disable signal has been seen
// on `threshold` consecutive cycles.  Any non-disable outcome resets
// the streak via Reset.
//
// The zero value is NOT ready — use NewInstallGateDisableDebouncer.
// Not safe for concurrent use; the serve loop is single-goroutine.
type InstallGateDisableDebouncer struct {
	threshold       int
	consecutive     int
	torndownAlready bool
}

// NewInstallGateDisableDebouncer returns a debouncer with the default
// consecutive-disable threshold.
func NewInstallGateDisableDebouncer() *InstallGateDisableDebouncer {
	return &InstallGateDisableDebouncer{threshold: defaultInstallGateDisableThreshold}
}

// Threshold returns the number of consecutive disable responses required
// before teardown.
func (d *InstallGateDisableDebouncer) Threshold() int { return d.threshold }

// RecordDisabled records one cycle that returned the server-disabled
// signal and reports whether teardown should now fire.  It returns true
// exactly once per disable streak — on the cycle the streak first reaches
// the threshold — so the caller doesn't repeat the (idempotent but noisy)
// teardown every subsequent disabled cycle.
func (d *InstallGateDisableDebouncer) RecordDisabled() bool {
	if d.torndownAlready {
		// Already torn down this streak; keep returning false until a
		// Reset (an enabled/healthy cycle) clears the latch.
		return false
	}
	d.consecutive++
	if d.consecutive >= d.threshold {
		d.torndownAlready = true
		return true
	}
	return false
}

// Reset clears the consecutive-disable streak.  Call on any cycle whose
// outcome is NOT the server-disabled signal (a healthy 200, a transient
// non-disable error, etc.) so a single blip cannot accumulate toward
// teardown across unrelated cycles.
func (d *InstallGateDisableDebouncer) Reset() {
	d.consecutive = 0
	d.torndownAlready = false
}
