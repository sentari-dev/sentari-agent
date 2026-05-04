// Sentinel + helper for the server-side install-gate disable signal.
//
// When the Sentari server has install-gate disabled tenant-wide
// (system_config.install_gate.enabled = false, or
// SENTARI_INSTALL_GATE_ENABLED=false on a fresh-install fallback),
// /api/v1/agent/policy-map returns 404 with the response header
// X-Sentari-Install-Gate-Disabled: true.  This is intentionally
// distinguishable from a transient 404 — agents tear down host
// configs immediately rather than waiting for the existing 7-day
// fail-open grace window.

package comms

import (
	"errors"
	"net/http"
)

// ErrInstallGateServerDisabled is returned by FetchInstallGateMap
// when the server explicitly signals install-gate is disabled.
// Callers should treat this as "tear down host configs, persist a
// marker, do not retry until next cycle" — distinct from a transient
// 404 which triggers the existing 7-day fail-open path.
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
