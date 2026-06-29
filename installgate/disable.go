// Disable-side helpers: tearing down host configs when install-gate
// is turned off (either per-host via agent.conf, or tenant-wide via
// the server's X-Sentari-Install-Gate-Disabled response header).
//
// The per-writer fail-open path already does the right thing when
// the policy map has no endpoint for an ecosystem (Remove the
// Sentari-managed file; never touch operator-curated files).  So
// "remove all" reduces to "Apply with an empty policy map" — every
// writer hits its own no-endpoint branch.

package installgate

import (
	"os"
	"path/filepath"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// ServerDisabledMarkerName is the file the agent writes when the
// server has signalled install-gate is disabled tenant-wide
// (X-Sentari-Install-Gate-Disabled: true).  Read at startup so an
// agent restart between "server said off" and the next 200 doesn't
// re-write configs from the local cache while the server is still
// telling everyone to back off.
const ServerDisabledMarkerName = "install_gate.server_disabled.marker"

// RemoveAll tears down every install-gate config file managed by
// any writer.  Implemented via Apply against an empty policy map so
// each writer hits its own existing fail-open branch (no endpoint →
// remove only if Sentari-managed; never touch operator-curated
// files).  Returns the same per-ecosystem result struct + error
// slice as Apply so callers get identical structured-log shape.
func RemoveAll(opts ApplyOptions) (ApplyResult, []error) {
	return Apply(&scanner.InstallGateMap{}, opts)
}

// MarkerPath returns the absolute path to the server-disabled
// marker file inside the agent data dir.  No directory creation —
// callers ensure dataDir exists before invoking marker writers.
func MarkerPath(dataDir string) string {
	return filepath.Join(dataDir, ServerDisabledMarkerName)
}

// WriteServerDisabledMarker creates the marker file (mode 0600).
// Idempotent — re-creating on every server-disabled response is
// fine; operators tail the file's mtime to learn "when did this
// start?".
func WriteServerDisabledMarker(dataDir string) error {
	f, err := os.OpenFile(MarkerPath(dataDir), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// ClearServerDisabledMarker removes the marker.  Returns nil when
// the file is already absent (idempotent re-clear is fine on every
// 200 response).
func ClearServerDisabledMarker(dataDir string) error {
	if err := os.Remove(MarkerPath(dataDir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// HasServerDisabledMarker reports whether the marker exists.  Used
// to decide whether the agent should force a full /policy-map
// fetch this cycle (so the next 200 reliably clears the marker).
//
// Fail-safe semantics: any stat error other than os.ErrNotExist —
// e.g., a permission/IO error after the operator chowned the
// data dir — is treated as "marker present".  Reasoning: when
// we can't tell whether the marker exists, treating it as
// present means we err on the side of forcing a fresh fetch
// (cheap, idempotent) rather than re-applying configs we may
// already have torn down.
func HasServerDisabledMarker(dataDir string) bool {
	if _, err := os.Stat(MarkerPath(dataDir)); err == nil {
		return true
	} else if !os.IsNotExist(err) {
		// Stat failed for some reason other than "file absent" —
		// e.g., permission denied on the data dir.  Fail-safe: treat
		// as marker-present so we force a fresh fetch this cycle.
		return true
	}
	return false
}
