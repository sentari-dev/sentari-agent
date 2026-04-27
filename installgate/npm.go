// npm / Node.js writer.
//
// Second ecosystem after pip.  ``.npmrc`` is structurally the
// simplest of the supported configs — flat ``key=value`` without
// section headers, no ``trusted-host`` equivalent (npm trusts any
// host whose TLS chain validates), and no port-stripping
// considerations (npm honours ports in registry URLs natively).
//
// Scope (design doc §4.2):
//
//   - Honours ``proxy_endpoints["npm"]`` from the policy-map.
//   - Writes only the top-level ``registry=`` setting.  Scoped-
//     registry mappings (``@vendor:registry=...``) are explicitly
//     deferred until a customer asks — the policy-map shape would
//     need a per-scope sub-field that doesn't exist yet.
//   - User scope (``~/.npmrc``) on Linux/macOS/Windows is the
//     dev-laptop default; system scope (``/etc/npmrc``) lands on
//     server hosts.  npm's per-project ``.npmrc`` overrides both
//     and we deliberately do NOT walk repos to write project-local
//     files (would be racy with repo creation + clone).

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// NpmScope picks ``user`` or ``system`` ``.npmrc``.  Same defaulting
// story as ``PipScope``: zero-value → user (laptop default).
type NpmScope int

const (
	// NpmScopeUser writes ``~/.npmrc`` on every supported OS.
	NpmScopeUser NpmScope = iota

	// NpmScopeSystem writes ``/etc/npmrc`` on Linux/macOS.  npm's
	// "system"-level config on Windows is install-prefix-relative
	// (``${prefix}\etc\npmrc``) and the prefix moves around per
	// install method (msi / chocolatey / nvm-windows); ``NpmPath``
	// returns empty on Windows for system scope and the writer
	// becomes a soft no-op rather than guessing wrong.
	NpmScopeSystem
)

// NpmPath returns the absolute ``.npmrc`` path for the given scope
// on the running OS.  Empty return signals "skip" — the caller
// short-circuits to a soft no-op the same way ``WritePip`` does
// for un-derivable paths.
func NpmPath(scope NpmScope) string {
	switch scope {
	case NpmScopeUser:
		// npm uses ``$HOME/.npmrc`` uniformly.  On Windows
		// ``os.UserHomeDir`` consults USERPROFILE, which is what
		// npm itself reads.
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		return filepath.Join(home, ".npmrc")
	case NpmScopeSystem:
		switch runtime.GOOS {
		case "windows":
			// npm's Windows "global" prefix is non-stable across
			// install methods; refuse rather than write to a path
			// npm won't read.  Operators on Windows should use
			// user-scope.
			return ""
		default:
			return "/etc/npmrc"
		}
	}
	return ""
}

// WriteNpmResult mirrors ``WritePipResult`` — same shape so the
// orchestrator log emits structurally-identical lines per
// ecosystem.
type WriteNpmResult struct {
	Path    string
	Changed bool
	Removed bool
}

// WriteNpm applies the npm section of a verified policy-map to
// the host.  Behaviour matrix matches ``WritePip``:
//
//	+----------------------+--------------------+--------------------------+
//	| proxy_endpoints[npm] | existing           | action                   |
//	+----------------------+--------------------+--------------------------+
//	| non-empty            | absent             | write fresh, marker+body |
//	| non-empty            | present            | rewrite (backup if body  |
//	|                      |                    |  differs)                |
//	| empty / missing      | absent             | no-op                    |
//	| empty / missing      | Sentari-managed    | remove (fail-open revert)|
//	| empty / missing      | operator-curated   | no-op (refuse to delete) |
//	+----------------------+--------------------+--------------------------+
//
// The Sentari-managed gate on the fail-open ``remove`` branch is
// the same as pip's: an operator-curated ``.npmrc`` (auth tokens
// for private registries, custom cache locations) MUST survive
// install-gate disablement intact.
func WriteNpm(m *scanner.InstallGateMap, scope NpmScope, marker MarkerFields) (WriteNpmResult, error) {
	res := WriteNpmResult{Path: NpmPath(scope)}
	if res.Path == "" {
		// Soft no-op — orchestrator logs and moves on.
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteNpm: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["npm"])
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteNpm: inspect existing config: %w", err)
		}
		if !managed {
			return res, nil
		}
		removed, err := Remove(res.Path)
		if err != nil {
			return res, err
		}
		res.Removed = removed
		return res, nil
	}

	body, err := renderNpmrc(endpoint, marker)
	if err != nil {
		return res, err
	}

	changed, err := WriteAtomic(WriteOptions{
		Path:     res.Path,
		Content:  body,
		FileMode: 0o644,
		Now:      marker.Applied,
	})
	if err != nil {
		return res, err
	}
	res.Changed = changed
	return res, nil
}

// renderNpmrc produces the bytes for the rendered ``.npmrc``.
// Format per design doc §4.2 — marker block then a single
// ``registry=<url>`` line.  No ``[global]`` (npm config has no
// sections).  Token-bearing settings (``//registry/:_authToken``)
// are deliberately NOT touched; the operator's pre-existing tokens
// for internal registries are preserved in the
// ``.sentari-backup-*`` file the writer creates on first overwrite.
func renderNpmrc(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderNpmrc: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderNpmrc: %w", err)
	}
	// npm's registry URL must end with ``/`` — npm appends paths
	// directly to it without inserting a separator, so a missing
	// trailing slash silently breaks tarball lookups.  Add one if
	// the operator forgot.
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	fmt.Fprintf(&b, "registry=%s\n", endpoint)
	return []byte(b.String()), nil
}
