// Pip / Python writer.
//
// The first ecosystem writer in Phase B.  pip.conf is the simplest
// of the supported ecosystems (one INI file, two settings) so it
// proves the end-to-end flow — cached signed envelope → rendered
// native config → blocked install — before we tackle Maven's XML
// merging, NuGet's package-source-clearing dance, or apt's GPG-
// keyring drop-ins.
//
// Scope:
//
//   - Honours ``proxy_endpoints["pypi"]`` from the policy-map.  An
//     empty endpoint is a no-op (Phase-A deployments where the
//     server has policies but no proxy URL configured).
//   - Writes both index-url and trusted-host (pip refuses to talk
//     to a non-PyPI HTTPS host without ``trusted-host`` even when
//     the cert chains to a system-trusted CA).
//   - Writes only the system-or-user config; never touches
//     virtualenv-local pip.conf because (a) walking every venv on
//     a host is racy with venv creation and (b) system/user config
//     applies regardless unless the venv explicitly overrides.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// PipScope is the precedence target for pip.conf.  ``user`` is the
// dev-laptop default; ``system`` is the server-host default.  The
// agent's config picks one — there's no "both" mode (pip's own
// precedence rules would resolve them, but writing two files
// doubles the audit surface for no real benefit).
type PipScope int

const (
	// PipScopeUser writes the per-user pip config:
	// ``~/.config/pip/pip.conf`` on Linux/macOS,
	// ``%APPDATA%\pip\pip.ini`` on Windows.
	PipScopeUser PipScope = iota

	// PipScopeSystem writes the system-wide pip config:
	// ``/etc/pip.conf`` on Linux/macOS, ``%ProgramData%\pip\pip.ini``
	// on Windows.
	PipScopeSystem
)

// PipPath returns the absolute pip-config path for the given scope
// on the running OS.  Returns an empty string when the path can't
// be derived (no ``HOME`` env var on Linux user-scope, no
// ``APPDATA`` env var on Windows).  Callers treat the empty case
// as "skip pip writer for this scope" and emit a typed warning.
func PipPath(scope PipScope) string {
	switch runtime.GOOS {
	case "windows":
		switch scope {
		case PipScopeUser:
			if dir := os.Getenv("APPDATA"); dir != "" {
				return filepath.Join(dir, "pip", "pip.ini")
			}
			return ""
		case PipScopeSystem:
			if dir := os.Getenv("ProgramData"); dir != "" {
				return filepath.Join(dir, "pip", "pip.ini")
			}
			// Hard-coded fallback: %ProgramData% defaults to
			// C:\ProgramData on every supported Windows version.
			return `C:\ProgramData\pip\pip.ini`
		}
	default: // linux, darwin, freebsd, …
		switch scope {
		case PipScopeUser:
			// XDG_CONFIG_HOME first, then ~/.config — same precedence
			// pip itself uses internally, so the writer ends up at
			// the same path pip will read from.
			if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
				return filepath.Join(xdg, "pip", "pip.conf")
			}
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, ".config", "pip", "pip.conf")
		case PipScopeSystem:
			return "/etc/pip.conf"
		}
	}
	return ""
}

// WritePipResult describes the outcome of one pip writer run.
// Returned per scope so the orchestrator can log a precise summary
// (e.g. "rewrote /etc/pip.conf, no change to ~/.config/pip/pip.conf").
type WritePipResult struct {
	// Path is the resolved final destination, or empty if the path
	// could not be derived for the running OS.
	Path string

	// Changed is true iff the file was created or its contents
	// differ from what was already there.  ``false`` covers both
	// the no-op case (idempotent re-write) and the no-policy-no-
	// proxy case (writer produced no file).
	Changed bool

	// Removed is true iff the writer removed an existing
	// Sentari-managed config (fail-open path: the policy-map no
	// longer points pip anywhere, so the agent should revert).
	Removed bool
}

// WritePip applies the pip section of a verified policy-map to the
// host.  Returns the resolved path + whether the file changed.
//
// Behaviour matrix:
//
//	+----------------------+--------------------+--------------------------+
//	| proxy_endpoints[pypi]| existing           | action                   |
//	+----------------------+--------------------+--------------------------+
//	| non-empty            | absent             | write fresh, marker+body |
//	| non-empty            | present            | rewrite (backup if body  |
//	|                      |                    |  differs)                |
//	| empty / missing      | absent             | no-op                    |
//	| empty / missing      | Sentari-managed    | remove (fail-open revert)|
//	| empty / missing      | operator-curated   | no-op (refuse to delete) |
//	+----------------------+--------------------+--------------------------+
//
// The fail-open ``remove`` branch is gated on the existing file
// carrying the Sentari marker — we never delete an operator-curated
// pip.conf that pre-dated install-gate enrolment, even if the
// policy-map drops the proxy URL.  Any pre-existing content on a
// host's first install-gate apply has already been preserved at
// ``<path>.sentari-backup-<timestamp>``; a Sentari-managed file is
// the only state we own and the only thing we'll remove.
//
// When ``PipPath`` cannot derive a target (no ``HOME`` on Linux
// user-scope, no ``APPDATA`` on Windows), the call is a soft no-op:
// returns ``(res, nil)`` with empty ``Path``.  The orchestrator
// inspects the result and logs a warning — a hard error here would
// crash the agent on a misconfigured host where pip simply isn't
// installed.
func WritePip(m *scanner.InstallGateMap, scope PipScope, marker MarkerFields) (WritePipResult, error) {
	res := WritePipResult{Path: PipPath(scope)}
	if res.Path == "" {
		// Soft no-op — the orchestrator logs and moves on.
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WritePip: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["pypi"])
	if endpoint == "" {
		// Fail-open: no proxy configured for pypi.  Remove only if
		// the existing file is Sentari-managed; never touch an
		// operator-curated pip.conf.  ``isSentariManaged`` returns
		// false for absent files, so a host that never had pip
		// configured stays inert.
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WritePip: inspect existing config: %w", err)
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

	body, err := renderPipConf(endpoint, marker)
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

// renderPipConf produces the bytes for the rendered pip.conf.
// Format matches design doc §4.1 — the marker block, then the
// ``[global]`` section with ``index-url`` and ``trusted-host``.
//
// We do NOT attempt to merge with an operator-curated pip.conf:
// the file we write is a complete Sentari-managed override.  The
// backup created on first write preserves any prior operator
// config; an operator who wants to keep their settings can disable
// install-gate at the agent level, which removes our file and
// surfaces the backup as a candidate restore.
func renderPipConf(endpoint string, marker MarkerFields) ([]byte, error) {
	// Defensive trim: a stray trailing newline in the proxy URL
	// from a hand-edited config would land mid-INI on the
	// ``index-url =`` line and break pip's parser.
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderPipConf: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderPipConf: %w", err)
	}

	host, err := hostOf(endpoint)
	if err != nil {
		return nil, fmt.Errorf("renderPipConf: derive host from endpoint: %w", err)
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	b.WriteString("[global]\n")
	fmt.Fprintf(&b, "index-url = %s\n", endpoint)
	fmt.Fprintf(&b, "trusted-host = %s\n", host)
	return []byte(b.String()), nil
}

// hostOf returns the bare host (no scheme, no port) of an endpoint
// URL.  Used for the ``trusted-host`` line.  Implemented
// without importing ``net/url`` because the parsing is trivial and
// we want stable error messages — net/url's errors include the
// full URL on failure, which would land in operator log files
// alongside whatever configuration secret happens to be embedded.
func hostOf(endpoint string) (string, error) {
	rest := endpoint
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(rest, scheme) {
			rest = rest[len(scheme):]
			break
		}
	}
	// Trim path / query.
	if i := strings.IndexAny(rest, "/?#"); i != -1 {
		rest = rest[:i]
	}
	// Trim port.  pip's ``trusted-host`` does NOT accept a port —
	// providing host:port silently downgrades to plain host but
	// emits a warning, which we'd rather avoid.
	if i := strings.LastIndex(rest, ":"); i != -1 {
		// Keep IPv6 literals (``[::1]:8080``) intact-up-to-port:
		// strip only when the remaining suffix is digits.
		port := rest[i+1:]
		if isAllDigits(port) {
			rest = rest[:i]
		}
	}
	if rest == "" {
		return "", fmt.Errorf("endpoint has no host component")
	}
	return rest, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
