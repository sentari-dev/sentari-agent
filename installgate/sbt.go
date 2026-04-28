// sbt writer — Scala build tool.
//
// sbt resolves Maven artifacts via the same Ivy/Aether layout
// gradle and Maven use; the user-level ``~/.sbt/repositories``
// file overrides every project's resolver list when present.  We
// own that file in its entirety because sbt's resolver-resolution
// is "first matching repositories file wins" — a Sentari-managed
// file at the user level shadows the bundled defaults and any
// project-local overrides for plugin resolution.
//
// Reads ``proxy_endpoints["maven"]`` since sbt's repository format
// shares the Maven artifact layout.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// SbtScope picks the user-level or system-level repositories file.
type SbtScope int

const (
	// SbtScopeUser writes ``~/.sbt/repositories``.  Same path on
	// every supported OS — sbt is JVM-portable.
	SbtScopeUser SbtScope = iota

	// SbtScopeSystem writes ``$SBT_HOME/conf/repositories``.
	// Returns empty (soft no-op) when ``SBT_HOME`` is not set —
	// sbt's install path varies across distros + sdkman / brew /
	// apt installs.
	SbtScopeSystem
)

// SbtPath returns the absolute repositories-file path for the
// given scope.  Empty return → soft no-op upstream.
func SbtPath(scope SbtScope) string {
	switch scope {
	case SbtScopeUser:
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		return filepath.Join(home, ".sbt", "repositories")
	case SbtScopeSystem:
		sh := os.Getenv("SBT_HOME")
		if sh == "" {
			return ""
		}
		return filepath.Join(sh, "conf", "repositories")
	}
	return ""
}

// WriteSbtResult mirrors the other writer-result shapes, plus
// SkippedOperator because ~/.sbt/repositories is operator-curate-
// able on hosts that already use sbt.
type WriteSbtResult struct {
	Path            string
	Changed         bool
	Removed         bool
	SkippedOperator bool
}

// WriteSbt applies the Maven section of the policy-map to sbt's
// repositories file.  Operator-curated files (no marker) are
// preserved — sbt repositories files commonly carry credentials
// for internal Artifactory hosts in their resolver URLs.
func WriteSbt(m *scanner.InstallGateMap, scope SbtScope, marker MarkerFields) (WriteSbtResult, error) {
	res := WriteSbtResult{Path: SbtPath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteSbt: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["maven"])
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteSbt: inspect existing config: %w", err)
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

	if _, err := os.Stat(res.Path); err == nil {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteSbt: inspect existing config: %w", err)
		}
		if !managed {
			res.SkippedOperator = true
			return res, nil
		}
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("installgate.WriteSbt: stat %s: %w", res.Path, err)
	}

	body, err := renderSbtRepositories(endpoint, marker)
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

// renderSbtRepositories produces the bytes for a fresh
// Sentari-managed sbt repositories file.  Format is:
//
//	[repositories]
//	sentari-proxy: <url>
//
// The ``[repositories]`` header is mandatory; without it sbt
// silently ignores the file and falls back to its baked-in
// defaults (which is the worst-case failure mode — operators
// would see no error and the gate would be inert).
func renderSbtRepositories(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderSbtRepositories: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderSbtRepositories: %w", err)
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	b.WriteString("\n[repositories]\n")
	fmt.Fprintf(&b, "sentari-proxy: %s\n", endpoint)
	return []byte(b.String()), nil
}
