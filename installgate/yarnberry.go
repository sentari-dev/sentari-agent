// Yarn Berry writer — Yarn 2 / 3 / 4.
//
// Yarn classic (1.x) reads ``.npmrc`` and is therefore covered by
// the npm writer (PR-4).  Yarn Berry (2+) does NOT read ``.npmrc``
// — it has its own ``.yarnrc.yml`` config namespace.  Without a
// dedicated writer, yarn-berry projects on a host bypass the
// install-gate even when npm is fully gated.  This is the same
// class of gap as uv/pdm on the Python side.
//
// Reads ``proxy_endpoints["npm"]`` since yarn-berry consumes the
// npm registry layout.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// YarnBerryScope picks the user-level config.  Yarn berry has no
// system-wide config path — its config-cascade is per-project
// then per-user — so YarnBerryScopeSystem is a soft no-op kept
// for symmetry with the other scope enums.
type YarnBerryScope int

const (
	// YarnBerryScopeUser writes ``~/.yarnrc.yml``.  Same path on
	// every supported OS.
	YarnBerryScopeUser YarnBerryScope = iota

	// YarnBerryScopeSystem soft-no-ops (Yarn Berry has no
	// system-wide config path).
	YarnBerryScopeSystem
)

// YarnBerryPath returns the absolute ``.yarnrc.yml`` path.
// Empty return → soft no-op upstream.
func YarnBerryPath(scope YarnBerryScope) string {
	if scope == YarnBerryScopeSystem {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".yarnrc.yml")
}

// WriteYarnBerryResult — same shape as the other writer-result
// types.  ``.yarnrc.yml`` commonly carries operator-curated
// settings (custom resolution behaviour, plugin config, scoped
// registry tokens) so the SkippedOperator guard applies.
type WriteYarnBerryResult struct {
	Path            string
	Changed         bool
	Removed         bool
	SkippedOperator bool
}

// WriteYarnBerry applies the npm section of the policy-map to
// yarn berry's ``.yarnrc.yml``.  Operator-curated files are
// preserved.
func WriteYarnBerry(m *scanner.InstallGateMap, scope YarnBerryScope, marker MarkerFields) (WriteYarnBerryResult, error) {
	res := WriteYarnBerryResult{Path: YarnBerryPath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteYarnBerry: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["npm"])
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteYarnBerry: inspect existing config: %w", err)
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
			return res, fmt.Errorf("installgate.WriteYarnBerry: inspect existing config: %w", err)
		}
		if !managed {
			res.SkippedOperator = true
			return res, nil
		}
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("installgate.WriteYarnBerry: stat %s: %w", res.Path, err)
	}

	body, err := renderYarnrcYML(endpoint, marker)
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

// renderYarnrcYML produces a fresh Sentari-managed
// ``.yarnrc.yml``.  YAML is whitespace-sensitive so we keep the
// rendered file flat (top-level mappings only) and emit a
// trailing newline.  ``npmRegistryServer`` is yarn-berry's
// equivalent of npm's ``registry=`` setting; ``npmAlwaysAuth``
// matches npm's ``always-auth`` so internal-CA proxies don't
// fall back to anonymous resolution.
//
// YAML rules: the URL value is double-quoted so YAML treats it as
// a plain scalar regardless of embedded ``:`` characters (which
// otherwise terminate a mapping key).
func renderYarnrcYML(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderYarnrcYML: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderYarnrcYML: %w", err)
	}
	// YAML double-quoted strings honour backslash escapes; an
	// embedded ``"`` would terminate the string and let an attacker
	// smuggle additional YAML keys.
	if strings.ContainsAny(endpoint, "\"\\") {
		return nil, fmt.Errorf("renderYarnrcYML: endpoint contains YAML-quoting-hostile characters")
	}
	// npm registry URLs require a trailing slash; yarn berry
	// follows the same convention.  Normalise so an operator who
	// drops the slash from the policy-map config doesn't end up
	// with broken tarball lookups.
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	fmt.Fprintf(&b, "npmRegistryServer: \"%s\"\n", endpoint)
	return []byte(b.String()), nil
}
