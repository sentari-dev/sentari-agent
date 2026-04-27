// pdm writer — Python development environment manager.
//
// pdm reads its config from a TOML file at a platformdirs-derived
// path (Linux: ``~/.config/pdm/config.toml``, macOS: ``~/Library/
// Application Support/pdm/config.toml``, Windows: ``%LOCALAPPDATA%
// \pdm\pdm\config.toml``).  The ``[pypi].url`` setting redirects
// every package install through Sentari-Proxy globally — same
// semantic as pip's ``index-url``.
//
// pdm has no system-wide config path; it's per-user only.  The
// scope enum keeps the System variant for symmetry with the other
// writers, but the System path resolves to empty (soft no-op).

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// PdmScope picks the user-level config (system is a soft no-op
// because pdm doesn't define a system-wide config path).
type PdmScope int

const (
	// PdmScopeUser writes pdm's per-user config:
	//
	//   - ``$XDG_CONFIG_HOME/pdm/config.toml`` (Linux, fallback
	//     to ``~/.config/pdm/config.toml``)
	//   - ``~/Library/Application Support/pdm/config.toml`` (macOS)
	//   - ``%LOCALAPPDATA%\pdm\pdm\config.toml`` (Windows)
	PdmScopeUser PdmScope = iota

	// PdmScopeSystem soft-no-ops on every OS because pdm itself
	// has no equivalent system config path — the platformdirs
	// abstraction it uses returns user-level paths only.
	PdmScopeSystem
)

// PdmPath returns the absolute pdm config path for the given
// scope.  Empty return → soft no-op upstream.
func PdmPath(scope PdmScope) string {
	if scope == PdmScopeSystem {
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		// platformdirs.user_config_dir uses LOCALAPPDATA + the
		// app's vendor + name as a double-segment path.  pdm's
		// vendor is also "pdm" so the path doubles up.
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "pdm", "pdm", "config.toml")
		}
		return ""
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		return filepath.Join(home, "Library", "Application Support", "pdm", "config.toml")
	default: // linux, freebsd
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "pdm", "config.toml")
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		return filepath.Join(home, ".config", "pdm", "config.toml")
	}
}

// WritePdmResult — same shape as WriteUvResult; pdm config can
// carry operator-curated content (custom sources, lockfile
// strategies) so the SkippedOperator guard applies.
type WritePdmResult struct {
	Path            string
	Changed         bool
	Removed         bool
	SkippedOperator bool
}

// WritePdm applies the pypi section of the policy-map to pdm's
// config.  Same operator-protection contract as the other
// writers.
func WritePdm(m *scanner.InstallGateMap, scope PdmScope, marker MarkerFields) (WritePdmResult, error) {
	res := WritePdmResult{Path: PdmPath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WritePdm: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["pypi"])
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WritePdm: inspect existing config: %w", err)
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
			return res, fmt.Errorf("installgate.WritePdm: inspect existing config: %w", err)
		}
		if !managed {
			res.SkippedOperator = true
			return res, nil
		}
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("installgate.WritePdm: stat %s: %w", res.Path, err)
	}

	body, err := renderPdmConfig(endpoint, marker)
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

// renderPdmConfig produces a fresh Sentari-managed pdm
// config.toml.  Single ``[pypi]`` table with ``url`` and an
// explicit ``verify_ssl = true`` so pdm doesn't fall back to
// host-default behaviour on an internal CA install.
//
// pdm's TOML reader is the standard Python tomllib so any TOML-
// hostile bytes in the URL would break it — same defensive
// quoting as renderUvToml.
func renderPdmConfig(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderPdmConfig: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderPdmConfig: %w", err)
	}
	if strings.ContainsAny(endpoint, "\"\\") {
		return nil, fmt.Errorf("renderPdmConfig: endpoint contains TOML-quoting-hostile characters")
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	b.WriteString("\n[pypi]\n")
	fmt.Fprintf(&b, "url = \"%s\"\n", endpoint)
	b.WriteString("verify_ssl = true\n")
	return []byte(b.String()), nil
}
