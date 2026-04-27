// uv writer — Astral's Python package manager.
//
// uv has its own configuration namespace separate from pip's: the
// pip-compat layer (``uv pip install ...``) honours pip.conf, but
// the modern uv-native commands (``uv add``, ``uv sync``,
// ``uv lock``, ``uv tool install``) read ``uv.toml``.  Without a
// dedicated writer the install-gate covers ``uv pip install`` only
// and quietly mis-routes the modern commands — worse than known
// partial coverage because operators assume the gate works
// uniformly.
//
// Reads the same ``proxy_endpoints["pypi"]`` as the pip writer
// since uv consumes the PyPI ecosystem.  An operator who wants to
// gate pip but NOT uv (rare) can drop the uv writer by clearing
// ``[install_gate] uv_scope`` — the agent then leaves uv.toml
// alone.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// UvScope picks the user-level or system-level ``uv.toml``.
// Same shape as the other Python-ecosystem scope types.
type UvScope int

const (
	// UvScopeUser writes the per-user ``uv.toml``:
	//
	//   - ``$XDG_CONFIG_HOME/uv/uv.toml`` (Linux/macOS, falls back
	//     to ``~/.config/uv/uv.toml`` when XDG is unset)
	//   - ``%APPDATA%\uv\uv.toml`` (Windows)
	UvScopeUser UvScope = iota

	// UvScopeSystem writes the system-wide ``uv.toml``:
	//
	//   - ``/etc/uv/uv.toml`` (Linux/macOS)
	//   - ``%PROGRAMDATA%\uv\uv.toml`` (Windows)
	UvScopeSystem
)

// UvPath returns the absolute uv.toml path for the given scope.
// Empty return → soft no-op upstream (caller logs a warning and
// continues with the other writers).
func UvPath(scope UvScope) string {
	switch runtime.GOOS {
	case "windows":
		switch scope {
		case UvScopeUser:
			if dir := os.Getenv("APPDATA"); dir != "" {
				return filepath.Join(dir, "uv", "uv.toml")
			}
			return ""
		case UvScopeSystem:
			if dir := os.Getenv("ProgramData"); dir != "" {
				return filepath.Join(dir, "uv", "uv.toml")
			}
			return `C:\ProgramData\uv\uv.toml`
		}
	default: // linux, darwin, freebsd
		switch scope {
		case UvScopeUser:
			if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
				return filepath.Join(xdg, "uv", "uv.toml")
			}
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, ".config", "uv", "uv.toml")
		case UvScopeSystem:
			return "/etc/uv/uv.toml"
		}
	}
	return ""
}

// WriteUvResult mirrors WriteNpmResult — uv.toml is operator-
// curate-able (custom indexes, scoped tokens) so the SkippedOperator
// guard from Maven/NuGet applies.
type WriteUvResult struct {
	Path            string
	Changed         bool
	Removed         bool
	SkippedOperator bool
}

// WriteUv applies the pypi section of the policy-map to uv's
// config.  Behaviour matrix matches the other operator-curate-
// aware writers (Maven, NuGet): an existing uv.toml without the
// Sentari marker is left untouched and surfaces
// ``SkippedOperator=true``.  Operators with custom ``[[index]]``
// blocks (private mirrors with auth tokens, scoped registry
// configs) keep their config.
func WriteUv(m *scanner.InstallGateMap, scope UvScope, marker MarkerFields) (WriteUvResult, error) {
	res := WriteUvResult{Path: UvPath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteUv: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["pypi"])
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteUv: inspect existing config: %w", err)
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
			return res, fmt.Errorf("installgate.WriteUv: inspect existing config: %w", err)
		}
		if !managed {
			res.SkippedOperator = true
			return res, nil
		}
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("installgate.WriteUv: stat %s: %w", res.Path, err)
	}

	body, err := renderUvToml(endpoint, marker)
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

// renderUvToml produces a fresh Sentari-managed uv.toml.  Single
// ``[[index]]`` block with ``default = true`` so uv treats this
// as the sole index and skips the upstream PyPI default — same
// semantic as pip's ``index-url`` with no ``extra-index-url``.
//
// Note on TOML quoting: the URL is interpolated inside double-
// quoted strings, so any embedded ``"`` would break the file.
// validateEndpoint already refuses control bytes + spaces; ``"``
// and ``\`` are vanishingly unlikely in a real proxy URL but we
// gate them here for defence-in-depth.
func renderUvToml(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderUvToml: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderUvToml: %w", err)
	}
	if strings.ContainsAny(endpoint, "\"\\") {
		return nil, fmt.Errorf("renderUvToml: endpoint contains TOML-quoting-hostile characters")
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	b.WriteString("\n[[index]]\n")
	b.WriteString("name = \"sentari-proxy\"\n")
	fmt.Fprintf(&b, "url = \"%s\"\n", endpoint)
	b.WriteString("default = true\n")
	return []byte(b.String()), nil
}
