// NuGet / .NET writer.
//
// Fourth ecosystem after pip, npm, and Maven.  ``NuGet.Config``
// is structurally similar to Maven's settings.xml — XML with a
// few well-known elements — but its semantics are simpler:
// ``<packageSources>`` with ``<clear/>`` removes inherited
// defaults, and a single ``<add>`` element points NuGet at
// Sentari-Proxy.
//
// Operator-curated NuGet.Config can carry cleartext credentials
// in ``<packageSourceCredentials>`` blocks, so the same
// SkippedOperator guard the Maven writer applies is in force
// here: an existing config without the Sentari marker is left
// untouched and surfaces as ``SkippedOperator=true``.  Merge
// support — splicing a ``<packageSource>`` into an existing
// document — is deferred to a follow-up PR alongside Maven's.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// NuGetScope picks the user-level or system-level NuGet config.
type NuGetScope int

const (
	// NuGetScopeUser writes:
	//   - ``%APPDATA%\NuGet\NuGet.Config`` on Windows
	//   - ``~/.nuget/NuGet/NuGet.Config`` on Linux/macOS
	// These are the canonical per-user paths NuGet itself reads.
	NuGetScopeUser NuGetScope = iota

	// NuGetScopeSystem writes ``%ProgramData%\NuGet\Config\Sentari.Config``
	// on Windows (NuGet auto-loads every ``*.Config`` in that dir).
	// On POSIX, NuGet has no equivalent system-wide config
	// directory; the writer soft-no-ops there.
	NuGetScopeSystem
)

// NuGetPath returns the absolute config path for the given scope
// on the running OS, or empty when the path can't be derived.
func NuGetPath(scope NuGetScope) string {
	switch runtime.GOOS {
	case "windows":
		switch scope {
		case NuGetScopeUser:
			if dir := os.Getenv("APPDATA"); dir != "" {
				return filepath.Join(dir, "NuGet", "NuGet.Config")
			}
			return ""
		case NuGetScopeSystem:
			if dir := os.Getenv("ProgramData"); dir != "" {
				return filepath.Join(dir, "NuGet", "Config", "Sentari.Config")
			}
			// Hard-coded fallback: %ProgramData% defaults to
			// ``C:\ProgramData`` on every supported Windows
			// version.  Same approach the pip writer takes.
			return `C:\ProgramData\NuGet\Config\Sentari.Config`
		}
	default: // linux, darwin, freebsd, …
		switch scope {
		case NuGetScopeUser:
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, ".nuget", "NuGet", "NuGet.Config")
		case NuGetScopeSystem:
			// NuGet has no POSIX system-config dir; soft no-op.
			return ""
		}
	}
	return ""
}

// WriteNuGetResult mirrors WriteMavenResult.  ``SkippedOperator``
// matters here for the same reason it does in Maven — an
// operator-curated NuGet.Config commonly carries package source
// credentials that MUST survive install-gate enrolment intact.
type WriteNuGetResult struct {
	Path            string
	Changed         bool
	Removed         bool
	SkippedOperator bool
}

// WriteNuGet applies the NuGet section of a verified policy-map.
// Behaviour matrix matches WriteMaven exactly — see that
// function's docstring; the only difference is the rendered
// content (``<configuration><packageSources>...``).
func WriteNuGet(m *scanner.InstallGateMap, scope NuGetScope, marker MarkerFields) (WriteNuGetResult, error) {
	res := WriteNuGetResult{Path: NuGetPath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteNuGet: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["nuget"])
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteNuGet: inspect existing config: %w", err)
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
			return res, fmt.Errorf("installgate.WriteNuGet: inspect existing config: %w", err)
		}
		if !managed {
			res.SkippedOperator = true
			return res, nil
		}
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("installgate.WriteNuGet: stat %s: %w", res.Path, err)
	}

	body, err := renderNuGetConfig(endpoint, marker)
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

// renderNuGetConfig produces the bytes for a fresh Sentari-managed
// NuGet.Config.  Layout per design doc §4.4: ``<packageSources>``
// with ``<clear/>`` to drop inherited defaults, then a single
// ``<add>`` element pointing at Sentari-Proxy.
func renderNuGetConfig(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderNuGetConfig: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderNuGetConfig: %w", err)
	}

	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	b.WriteString(renderXMLMarker(marker))
	b.WriteString("<configuration>\n")
	b.WriteString("  <packageSources>\n")
	b.WriteString("    <clear />\n")
	fmt.Fprintf(&b, "    <add key=\"sentari-proxy\" value=\"%s\" />\n", xmlEscape(endpoint))
	b.WriteString("  </packageSources>\n")
	b.WriteString("</configuration>\n")
	return []byte(b.String()), nil
}
