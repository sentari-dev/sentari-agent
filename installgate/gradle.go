// Gradle writer — JVM build tool.
//
// Gradle resolves Maven artifacts from repositories declared in
// each project's build script.  At the user/system level, init
// scripts in ``$GRADLE_USER_HOME/init.d/*.gradle`` are auto-loaded
// before every build invocation, which makes them the natural
// vehicle for fleet-wide repository overrides.  We drop a single
// ``sentari-proxy.gradle`` file there that rewrites every project's
// repository list to point at Sentari-Proxy.
//
// Reads ``proxy_endpoints["maven"]`` since gradle's repository
// format and Sentari-Proxy's Maven mirror share the same artifact
// layout.
//
// Operator-curated init scripts (custom plugin repos, mirror
// declarations for internal Artifactory) are recognised by the
// presence of OTHER ``.gradle`` files in the same directory — this
// writer only owns ``sentari-proxy.gradle`` and never touches
// other init scripts.  An operator who hand-curated their own
// ``99-corp.gradle`` keeps it intact.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// gradleInitFilename is the file we own under the user/system
// init.d directory.  Naming chosen so alphabetic ordering puts
// our script after operator-curated ones (``99-…``) by default —
// init scripts apply in lexical order and we want operator
// overrides to take precedence over the agent's defaults.
const gradleInitFilename = "sentari-proxy.gradle"

// GradleScope picks the user-level or system-level init.d.
type GradleScope int

const (
	// GradleScopeUser writes ``$GRADLE_USER_HOME/init.d/sentari-proxy.gradle``
	// when ``GRADLE_USER_HOME`` is set, otherwise
	// ``~/.gradle/init.d/sentari-proxy.gradle`` (gradle's default).
	GradleScopeUser GradleScope = iota

	// GradleScopeSystem writes ``$GRADLE_HOME/init.d/sentari-proxy.gradle``.
	// Returns empty (soft no-op) when ``GRADLE_HOME`` is not set —
	// gradle's install path varies across distros + sdkman / brew /
	// apt installs, so guess-paths would write into a directory
	// gradle won't read.
	GradleScopeSystem
)

// GradlePath returns the absolute init-script path for the given
// scope.  Empty return → soft no-op upstream.
func GradlePath(scope GradleScope) string {
	switch scope {
	case GradleScopeUser:
		if guh := os.Getenv("GRADLE_USER_HOME"); guh != "" {
			return filepath.Join(guh, "init.d", gradleInitFilename)
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		// gradle uses the same ``.gradle`` directory under HOME on
		// every supported OS, including Windows (gradle is a JVM
		// tool, paths are platform-portable inside the JVM).
		return filepath.Join(home, ".gradle", "init.d", gradleInitFilename)
	case GradleScopeSystem:
		gh := os.Getenv("GRADLE_HOME")
		if gh == "" {
			return ""
		}
		return filepath.Join(gh, "init.d", gradleInitFilename)
	}
	return ""
}

// WriteGradleResult mirrors the other writer-result shapes.
type WriteGradleResult struct {
	Path    string
	Changed bool
	Removed bool
}

// WriteGradle applies the Maven section of the policy-map to a
// gradle init script.  Behaviour matrix matches the pip / npm
// writers (the SkippedOperator path doesn't apply because we own
// a uniquely-named init script — operator-curated init scripts
// live alongside under different names and stay untouched).
func WriteGradle(m *scanner.InstallGateMap, scope GradleScope, marker MarkerFields) (WriteGradleResult, error) {
	res := WriteGradleResult{Path: GradlePath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteGradle: nil policy map")
	}

	endpoint := strings.TrimSpace(m.ProxyEndpoints["maven"])
	if endpoint == "" {
		// Fail-open: remove only Sentari-managed scripts (the
		// marker is present in the file content); never delete
		// other init scripts the operator may have placed in the
		// same directory.
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteGradle: inspect existing init script: %w", err)
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

	body, err := renderGradleInit(endpoint, marker)
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

// renderGradleInit produces a fresh Sentari-managed Groovy init
// script.  The script rewrites every project's repository list
// to a single Sentari-Proxy URL — same semantic as Maven's
// ``<mirrorOf>*</mirrorOf>``.
//
// We use ``allprojects { ... }`` rather than ``settingsEvaluated``
// because the former is the more portable across Gradle 6 / 7 / 8
// and doesn't break when projects override ``repositories {}``
// later in their own build script: gradle re-evaluates the
// ``allprojects`` closure on every project, so our mirror
// declaration is always present.
func renderGradleInit(endpoint string, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderGradleInit: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderGradleInit: %w", err)
	}
	// Groovy single-quoted strings are byte-faithful (no escape
	// processing), but we embed in single-quoted strings inside
	// the rendered script.  An embedded ``'`` would terminate
	// the string and let an attacker smuggle Groovy code.
	if strings.ContainsAny(endpoint, "'\\") {
		return nil, fmt.Errorf("renderGradleInit: endpoint contains Groovy-string-hostile characters")
	}

	var b strings.Builder
	b.WriteString(renderSlashMarker(marker))
	b.WriteString("\n")
	b.WriteString("allprojects {\n")
	b.WriteString("    buildscript {\n")
	b.WriteString("        repositories {\n")
	b.WriteString("            maven {\n")
	fmt.Fprintf(&b, "                url '%s'\n", endpoint)
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("    repositories {\n")
	b.WriteString("        maven {\n")
	fmt.Fprintf(&b, "            url '%s'\n", endpoint)
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return []byte(b.String()), nil
}
