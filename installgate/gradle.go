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
	"bytes"
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
// script.  The script CLEARS every repository list before adding
// Sentari-Proxy as the sole entry — same semantic as Maven's
// ``<mirrorOf>*</mirrorOf>``.  Three repository surfaces are
// replaced (not appended to):
//
//  1. ``settings.pluginManagement.repositories`` — Gradle plugin
//     resolution.  Without this, ``plugins { id 'foo' }`` still
//     fetches from the Gradle Plugin Portal.  Hooked via
//     ``beforeSettings`` so we intercept before settings.gradle
//     evaluates and locks the configuration.
//
//  2. ``buildscript.repositories`` per-project — the classpath
//     used by ``apply plugin:`` and similar.  Cleared inside
//     ``allprojects`` so the rewrite applies to every subproject
//     in a multi-module build.
//
//  3. ``project.repositories`` per-project — dependency
//     resolution.  Hooked via ``afterEvaluate`` so we run AFTER
//     the project's own ``repositories { ... }`` block; merely
//     adding our mirror earlier wouldn't override an explicit
//     ``mavenCentral()`` call later in the script.
//
// The clear-then-add pattern is the only reliable way to defeat
// the "additional repositories block silently appends" bypass
// pointed out by Copilot on PR #27.
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
	fmt.Fprintf(&b, "def sentariProxyUrl = '%s'\n\n", endpoint)
	// Plugin resolution surface.  beforeSettings runs before
	// settings.gradle evaluates, so clearing the pluginManagement
	// repositories here forces every ``plugins { ... }`` block to
	// resolve through Sentari-Proxy.
	b.WriteString("beforeSettings { settings ->\n")
	b.WriteString("    settings.pluginManagement.repositories.clear()\n")
	b.WriteString("    settings.pluginManagement.repositories.maven { url sentariProxyUrl }\n")
	b.WriteString("}\n\n")
	b.WriteString("allprojects {\n")
	// Buildscript classpath surface — apply plugin: and other
	// build-time deps go through here.  Cleared per-project so
	// every module in a multi-project build is covered.
	b.WriteString("    buildscript {\n")
	b.WriteString("        repositories.clear()\n")
	b.WriteString("        repositories.maven { url sentariProxyUrl }\n")
	b.WriteString("    }\n")
	// Dependency resolution surface — afterEvaluate runs AFTER
	// the project's own repositories { } block, so we override
	// even projects that explicitly call mavenCentral() later
	// in their build script.
	b.WriteString("    afterEvaluate {\n")
	b.WriteString("        repositories.clear()\n")
	b.WriteString("        repositories.maven { url sentariProxyUrl }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	rendered := []byte(b.String())

	// Render-time structural check — paranoia + canary on top of
	// the input gates above.  See ADR 0003 (sentari repo)
	// "Mitigations against the gradle-writer expansion" for the
	// rationale: we author Groovy that runs in gradle's JVM, so
	// any future regression that lets unexpected content into the
	// rendered script must be caught before it hits disk.
	if err := validateRenderedGradle(rendered, endpoint); err != nil {
		return nil, fmt.Errorf("renderGradleInit: structural check: %w", err)
	}
	return rendered, nil
}

// validateRenderedGradle is a defense-in-depth canary: it
// re-validates the *rendered* gradle init script against a fixed
// shape before the writer commits the bytes to disk.  Triggers
// on:
//
//   - the marker prefix not being present at offset zero;
//   - the closing ``}`` not appearing at the end;
//   - the symbolic name ``sentariProxyUrl`` appearing anything other
//     than the exact expected count of references (1 def + 6 uses
//     across pluginManagement / buildscript / afterEvaluate);
//   - the URL appearing other than once (only inside the ``def``
//     line as a string literal — every other reference goes through
//     the variable);
//   - any of a small list of Groovy keywords associated with
//     arbitrary code execution (``eval``, ``execute``,
//     ``ProcessBuilder``, ``Runtime``, ``GroovyShell``,
//     ``System.exec``).
//
// The check is deliberately cheap and over-strict: the render
// function is a constant template with one variable substitution,
// so any deviation from the expected shape indicates either a
// regression in the renderer or — much less likely — a malicious
// URL that slipped the input gates.  Refusing to write under
// either condition is the right behaviour.
func validateRenderedGradle(rendered []byte, endpoint string) error {
	if !bytes.HasPrefix(rendered, []byte(sentariManagedSentinelSlash)) {
		return fmt.Errorf("rendered script missing slash-marker prefix")
	}
	trimmed := bytes.TrimRight(rendered, "\n")
	if !bytes.HasSuffix(trimmed, []byte("}")) {
		return fmt.Errorf("rendered script does not end with closing brace")
	}
	// The variable name ``sentariProxyUrl`` appears 4 times in the
	// canonical render: once on the def's left-hand side, then
	// once each as the URL argument in pluginManagement,
	// buildscript, and afterEvaluate (3 uses).  Total = 4.
	const sentariProxyUrlOccurrences = 4
	if got := bytes.Count(rendered, []byte("sentariProxyUrl")); got != sentariProxyUrlOccurrences {
		return fmt.Errorf(
			"rendered script has %d ``sentariProxyUrl`` references, want %d",
			got, sentariProxyUrlOccurrences,
		)
	}
	if got := bytes.Count(rendered, []byte(endpoint)); got != 1 {
		return fmt.Errorf(
			"rendered script has %d copies of the endpoint URL, want exactly 1 (only the def line)",
			got,
		)
	}
	// Groovy keywords associated with arbitrary code execution.
	// This list is the minimum bar — a sophisticated attacker who
	// owns the input could find non-listed primitives, but the
	// signed-envelope + input-gate layers above are the primary
	// defence.  This canary catches obvious regressions.
	//
	// Scan ONLY the Groovy body — everything after the def line.
	// The marker header carries the operator-supplied KeyID and
	// the endpoint URL (in the def's right-hand side), neither
	// of which is restricted to a keyword-free alphabet by
	// upstream validators.  A legitimate proxy URL like
	// ``https://eval-proxy.corp.local/maven/`` or a KeyID like
	// ``runtime-2026q2`` would otherwise false-positive.
	body, err := gradleBodyAfterDef(rendered)
	if err != nil {
		return err
	}
	forbidden := []string{
		"eval", "execute", "ProcessBuilder", "Runtime",
		"GroovyShell", "System.exec", "@Grab", "Eval.",
	}
	for _, kw := range forbidden {
		if bytes.Contains(body, []byte(kw)) {
			return fmt.Errorf("rendered script contains forbidden Groovy primitive %q", kw)
		}
	}
	return nil
}

// gradleBodyAfterDef returns the bytes of the rendered script
// that follow the ``def sentariProxyUrl = '<URL>'`` line.  Used
// by the forbidden-primitive scan so an operator-supplied URL
// or KeyID containing keyword-collision substrings can't false-
// positive the canary.  Returns an error if the def line is
// missing or truncated; the structural checks above run before
// this so that error path is unreachable on a valid render.
func gradleBodyAfterDef(rendered []byte) ([]byte, error) {
	defIdx := bytes.Index(rendered, []byte("def sentariProxyUrl "))
	if defIdx < 0 {
		return nil, fmt.Errorf("rendered script missing ``def sentariProxyUrl`` line")
	}
	// Find the newline that terminates the def line.
	rest := rendered[defIdx:]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("rendered script def line is not newline-terminated")
	}
	return rest[nl+1:], nil
}
