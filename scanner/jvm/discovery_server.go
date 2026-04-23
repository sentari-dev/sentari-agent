package jvm

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Common shape for every app-server discoverer.  Each server is
// ultimately "look at these env vars + these well-known install
// parent directories, and emit an Environment for every candidate
// that passes a server-specific shape check."  The variation between
// servers is tiny and worth factoring out, because six near-identical
// 40-line files become six near-identical 10-line files.
//
// The shape check (``marker``) is how we tell a real server install
// from an unrelated directory that happens to have the matching name:
// a Tomcat install always has ``bin/catalina.sh`` (or .bat); a
// WildFly install always has ``bin/standalone.sh`` + ``modules/``.
// Without this check, an env var pointing at /tmp would cause us to
// walk /tmp looking for JARs — useless and slow.
type serverSpec struct {
	layout       string
	envVars      []string
	wellKnown    map[string][]string // per-OS parents that CONTAIN server installs (one level deep)
	wellKnownAbs map[string][]string // per-OS paths that ARE server installs (no descent)
	marker       func(root string) bool
}

// discoverByServerSpec applies the spec on this host and returns
// deduplicated Environments.  Envvars first (explicit operator
// intent), then OS-specific well-known paths.  A candidate that
// fails the marker check is silently skipped — a stray env var
// shouldn't cause us to scan an unrelated directory.
func discoverByServerSpec(spec serverSpec) []scanner.Environment {
	var out []scanner.Environment
	seen := map[string]struct{}{}

	emit := func(path string) {
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		if _, dup := seen[clean]; dup {
			return
		}
		if !isDir(clean) || !spec.marker(clean) {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, scanner.Environment{
			EnvType: EnvJVM,
			Name:    spec.layout,
			Path:    clean,
		})
	}

	for _, ev := range spec.envVars {
		emit(os.Getenv(ev))
	}

	// Well-known parents (/opt/apache-tomcat-*, /opt/wildfly-*, …) —
	// walk one level deep and emit each child that passes marker().
	for _, parent := range spec.wellKnown[runtime.GOOS] {
		entries, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if !d.IsDir() {
				continue
			}
			emit(filepath.Join(parent, d.Name()))
		}
	}

	// Well-known absolute install paths (e.g. /opt/IBM/WebSphere/AppServer)
	// — emit directly without walking.
	for _, candidate := range spec.wellKnownAbs[runtime.GOOS] {
		emit(candidate)
	}

	return out
}

// hasAny returns true iff ``root`` contains at least one of the given
// relative paths.  Helper for the marker predicates below — each
// server has a short list of "this file/dir uniquely identifies an
// install of me" markers.
func hasAny(root string, rels ...string) bool {
	for _, rel := range rels {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			return true
		}
	}
	return false
}
