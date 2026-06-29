package jvm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Generic library-directory discoverer.  Catches vendor-drop JARs
// that don't belong to a recognised app server — e.g. a standalone
// product install at /opt/acme-tool/lib, or the Java-compat packages
// at /usr/share/java on Debian-family distros.
//
// Relative to the app-server discoverers, this one deliberately
// produces more-granular Environments (specific lib dirs rather
// than whole install trees) so it doesn't double-count any tree
// that a specialised discoverer already claimed.  The caller passes
// the list of already-emitted paths; we skip any generic candidate
// that is a descendant of one of those.
//
// Package-level root lists are variables (not consts) so tests can
// substitute fixture trees.  Matches the pattern from
// ``jdkWellKnownRoots`` in discovery_jdk.go.

var (
	// genericOptRoots are the one-level parents under which we scan
	// each child's lib/libs subdir.  A typical customer install
	// named ``/opt/acme-tool`` is caught via /opt → acme-tool → lib.
	genericOptRoots = initGenericOptRoots()

	// genericDirectRoots are absolute directories we scan as-is.
	// Debian's /usr/share/java is the canonical example.
	genericDirectRoots = initGenericDirectRoots()
)

func initGenericOptRoots() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/opt", "/var/lib"}
	case "darwin":
		return []string{"/opt", "/usr/local/opt"}
	case "windows":
		return []string{
			`C:\`,
			`C:\Program Files`,
			`C:\Program Files (x86)`,
		}
	default:
		return nil
	}
}

func initGenericDirectRoots() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/usr/share/java", "/usr/lib/java"}
	case "darwin":
		return []string{"/usr/local/share/java"}
	default:
		return nil
	}
}

// discoverGeneric walks the genericOptRoots + genericDirectRoots and
// emits one Environment per lib/libs directory found.  ``exclude``
// contains the paths of Environments already emitted by specialised
// discoverers (Tomcat install root, WildFly install root, …); we
// skip any generic candidate that lives inside one of those so we
// don't double-count JARs.
func discoverGeneric(exclude []string) []scanner.Environment {
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
		if !isDir(clean) {
			return
		}
		if isDescendantOfAny(clean, exclude) {
			return
		}
		seen[clean] = struct{}{}
		out = append(out, scanner.Environment{
			EnvType: EnvJVM,
			Name:    layoutGeneric,
			Path:    clean,
		})
	}

	for _, parent := range genericOptRoots {
		entries, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if !d.IsDir() {
				continue
			}
			base := filepath.Join(parent, d.Name())
			for _, sub := range []string{"lib", "libs"} {
				emit(filepath.Join(base, sub))
			}
		}
	}

	for _, direct := range genericDirectRoots {
		emit(direct)
	}

	return out
}

// isDescendantOfAny reports whether ``child`` is the same path as, or
// is nested under, any path in ``parents``.  Used to skip generic
// candidates that are already covered by specialised discoverers
// (e.g. /opt/tomcat/lib under an already-emitted /opt/tomcat).
func isDescendantOfAny(child string, parents []string) bool {
	child = filepath.Clean(child)
	for _, p := range parents {
		p = filepath.Clean(p)
		if child == p {
			return true
		}
		// Append a separator to avoid /opt/tomcat matching /opt/tom.
		if strings.HasPrefix(child, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
