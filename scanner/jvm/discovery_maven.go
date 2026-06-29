package jvm

import (
	"os"
	"path/filepath"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// discoverMavenCache returns Environments pointing at Maven-style
// repositories reachable from this host.  Two locations are checked:
//
//   1. ``$MAVEN_HOME/repository`` — explicit configuration, typical
//      on shared build agents where MAVEN_HOME points at a
//      writable group directory.
//   2. ``$HOME/.m2/repository`` — developer workstations.  On
//      Windows we read $USERPROFILE as the HOME fallback.
//
// Both may exist on one host (CI runner with a system-wide Maven +
// per-user cache); we emit a distinct Environment for each so they
// get walked independently.  The JVM Scanner's Scan() is given the
// directory to walk; the extractor runs per-JAR inside.
//
// Callers: invoked from Scanner.DiscoverAll() in scanner.go.  Pure —
// no side effects beyond reading the filesystem.
func discoverMavenCache() []scanner.Environment {
	var out []scanner.Environment

	if mvn := os.Getenv("MAVEN_HOME"); mvn != "" {
		candidate := filepath.Join(mvn, "repository")
		if isDir(candidate) {
			out = append(out, scanner.Environment{
				EnvType: EnvJVM,
				Name:    layoutMavenCache,
				Path:    candidate,
			})
		}
	}

	if home := userHome(); home != "" {
		candidate := filepath.Join(home, ".m2", "repository")
		// Don't emit the same path twice if $HOME/.m2/repository happens
		// to be the same as $MAVEN_HOME/repository.
		if isDir(candidate) && !containsPath(out, candidate) {
			out = append(out, scanner.Environment{
				EnvType: EnvJVM,
				Name:    layoutMavenCache,
				Path:    candidate,
			})
		}
	}

	return out
}
