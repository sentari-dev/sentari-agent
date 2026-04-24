package jvm

import (
	"os"
	"path/filepath"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// discoverGradleCache returns at most one Environment pointing at the
// Gradle resolved-artefact cache.  Precedence:
//
//   1. ``$GRADLE_USER_HOME/caches/modules-2/files-2.1`` — total
//      override.  If the env var is set, $HOME/.gradle is NOT also
//      considered.  Matches Gradle's own precedence so scanner
//      output matches what ``gradle dependencies`` would show on
//      the same host.
//   2. ``$HOME/.gradle/caches/modules-2/files-2.1`` — default on
//      developer workstations.
//
// The ``caches/modules-2/files-2.1`` suffix is Gradle's versioned
// artefact-cache layout; older layouts (``modules-1``,
// ``files-1.1``) are deliberately NOT checked because they haven't
// been produced by any supported Gradle release since 2016.
func discoverGradleCache() []scanner.Environment {
	var candidate string
	if gh := os.Getenv("GRADLE_USER_HOME"); gh != "" {
		candidate = filepath.Join(gh, "caches", "modules-2", "files-2.1")
	} else if home := userHome(); home != "" {
		candidate = filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1")
	}
	if candidate == "" || !isDir(candidate) {
		return nil
	}
	return []scanner.Environment{{
		EnvType: EnvJVM,
		Name:    layoutGradleCache,
		Path:    candidate,
	}}
}
