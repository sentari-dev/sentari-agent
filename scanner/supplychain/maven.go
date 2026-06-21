package supplychain

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
)

// unsignedJar is a runtime jar (group:artifact, version) that lacks an
// adjacent .asc PGP signature, recorded during the walk so the emit
// decision can be made *after* the whole tree is known.
type unsignedJar struct {
	name    string
	version string
}

// DetectInM2 walks ~/.m2/repository looking for installed runtime JARs
// that lack an adjacent .asc (PGP) signature.
//
// A naive "one `unsigned` signal per .asc-less jar" floods the fleet:
// the overwhelming majority of jars in a real ~/.m2 carry no signature
// because the Maven Central artifacts that *do* publish .asc files are
// rarely fetched with them, and developer/internal artifacts are almost
// never signed. Emitting one low signal per jar buries any genuine
// signal under thousands of expected ones.
//
// Instead we treat the missing signature as suspicious only when a
// signature was *expected*: i.e. the repository demonstrably practices
// PGP signing (at least one `.asc` is present somewhere in the tree).
// In that case an unsigned runtime jar is a real anomaly worth a signal.
// When no `.asc` exists anywhere, signing simply isn't in use for this
// repository and per-jar unsigned signals are pure noise — they are
// suppressed.
//
// `m2Dir` should be the path to `~/.m2/repository`.
func DetectInM2(m2Dir string) ([]deptree.SupplyChainSignal, error) {
	var unsigned []unsignedJar
	signingInUse := false

	walkErr := filepath.WalkDir(m2Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if pathfilter.ShouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		// Any .asc anywhere in the tree means PGP signing is practiced in
		// this repository, so a missing one becomes meaningful.
		if strings.HasSuffix(path, ".asc") {
			signingInUse = true
			return nil
		}
		if !strings.HasSuffix(path, ".jar") {
			return nil
		}
		// Skip javadoc / sources jars — those don't usually get signed
		// and are also not the runtime artefacts we care about.
		base := filepath.Base(path)
		if strings.HasSuffix(base, "-javadoc.jar") || strings.HasSuffix(base, "-sources.jar") {
			return nil
		}
		if _, err := os.Stat(path + ".asc"); err == nil {
			// This jar is signed — nothing to report, and it also proves
			// signing is in use.
			signingInUse = true
			return nil
		}
		// Derive coordinates from path: <m2>/group/path/artifact/version/<artifact>-<version>.jar
		name, version := mavenCoordsFromJarPath(m2Dir, path)
		if name == "" {
			return nil
		}
		unsigned = append(unsigned, unsignedJar{name: name, version: version})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
	}

	// Suppress the common case: when signing isn't practiced anywhere in
	// the repository, an unsigned jar is expected, not suspicious.
	if !signingInUse {
		return nil, nil
	}

	signals := make([]deptree.SupplyChainSignal, 0, len(unsigned))
	for _, u := range unsigned {
		signals = append(signals, deptree.SupplyChainSignal{
			PackageName:    u.name,
			PackageVersion: u.version,
			Ecosystem:      "maven",
			SignalType:     "unsigned",
			Severity:       "low",
			Source:         "agent-maven-asc",
		})
	}
	return signals, nil
}

// mavenCoordsFromJarPath reconstructs (groupId:artifactId, version)
// from the on-disk layout of ~/.m2:
//
//	<m2>/com/example/lib-a/1.0.0/lib-a-1.0.0.jar
//
// returns ("com.example:lib-a", "1.0.0")
func mavenCoordsFromJarPath(m2Dir, jarPath string) (string, string) {
	rel, err := filepath.Rel(m2Dir, jarPath)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 4 {
		return "", ""
	}
	version := parts[len(parts)-2]
	artifact := parts[len(parts)-3]
	group := strings.Join(parts[:len(parts)-3], ".")
	return group + ":" + artifact, version
}
