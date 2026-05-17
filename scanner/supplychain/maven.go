package supplychain

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// DetectInM2 walks ~/.m2/repository looking for installed JARs and
// emits an `unsigned` signal for any JAR without an adjacent .asc
// (PGP) signature.
//
// `m2Dir` should be the path to `~/.m2/repository`.
func DetectInM2(m2Dir string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(m2Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
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
		ascPath := path + ".asc"
		if _, err := os.Stat(ascPath); err != nil {
			// Derive coordinates from path: <m2>/group/path/artifact/version/<artifact>-<version>.jar
			name, version := mavenCoordsFromJarPath(m2Dir, path)
			if name == "" {
				return nil
			}
			signals = append(signals, deptree.SupplyChainSignal{
				PackageName:    name,
				PackageVersion: version,
				Ecosystem:      "maven",
				SignalType:     "unsigned",
				Severity:       "low",
				Source:         "agent-maven-asc",
			})
		}
		return nil
	})
	if walkErr != nil {
		return signals, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
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
