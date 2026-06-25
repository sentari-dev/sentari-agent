package supplychain

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const (
	// maxPOMBytes caps the POM file read. 4 MiB is ample for real POMs
	// (median is ~5 KiB; pathological multi-module monorepo POMs rarely
	// exceed 1 MiB).
	maxPOMBytes = 4 * 1024 * 1024
)

// snapshotPom is a minimal XML struct for parsing Maven POM files.
// We only care about the <dependencies> section to find SNAPSHOT versions.
type snapshotPom struct {
	Dependencies struct {
		Dep []struct {
			Version string `xml:"version"`
		} `xml:"dependency"`
	} `xml:"dependencies"`
}

// DetectSnapshotInRelease walks m2Dir and inspects .pom files. For each
// artifact whose version directory does NOT contain "SNAPSHOT" (i.e. a
// release artifact), it parses the POM to check whether any <dependency>
// declares a version ending in "-SNAPSHOT". If so, one
// maven_snapshot_in_release signal is emitted for that root artifact.
//
// The signal is per root artifact (not per SNAPSHOT dep) to keep signal
// volume manageable on large ~/.m2 caches.
func DetectSnapshotInRelease(m2Dir string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(m2Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip symlinks
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
		if !strings.HasSuffix(path, ".pom") {
			return nil
		}

		// Derive coordinates from the POM path. The version sits in the
		// second-to-last path component (the version directory).
		name, version := mavenCoordsFromPOMPath(m2Dir, path)
		if name == "" {
			return nil
		}

		// Only inspect non-SNAPSHOT roots.
		if strings.Contains(version, "SNAPSHOT") {
			return nil
		}

		// Read and parse the POM.
		data, readErr := safeio.ReadFile(path, maxPOMBytes)
		if readErr != nil {
			return nil
		}

		var pom snapshotPom
		if xmlErr := xml.Unmarshal(data, &pom); xmlErr != nil {
			return nil
		}

		// Check if any dependency version ends in -SNAPSHOT.
		for _, dep := range pom.Dependencies.Dep {
			if strings.HasSuffix(dep.Version, "-SNAPSHOT") ||
				strings.HasSuffix(dep.Version, "SNAPSHOT") {
				signals = append(signals, deptree.SupplyChainSignal{
					PackageName:    name,
					PackageVersion: version,
					Ecosystem:      "maven",
					SignalType:     "maven_snapshot_in_release",
					Severity:       "medium",
					Source:         "agent-maven-snapshot",
					Raw: map[string]interface{}{
						"pom_path":     path,
						"snapshot_dep": dep.Version,
					},
				})
				// One signal per root artifact — stop checking deps.
				break
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
	}
	return signals, nil
}

// mavenCoordsFromPOMPath reconstructs (groupId:artifactId, version)
// from the on-disk layout of ~/.m2:
//
//	<m2>/com/example/myapp/1.0.0/myapp-1.0.0.pom
//
// returns ("com.example:myapp", "1.0.0")
//
// This mirrors mavenCoordsFromJarPath but for .pom files.
func mavenCoordsFromPOMPath(m2Dir, pomPath string) (string, string) {
	rel, err := filepath.Rel(m2Dir, pomPath)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	// Minimum: group(1+) / artifact / version / file = 4 parts
	if len(parts) < 4 {
		return "", ""
	}
	version := parts[len(parts)-2]
	artifact := parts[len(parts)-3]
	group := strings.Join(parts[:len(parts)-3], ".")
	return group + ":" + artifact, version
}
