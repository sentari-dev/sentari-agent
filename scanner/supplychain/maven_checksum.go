package supplychain

import (
	"crypto/sha1" //nolint:gosec // SHA1 is mandated by the Maven checksum spec
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
	// maxJarBytes is the maximum jar size we read for checksum verification.
	// 200 MiB is generous but bounded; jars over this are skipped silently.
	maxJarBytes = 200 * 1024 * 1024

	// maxSHA1FileBytes is the maximum size of the .sha1 sidecar file.
	// SHA1 hex is 40 chars; 256 bytes allows for trailing whitespace / newlines.
	maxSHA1FileBytes = 256
)

// DetectChecksumMismatches walks m2Dir looking for .jar files that have a
// sibling .sha1 file. For each such pair it reads the .sha1 file, computes
// the SHA1 of the jar bytes, and emits a maven_checksum_mismatch signal
// when they disagree.
//
// Jars that have no .sha1 sibling are silently skipped — we cannot verify
// without a reference checksum.
//
// Javadoc and sources jars are ignored; they are not runtime artefacts.
func DetectChecksumMismatches(m2Dir string) ([]deptree.SupplyChainSignal, error) {
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
		if !strings.HasSuffix(path, ".jar") {
			return nil
		}
		// Skip javadoc / sources jars
		base := filepath.Base(path)
		if strings.HasSuffix(base, "-javadoc.jar") || strings.HasSuffix(base, "-sources.jar") {
			return nil
		}

		sha1Path := path + ".sha1"
		// Attempt to read the .sha1 sidecar directly via safeio.
		// Missing sidecar and unreadable cases both collapse to skip — no signal.
		sha1Bytes, readErr := safeio.ReadFile(sha1Path, maxSHA1FileBytes)
		if readErr != nil {
			return nil // no sidecar, or unreadable — skip
		}
		expected := strings.TrimSpace(strings.ToLower(string(sha1Bytes)))

		// Read the jar bytes for hashing.
		jarBytes, readErr := safeio.ReadFile(path, maxJarBytes)
		if readErr != nil {
			// Jar is too large or unreadable — skip.
			return nil
		}

		// Compute SHA1.
		h := sha1.New() //nolint:gosec // SHA1 is mandated by the Maven checksum spec
		h.Write(jarBytes)
		computed := fmt.Sprintf("%x", h.Sum(nil))

		if computed == expected {
			return nil
		}

		name, version := mavenCoordsFromJarPath(m2Dir, path)
		if name == "" {
			return nil
		}
		signals = append(signals, deptree.SupplyChainSignal{
			PackageName:    name,
			PackageVersion: version,
			Ecosystem:      "maven",
			SignalType:     "maven_checksum_mismatch",
			Severity:       "high",
			Source:         "agent-maven-sha1",
			Raw: map[string]interface{}{
				"jar_path":  path,
				"expected":  expected,
				"computed":  computed,
			},
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
	}
	return signals, nil
}
