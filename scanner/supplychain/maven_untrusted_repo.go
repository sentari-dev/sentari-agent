package supplychain

import (
	"bufio"
	"bytes"
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
	// maxRemoteRepoBytes caps the _remote.repositories file read.
	// 64 KiB is generous; real files are typically under 1 KiB.
	maxRemoteRepoBytes = 64 * 1024

	remoteRepoFilename = "_remote.repositories"
)

// trustedRepoIDs is the set of Maven repository identifiers considered
// always-trusted regardless of URL.
var trustedRepoIDs = map[string]bool{
	"central": true,
	"local":   true,
}

// trustedCentralURLs is the set of canonical Maven Central base URLs.
// A repo whose URL starts with one of these prefixes is trusted.
var trustedCentralURLs = []string{
	"https://repo1.maven.org/maven2",
	"https://repo.maven.apache.org/maven2",
}

// DetectUntrustedRepos walks m2Dir looking for _remote.repositories files.
// Each such file records which remote repository an artifact was downloaded
// from. Lines of the form `<artifact-key>><repo-id>=<repo-url>` are parsed;
// if repo-url is non-empty and does not match a trusted Maven Central URL,
// one maven_untrusted_repo signal is emitted for that version directory.
//
// One signal is emitted per _remote.repositories file that contains at
// least one untrusted entry — not one per line — to avoid signal flooding.
func DetectUntrustedRepos(m2Dir string) ([]deptree.SupplyChainSignal, error) {
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
		if filepath.Base(path) != remoteRepoFilename {
			return nil
		}

		data, readErr := safeio.ReadFile(path, maxRemoteRepoBytes)
		if readErr != nil {
			return nil
		}

		if !hasUntrustedEntry(data) {
			return nil
		}

		name, version := mavenCoordsFromRemoteRepoPath(m2Dir, path)
		if name == "" {
			return nil
		}

		// Find the first untrusted repo URL for the Raw field.
		untrustedURL := firstUntrustedURL(data)

		signals = append(signals, deptree.SupplyChainSignal{
			PackageName:    name,
			PackageVersion: version,
			Ecosystem:      "maven",
			SignalType:     "maven_untrusted_repo",
			Severity:       "high",
			Source:         "agent-maven-repo",
			Raw: map[string]interface{}{
				"repo_file":     path,
				"untrusted_url": untrustedURL,
			},
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
	}
	return signals, nil
}

// hasUntrustedEntry reports whether data contains at least one line
// with a non-trusted repo URL.
func hasUntrustedEntry(data []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isUntrustedLine(line) {
			return true
		}
	}
	return false
}

// firstUntrustedURL returns the URL of the first untrusted repo found in data.
func firstUntrustedURL(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isUntrustedLine(line) {
			// Parse the URL portion: <artifact-key>><repo-id>=<repo-url>
			gtIdx := strings.Index(line, ">")
			if gtIdx < 0 {
				continue
			}
			rest := line[gtIdx+1:] // "<repo-id>=<repo-url>"
			eqIdx := strings.Index(rest, "=")
			if eqIdx < 0 {
				continue
			}
			return rest[eqIdx+1:]
		}
	}
	return ""
}

// isUntrustedLine parses a single non-comment line from _remote.repositories
// and returns true if it references an untrusted remote repo.
//
// Format: `<artifact-key>><repo-id>=<repo-url>`
//
// Trusted when:
//   - repo-id is "central" or "local", OR
//   - repo-url is empty, OR
//   - repo-url starts with a canonical Maven Central URL
func isUntrustedLine(line string) bool {
	// Locate the ">" separator between artifact key and "repo-id=url".
	gtIdx := strings.Index(line, ">")
	if gtIdx < 0 {
		return false
	}
	rest := line[gtIdx+1:] // "<repo-id>=<repo-url>"

	eqIdx := strings.Index(rest, "=")
	if eqIdx < 0 {
		return false
	}
	repoID := rest[:eqIdx]
	repoURL := rest[eqIdx+1:]

	// Trusted by repo-id.
	if trustedRepoIDs[repoID] {
		return false
	}
	// Trusted by empty URL (no URL means it was fetched locally or from
	// the default configured central).
	if repoURL == "" {
		return false
	}
	// Trusted by Maven Central URL.
	for _, trusted := range trustedCentralURLs {
		if strings.HasPrefix(repoURL, trusted) {
			return false
		}
	}
	return true
}

// mavenCoordsFromRemoteRepoPath reconstructs (groupId:artifactId, version)
// from the path of a _remote.repositories file:
//
//	<m2>/com/example/lib-a/1.0.0/_remote.repositories
//
// returns ("com.example:lib-a", "1.0.0")
func mavenCoordsFromRemoteRepoPath(m2Dir, repoFilePath string) (string, string) {
	rel, err := filepath.Rel(m2Dir, repoFilePath)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	// Expected: group(1+) / artifact / version / _remote.repositories = min 4 parts
	if len(parts) < 4 {
		return "", ""
	}
	// parts[len-1] = "_remote.repositories"
	version := parts[len(parts)-2]
	artifact := parts[len(parts)-3]
	group := strings.Join(parts[:len(parts)-3], ".")
	return group + ":" + artifact, version
}
