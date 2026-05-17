package supplychain

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxNuspecBytes caps a single .nuspec read.  These are XML metadata
// files; 1 MiB is generous (typical < 4 KiB).
const maxNuspecBytes = 1 << 20 // 1 MiB

// DetectInNuGetCache walks ~/.nuget/packages (or whatever path is
// passed) and emits `unsigned` for any package that lacks an adjacent
// .signature.p7s file (NuGet's CMS signature).
//
// The on-disk layout is:
//
//	<root>/<lowercased-id>/<version>/<id>.<version>.nupkg
//	<root>/<lowercased-id>/<version>/.signature.p7s   (if signed)
func DetectInNuGetCache(cacheRoot string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(cacheRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		// We want to inspect leaf "version" directories. Heuristic:
		// a directory containing a .nuspec file is a version dir.
		nuspec := findNuspec(path)
		if nuspec == "" {
			return nil
		}
		name, version := nugetCoordsFromNuspec(nuspec)
		if name == "" {
			return nil
		}
		sigPath := filepath.Join(path, ".signature.p7s")
		if _, err := os.Stat(sigPath); err != nil {
			signals = append(signals, deptree.SupplyChainSignal{
				PackageName:    name,
				PackageVersion: version,
				Ecosystem:      "nuget",
				SignalType:     "unsigned",
				Severity:       "low",
				Source:         "agent-nuget-signature",
			})
		}
		return nil
	})
	if walkErr != nil {
		return signals, fmt.Errorf("walk %s: %w", cacheRoot, walkErr)
	}
	return signals, nil
}

func findNuspec(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".nuspec") {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

func nugetCoordsFromNuspec(path string) (string, string) {
	raw, err := safeio.ReadFile(path, maxNuspecBytes)
	if err != nil {
		return "", ""
	}
	var ns struct {
		Metadata struct {
			ID      string `xml:"id"`
			Version string `xml:"version"`
		} `xml:"metadata"`
	}
	if err := xml.Unmarshal(raw, &ns); err != nil {
		return "", ""
	}
	return ns.Metadata.ID, ns.Metadata.Version
}
