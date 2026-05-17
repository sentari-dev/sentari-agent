package supplychain

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxMETADATABytes caps METADATA / YANKED reads under dist-info.  PyPI
// METADATA can run a few hundred KB for verbose descriptions; 1 MiB is
// well above realistic and below abusive.
const maxMETADATABytes = 1 << 20 // 1 MiB

// DetectInPipCache walks pip's installed-distribution metadata in
// `sitePackagesDir` (e.g. `<venv>/lib/python3.X/site-packages`). For
// each *.dist-info/METADATA we record yanked-version status when pip's
// installer cache records it.
//
// Phase 3 yanked detection: PyPI marks a release as yanked via the
// JSON API. Pip's installer records yank state in
// `*.dist-info/INSTALLER` (when installed via pip after yank flag was
// introduced) and PyPI itself records yank in
// `*.dist-info/RECORD` doesn't carry this — there's no fully reliable
// on-disk signal that a version was yanked AFTER install. Phase 3
// emits yanked signals only when an explicit `*.dist-info/YANKED`
// marker file is present (this matches pip's experimental yank marker
// pattern used in some pip>=22 installs).
//
// Out of scope for Phase 3: querying PyPI's JSON API for current yank
// status (that's the server-side enrichment path).
func DetectInPipCache(sitePackagesDir string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(sitePackagesDir, func(path string, d fs.DirEntry, err error) error {
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
		if !strings.HasSuffix(d.Name(), ".dist-info") {
			return nil
		}
		metadataPath := filepath.Join(path, "METADATA")
		raw, err := safeio.ReadFile(metadataPath, maxMETADATABytes)
		if err != nil {
			return nil
		}
		name, version := pypiMetadataFields(raw)
		if name == "" {
			return nil
		}
		if _, err := os.Stat(filepath.Join(path, "YANKED")); err == nil {
			reason := ""
			if y, err := safeio.ReadFile(filepath.Join(path, "YANKED"), maxMETADATABytes); err == nil {
				reason = strings.TrimSpace(string(y))
			}
			rawSignal := map[string]interface{}{}
			if reason != "" {
				rawSignal["reason"] = reason
			}
			signals = append(signals, deptree.SupplyChainSignal{
				PackageName:    name,
				PackageVersion: version,
				Ecosystem:      "pypi",
				SignalType:     "yanked",
				Severity:       "medium",
				Source:         "agent-pypi-yanked-cache",
				Raw:            rawSignal,
			})
		}
		// Skip subdirs — only top-level dist-info matters.
		return filepath.SkipDir
	})
	if walkErr != nil {
		return signals, fmt.Errorf("walk %s: %w", sitePackagesDir, walkErr)
	}
	return signals, nil
}

func pypiMetadataFields(raw []byte) (string, string) {
	name, version := "", ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
		if name != "" && version != "" {
			break
		}
	}
	return name, version
}
