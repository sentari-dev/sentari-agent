// Package licenses produces deptree.LicenseEvidence rows by reading
// per-ecosystem on-disk metadata files. Each extractor walks the
// relevant install dir and emits one row per package per evidence
// source.
//
// Confidence scoring per source (matches docs/contracts):
//   - SPDX-formed expression in METADATA / package.json / nuspec  → 0.95
//   - PyPI Trove classifier fallback                              → 0.6
//   - Maven POM <licenses>                                        → 0.9
//   - NuGet <license>                                             → 0.9
//   - NuGet <licenseUrl> fallback                                 → 0.5
package licenses

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxMETADATABytes caps a single dist-info/METADATA read.  1 MiB is
// well above realistic PyPI metadata sizes.
const maxMETADATABytes = 1 << 20 // 1 MiB

// ExtractPyPI walks a site-packages dir, reading each *.dist-info/METADATA
// for one of: PEP 639 License-Expression (preferred, conf 0.95),
// License: header (mid, conf 0.7), Classifier: License :: ... (fallback,
// conf 0.6).
func ExtractPyPI(sitePackagesDir string) ([]deptree.LicenseEvidence, error) {
	var out []deptree.LicenseEvidence
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
		if !d.IsDir() || !strings.HasSuffix(d.Name(), ".dist-info") {
			return nil
		}
		metaPath := filepath.Join(path, "METADATA")
		raw, err := safeio.ReadFile(metaPath, maxMETADATABytes)
		if err != nil {
			return filepath.SkipDir
		}
		name, version, licenseExpr, licenseHdr, troves := parsePyPIMetadata(raw)
		if name == "" {
			return filepath.SkipDir
		}
		switch {
		case licenseExpr != "":
			out = append(out, deptree.LicenseEvidence{
				PackageName: name, PackageVersion: version, Ecosystem: "pypi",
				SpdxID: licenseExpr, Source: "spdx_pkg", Confidence: 0.95,
				RawText: licenseExpr,
			})
		case licenseHdr != "":
			out = append(out, deptree.LicenseEvidence{
				PackageName: name, PackageVersion: version, Ecosystem: "pypi",
				SpdxID: "", Source: "spdx_pkg", Confidence: 0.7,
				RawText: licenseHdr,
			})
		default:
			for _, t := range troves {
				out = append(out, deptree.LicenseEvidence{
					PackageName: name, PackageVersion: version, Ecosystem: "pypi",
					SpdxID: "", Source: "trove", Confidence: 0.6,
					RawText: t,
				})
			}
		}
		return filepath.SkipDir
	})
	if walkErr != nil {
		return out, fmt.Errorf("walk %s: %w", sitePackagesDir, walkErr)
	}
	return out, nil
}

func parsePyPIMetadata(raw []byte) (name, version, licenseExpr, licenseHdr string, troves []string) {
	const trovePrefix = "License ::"
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "License-Expression:"):
			licenseExpr = strings.TrimSpace(strings.TrimPrefix(line, "License-Expression:"))
		case strings.HasPrefix(line, "License:"):
			licenseHdr = strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		case strings.HasPrefix(line, "Classifier:"):
			c := strings.TrimSpace(strings.TrimPrefix(line, "Classifier:"))
			if strings.HasPrefix(c, trovePrefix) {
				troves = append(troves, c)
			}
		}
	}
	return name, version, licenseExpr, licenseHdr, troves
}
