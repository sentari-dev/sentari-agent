package licenses

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPackageJSONBytes caps a single ``package.json`` read in
// node_modules.  Mirrors scanner/npm/parser.go's local constant.
const maxPackageJSONBytes = 4 << 20 // 4 MiB

// ExtractNpm walks node_modules and reads each package's package.json
// for the `license` (string SPDX) or `licenses` (array of {type,url}).
// Confidence 0.95 for explicit SPDX, 0.7 for object-shape that's
// non-SPDX-ish.
func ExtractNpm(nodeModulesDir string) ([]deptree.LicenseEvidence, error) {
	var out []deptree.LicenseEvidence
	walkErr := filepath.WalkDir(nodeModulesDir, func(path string, d fs.DirEntry, err error) error {
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
		if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), "@") {
			return nil
		}
		pkgJSON := filepath.Join(path, "package.json")
		raw, err := safeio.ReadFile(pkgJSON, maxPackageJSONBytes)
		if err != nil {
			return nil
		}
		var pj npmPackageJSON
		if err := json.Unmarshal(raw, &pj); err != nil {
			return nil
		}
		if pj.Name == "" {
			return nil
		}
		emit := func(spdx, raw string, conf float64) {
			out = append(out, deptree.LicenseEvidence{
				PackageName:    pj.Name,
				PackageVersion: pj.Version,
				Ecosystem:      "npm",
				SpdxID:         spdx,
				Source:         "spdx_pkg",
				Confidence:     conf,
				RawText:        raw,
			})
		}
		if pj.LicenseString != "" {
			emit(pj.LicenseString, pj.LicenseString, 0.95)
		}
		for _, lic := range pj.LicenseArray {
			if lic.Type != "" {
				emit(lic.Type, lic.Type, 0.7)
			}
		}
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("walk %s: %w", nodeModulesDir, walkErr)
	}
	return out, nil
}

type npmPackageJSON struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	LicenseString string        `json:"-"`
	LicenseArray  []npmLicenseO `json:"licenses"`
}

type npmLicenseO struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Custom unmarshal because "license" can be either a string OR an
// object {type, url}. We map the string variant to LicenseString and
// the object variant by promoting it into the LicenseArray slot.
func (p *npmPackageJSON) UnmarshalJSON(data []byte) error {
	type alias struct {
		Name     string          `json:"name"`
		Version  string          `json:"version"`
		License  json.RawMessage `json:"license"`
		Licenses []npmLicenseO   `json:"licenses"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.Name = a.Name
	p.Version = a.Version
	p.LicenseArray = a.Licenses
	if len(a.License) == 0 {
		return nil
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(a.License, &s); err == nil {
		p.LicenseString = s
		return nil
	}
	// Object form.
	var o npmLicenseO
	if err := json.Unmarshal(a.License, &o); err == nil {
		p.LicenseArray = append(p.LicenseArray, o)
	}
	return nil
}
