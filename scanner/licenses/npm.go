package licenses

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPackageJSONBytes caps a single “package.json“ read in
// node_modules.  Mirrors scanner/npm/parser.go's local constant.
const maxPackageJSONBytes = 4 << 20 // 4 MiB

// maxLicenseFileBytes caps a single LICENSE-file read in the
// package.json-less fallback path.  License files are tiny (the GPL is
// ~35 KiB); 256 KiB is a generous ceiling that still bounds a hostile file.
const maxLicenseFileBytes = 256 << 10 // 256 KiB

// licenseFileNames are the conventional license-file names we probe, in
// priority order, when a package.json carries no “license“/“licenses“
// field. Matched case-insensitively against directory entries.
var licenseFileNames = []string{
	"license",
	"license.md",
	"license.txt",
	"licence",
	"licence.md",
	"copying",
}

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
		if d.IsDir() && pathfilter.ShouldSkipDir(path) {
			return filepath.SkipDir
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
		before := len(out)
		if pj.LicenseString != "" {
			emit(pj.LicenseString, pj.LicenseString, 0.95)
		}
		for _, lic := range pj.LicenseArray {
			if lic.Type != "" {
				emit(lic.Type, lic.Type, 0.7)
			}
		}
		// Fallback: package.json declared no license. Many (often older)
		// packages ship the license only as a LICENSE file. Emit its title
		// line (e.g. "MIT License") as low-confidence evidence — the server
		// normalizes common license names to an SPDX id. spdx left empty so
		// the server is the single source of truth for the mapping.
		if len(out) == before {
			if title := licenseFileTitle(path); title != "" {
				out = append(out, deptree.LicenseEvidence{
					PackageName:    pj.Name,
					PackageVersion: pj.Version,
					Ecosystem:      "npm",
					SpdxID:         "",
					Source:         "copyright_file",
					Confidence:     0.5,
					RawText:        title,
				})
			}
		}
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("walk %s: %w", nodeModulesDir, walkErr)
	}
	return out, nil
}

// licenseFileTitle returns the first non-empty, non-copyright line of the
// first conventional license file found in dir — the "title" line that names
// the license (e.g. "MIT License", "Apache License, Version 2.0"). Returns ""
// when no license file exists or it opens with a bare copyright/permission
// line that doesn't name a license (the server can't map those, so emitting
// them would just add noise). Truncated so a malformed file can't bloat the
// payload.
func licenseFileTitle(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	// Map lower-cased entry name -> actual name, so we can match
	// case-insensitively (LICENSE vs License vs license) without a stat storm.
	actual := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			actual[strings.ToLower(e.Name())] = e.Name()
		}
	}
	for _, want := range licenseFileNames {
		name, ok := actual[want]
		if !ok {
			continue
		}
		raw, err := safeio.ReadFile(filepath.Join(dir, name), maxLicenseFileBytes)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			t := strings.TrimSpace(line)
			if t == "" {
				continue
			}
			// Skip a leading copyright/permission line — it names no license,
			// so the server normalizer can't resolve it. The license name (if
			// the file has a title) comes first; otherwise there's nothing
			// useful to emit.
			low := strings.ToLower(t)
			if strings.HasPrefix(low, "copyright") || strings.HasPrefix(low, "permission is hereby") {
				return ""
			}
			if len(t) > 120 {
				t = t[:120]
			}
			return t
		}
		return ""
	}
	return ""
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
