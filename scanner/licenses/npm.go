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
			if name := detectLicenseFile(path); name != "" {
				out = append(out, deptree.LicenseEvidence{
					PackageName:    pj.Name,
					PackageVersion: pj.Version,
					Ecosystem:      "npm",
					SpdxID:         "",
					Source:         "copyright_file",
					Confidence:     0.5,
					RawText:        name,
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

// licenseSignature recognises a license from its body text. “must“ is a
// list of (lowercased) substrings that all have to appear in the file; the
// first signature in declaration order whose “must“ set matches wins, so
// more-specific licenses (LGPL, AGPL, BSD-3-Clause) must be listed before
// their less-specific cousins (GPL, BSD-2-Clause). “emit“ is the raw_text
// the agent sends to the server — chosen to be something the server
// normalizer already maps to an SPDX id.
type licenseSignature struct {
	emit string
	must []string
}

var licenseSignatures = []licenseSignature{
	// MIT — the dominant npm license, identified by its hereby-granted clause.
	{emit: "MIT License", must: []string{"permission is hereby granted, free of charge"}},
	// ISC — distinctive "without fee" wording.
	{emit: "ISC", must: []string{"permission to use, copy, modify", "with or without fee"}},
	// Apache 2.0.
	{emit: "Apache-2.0", must: []string{"apache license", "version 2.0"}},
	// AGPL/LGPL must precede plain GPL (their bodies contain the GPL phrase).
	{emit: "AGPL-3.0-only", must: []string{"affero general public license", "version 3"}},
	{emit: "LGPL-3.0-only", must: []string{"lesser general public license", "version 3"}},
	{emit: "LGPL-2.1-only", must: []string{"lesser general public license", "version 2.1"}},
	{emit: "GPL-3.0-only", must: []string{"gnu general public license", "version 3"}},
	{emit: "GPL-2.0-only", must: []string{"gnu general public license", "version 2"}},
	// BSD — 3-clause requires the no-endorse clause, so list it first.
	{emit: "BSD-3-Clause", must: []string{
		"redistribution and use in source and binary forms",
		"endorse or promote",
	}},
	{emit: "BSD-2-Clause", must: []string{"redistribution and use in source and binary forms"}},
	{emit: "MPL-2.0", must: []string{"mozilla public license", "version 2.0"}},
	{emit: "Unlicense", must: []string{
		"this is free and unencumbered software released into the public domain",
	}},
}

// detectLicenseFile returns the license name (as raw text the server normalizer
// can map) for the first conventional license file found in dir. Strategy:
//
//  1. **Body-signature scan** — recognise the licence from a distinctive phrase
//     anywhere in the file. This is what catches the dominant case where the
//     MIT/BSD/Apache body has *no* title line (the file opens with the
//     copyright notice).
//  2. **Title-line fallback** — if no signature matched, take the first
//     non-empty, non-copyright line as the license name (covers files that do
//     carry a title like “MIT License“ and rare licenses we don't classify).
//
// Returns "" when no license file exists or neither strategy produces a
// resolvable signal.
func detectLicenseFile(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	// Case-insensitive lookup table for the entries — LICENSE vs License vs
	// license — without a stat storm.
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
		low := strings.ToLower(string(raw))
		for _, sig := range licenseSignatures {
			matched := true
			for _, m := range sig.must {
				if !strings.Contains(low, m) {
					matched = false
					break
				}
			}
			if matched {
				return sig.emit
			}
		}
		// No body signature matched — fall back to the title line if it isn't
		// a bare copyright/permission opener.
		for _, line := range strings.Split(string(raw), "\n") {
			t := strings.TrimSpace(line)
			if t == "" {
				continue
			}
			lowLine := strings.ToLower(t)
			if strings.HasPrefix(lowLine, "copyright") ||
				strings.HasPrefix(lowLine, "permission is hereby") {
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
