// Package scanner — license normalization and tier classification.
//
// This module maps raw license strings (from pip METADATA, conda JSON, deb
// copyright files, etc.) to SPDX identifiers and classifies them into risk
// tiers: permissive, weak-copyleft, strong-copyleft, proprietary, unknown.
//
// The mapping table can be extended at runtime via server-pushed overlays
// (for org-specific licenses like LicenseRef-*).
package scanner

import (
	"encoding/json"
	"strings"
	"sync"
)

// LicenseMap holds SPDX normalization and tier classification data.
type LicenseMap struct {
	SPDXMap map[string]string `json:"spdx_map"`
	TierMap map[string]string `json:"tier_map"`
	Version int               `json:"version"`
}

var (
	mu         sync.RWMutex
	activeSPDX map[string]string
	activeTier map[string]string
	mapVersion int
)

func init() {
	activeSPDX = make(map[string]string, len(defaultSPDXMap))
	for k, v := range defaultSPDXMap {
		activeSPDX[k] = v
	}
	activeTier = make(map[string]string, len(defaultTierMap))
	for k, v := range defaultTierMap {
		activeTier[k] = v
	}
}

// NormalizeLicense takes a raw license string and returns (spdxID, tier).
// Returns ("", "unknown") if the license cannot be identified.
func NormalizeLicense(raw string) (string, string) {
	if raw == "" {
		return "", "unknown"
	}

	normalized := strings.ToLower(strings.TrimSpace(raw))

	mu.RLock()
	defer mu.RUnlock()

	// 1. Check if raw is already a valid SPDX ID (case-sensitive lookup in tier map).
	trimmed := strings.TrimSpace(raw)
	if _, ok := activeTier[trimmed]; ok {
		return trimmed, activeTier[trimmed]
	}

	// 2. Exact match in SPDX map (lowercased).
	if spdx, ok := activeSPDX[normalized]; ok {
		tier := activeTier[spdx]
		if tier == "" {
			tier = "unknown"
		}
		return spdx, tier
	}

	// 3. Fuzzy: strip common suffixes/prefixes and retry.
	fuzzy := normalized
	for _, strip := range []string{"license", "licence", "the ", "a "} {
		fuzzy = strings.ReplaceAll(fuzzy, strip, "")
	}
	fuzzy = strings.TrimSpace(fuzzy)
	if fuzzy != normalized {
		if spdx, ok := activeSPDX[fuzzy]; ok {
			tier := activeTier[spdx]
			if tier == "" {
				tier = "unknown"
			}
			return spdx, tier
		}
	}

	return "", "unknown"
}

// NormalizeLicenseClassifier extracts the license name from a Python trove
// classifier string like "License :: OSI Approved :: MIT License" and
// normalizes it.
func NormalizeLicenseClassifier(classifier string) (string, string) {
	parts := strings.Split(classifier, " :: ")
	if len(parts) < 3 {
		return "", "unknown"
	}
	// The last part is the license name, e.g. "MIT License".
	return NormalizeLicense(parts[len(parts)-1])
}

// ApplyOverlay merges an overlay map on top of the defaults.
func ApplyOverlay(overlay LicenseMap) {
	mu.Lock()
	defer mu.Unlock()
	for k, v := range overlay.SPDXMap {
		activeSPDX[strings.ToLower(strings.TrimSpace(k))] = v
	}
	for k, v := range overlay.TierMap {
		activeTier[k] = v
	}
	mapVersion = overlay.Version
}

// ResetToDefaults restores the mapping tables to built-in defaults.
func ResetToDefaults() {
	mu.Lock()
	defer mu.Unlock()
	activeSPDX = make(map[string]string, len(defaultSPDXMap))
	for k, v := range defaultSPDXMap {
		activeSPDX[k] = v
	}
	activeTier = make(map[string]string, len(defaultTierMap))
	for k, v := range defaultTierMap {
		activeTier[k] = v
	}
	mapVersion = 0
}

// MapVersion returns the current version of the active license map.
func MapVersion() int {
	mu.RLock()
	defer mu.RUnlock()
	return mapVersion
}

// Cached license-map overlays are loaded and persisted only as signed
// envelopes — see scanner/signed_map.go (LoadVerifiedOverlayFromFile,
// SaveVerifiedEnvelopeToFile).  Unsigned load/save helpers used to live
// here in v0.12-pre and were removed in ADR 0001 to prevent accidental
// bypass of signature verification.

// ExtractLicenseFromMetadata parses a Python METADATA or PKG-INFO file content
// and returns (rawLicense, spdxID, tier).
// It first looks for a "License:" header; if absent, falls back to
// "Classifier: License :: ..." trove classifiers.
func ExtractLicenseFromMetadata(content string) (string, string, string) {
	var licenseRaw string
	var classifierLicense string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")

		if strings.HasPrefix(line, "License:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
			if val != "" && val != "UNKNOWN" {
				licenseRaw = val
			}
		}

		if strings.HasPrefix(line, "Classifier: License ::") && classifierLicense == "" {
			parts := strings.Split(line, " :: ")
			if len(parts) >= 3 {
				classifierLicense = parts[len(parts)-1]
			}
		}
	}

	if licenseRaw != "" {
		spdx, tier := NormalizeLicense(licenseRaw)
		return licenseRaw, spdx, tier
	}

	if classifierLicense != "" {
		spdx, tier := NormalizeLicense(classifierLicense)
		return classifierLicense, spdx, tier
	}

	return "", "", "unknown"
}

// ExtractLicenseFromCondaJSON extracts the license field from a conda-meta
// JSON file and normalizes it. Returns (raw, spdxID, tier).
func ExtractLicenseFromCondaJSON(data []byte) (string, string, string) {
	var meta struct {
		License string `json:"license"`
	}
	if err := json.Unmarshal(data, &meta); err != nil || meta.License == "" {
		return "", "", "unknown"
	}
	spdx, tier := NormalizeLicense(meta.License)
	return meta.License, spdx, tier
}

// ExtractLicenseFromDebCopyright extracts the first License: value from a
// Debian machine-readable copyright file.
func ExtractLicenseFromDebCopyright(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "License:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
			if val != "" {
				return val
			}
		}
	}
	return ""
}

// --- Default mapping tables ---

// defaultSPDXMap maps lowercased raw license strings to SPDX identifiers.
var defaultSPDXMap = map[string]string{
	// Permissive
	"mit license":                          "MIT",
	"mit":                                  "MIT",
	"apache software license":              "Apache-2.0",
	"apache software license 2.0":          "Apache-2.0",
	"apache license 2.0":                   "Apache-2.0",
	"apache license, version 2.0":          "Apache-2.0",
	"apache 2.0":                           "Apache-2.0",
	"apache-2.0":                           "Apache-2.0",
	"bsd license":                          "BSD-3-Clause",
	"bsd":                                  "BSD-3-Clause",
	"bsd 3-clause license":                 "BSD-3-Clause",
	"new bsd license":                      "BSD-3-Clause",
	"modified bsd license":                 "BSD-3-Clause",
	"3-clause bsd license":                 "BSD-3-Clause",
	"bsd-3-clause":                         "BSD-3-Clause",
	"bsd 2-clause license":                 "BSD-2-Clause",
	"simplified bsd license":               "BSD-2-Clause",
	"bsd-2-clause":                         "BSD-2-Clause",
	"isc license":                          "ISC",
	"isc license (iscl)":                   "ISC",
	"isc":                                  "ISC",
	"python software foundation license":   "PSF-2.0",
	"psf license":                          "PSF-2.0",
	"psf":                                  "PSF-2.0",
	"public domain":                        "Unlicense",
	"the unlicense (unlicense)":            "Unlicense",
	"unlicense":                            "Unlicense",
	"creative commons zero v1.0 universal": "CC0-1.0",
	"cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
	"zlib license":            "Zlib",
	"zlib/libpng license":     "Zlib",
	"boost software license 1.0": "BSL-1.0",
	"artistic license 2.0":    "Artistic-2.0",
	"unicode license v3":      "Unicode-3.0",

	// Weak copyleft
	"gnu lesser general public license v2 (lgplv2)":           "LGPL-2.0-only",
	"gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
	"gnu lesser general public license v3 (lgplv3)":           "LGPL-3.0-only",
	"gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
	"lgpl-2.1":                                "LGPL-2.1-only",
	"lgpl-3.0":                                "LGPL-3.0-only",
	"lgpl":                                    "LGPL-3.0-only",
	"mozilla public license 2.0 (mpl 2.0)":    "MPL-2.0",
	"mozilla public license 2.0":              "MPL-2.0",
	"mpl-2.0":                                 "MPL-2.0",
	"mpl 2.0":                                 "MPL-2.0",
	"eclipse public license 2.0":              "EPL-2.0",
	"eclipse public license 1.0":              "EPL-1.0",
	"epl-2.0":                                 "EPL-2.0",
	"common development and distribution license 1.0": "CDDL-1.0",

	// Strong copyleft
	"gnu general public license v2 (gplv2)":                       "GPL-2.0-only",
	"gnu general public license v2 or later (gplv2+)":             "GPL-2.0-or-later",
	"gnu general public license v3 (gplv3)":                       "GPL-3.0-only",
	"gnu general public license v3 or later (gplv3+)":             "GPL-3.0-or-later",
	"gpl-2.0":        "GPL-2.0-only",
	"gpl-3.0":        "GPL-3.0-only",
	"gplv2":          "GPL-2.0-only",
	"gplv3":          "GPL-3.0-only",
	"gpl v3":         "GPL-3.0-only",
	"gpl v2":         "GPL-2.0-only",
	"gnu affero general public license v3":                        "AGPL-3.0-only",
	"gnu affero general public license v3 or later (agplv3+)":     "AGPL-3.0-or-later",
	"agpl-3.0":       "AGPL-3.0-only",
	"european union public licence 1.2 (eupl 1.2)": "EUPL-1.2",
	"eupl-1.2": "EUPL-1.2",
	"eupl 1.2": "EUPL-1.2",
}

// defaultTierMap maps SPDX identifiers to risk tiers.
var defaultTierMap = map[string]string{
	// Permissive
	"MIT":           "permissive",
	"Apache-2.0":    "permissive",
	"BSD-2-Clause":  "permissive",
	"BSD-3-Clause":  "permissive",
	"ISC":           "permissive",
	"PSF-2.0":       "permissive",
	"Unlicense":     "permissive",
	"CC0-1.0":       "permissive",
	"Zlib":          "permissive",
	"BSL-1.0":       "permissive",
	"Artistic-2.0":  "permissive",
	"Unicode-3.0":   "permissive",
	"0BSD":          "permissive",
	"BlueOak-1.0.0": "permissive",

	// Weak copyleft
	"LGPL-2.0-only":     "weak-copyleft",
	"LGPL-2.0-or-later": "weak-copyleft",
	"LGPL-2.1-only":     "weak-copyleft",
	"LGPL-2.1-or-later": "weak-copyleft",
	"LGPL-3.0-only":     "weak-copyleft",
	"LGPL-3.0-or-later": "weak-copyleft",
	"MPL-2.0":           "weak-copyleft",
	"EPL-1.0":           "weak-copyleft",
	"EPL-2.0":           "weak-copyleft",
	"CDDL-1.0":          "weak-copyleft",

	// Strong copyleft
	"GPL-2.0-only":      "strong-copyleft",
	"GPL-2.0-or-later":  "strong-copyleft",
	"GPL-3.0-only":      "strong-copyleft",
	"GPL-3.0-or-later":  "strong-copyleft",
	"AGPL-3.0-only":     "strong-copyleft",
	"AGPL-3.0-or-later": "strong-copyleft",
	"EUPL-1.2":          "strong-copyleft",
}
