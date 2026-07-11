package scanner

import "testing"

func TestNormalizeLicense_ExactMatch(t *testing.T) {
	cases := []struct {
		raw      string
		wantSPDX string
		wantTier string
	}{
		{"MIT License", "MIT", "permissive"},
		{"Apache Software License", "Apache-2.0", "permissive"},
		{"GNU General Public License v3 (GPLv3)", "GPL-3.0-only", "strong-copyleft"},
		{"BSD License", "BSD-3-Clause", "permissive"},
		{"Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0", "weak-copyleft"},
		{"GNU Lesser General Public License v3 (LGPLv3)", "LGPL-3.0-only", "weak-copyleft"},
		{"ISC License (ISCL)", "ISC", "permissive"},
		{"European Union Public Licence 1.2 (EUPL 1.2)", "EUPL-1.2", "strong-copyleft"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			spdx, tier := NormalizeLicense(tc.raw)
			if spdx != tc.wantSPDX {
				t.Errorf("NormalizeLicense(%q) spdx = %q, want %q", tc.raw, spdx, tc.wantSPDX)
			}
			if tier != tc.wantTier {
				t.Errorf("NormalizeLicense(%q) tier = %q, want %q", tc.raw, tier, tc.wantTier)
			}
		})
	}
}

func TestNormalizeLicense_CaseInsensitive(t *testing.T) {
	spdx, tier := NormalizeLicense("mit license")
	if spdx != "MIT" {
		t.Errorf("got spdx %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("got tier %q, want permissive", tier)
	}
}

func TestNormalizeLicense_Whitespace(t *testing.T) {
	spdx, _ := NormalizeLicense("  MIT License  ")
	if spdx != "MIT" {
		t.Errorf("got spdx %q, want MIT", spdx)
	}
}

func TestNormalizeLicense_Unknown(t *testing.T) {
	spdx, tier := NormalizeLicense("Some Custom Internal License v42")
	if spdx != "" {
		t.Errorf("got spdx %q, want empty", spdx)
	}
	if tier != "unknown" {
		t.Errorf("got tier %q, want unknown", tier)
	}
}

func TestNormalizeLicense_Empty(t *testing.T) {
	spdx, tier := NormalizeLicense("")
	if spdx != "" {
		t.Errorf("got spdx %q, want empty", spdx)
	}
	if tier != "unknown" {
		t.Errorf("got tier %q, want unknown", tier)
	}
}

func TestNormalizeLicense_SPDXPassthrough(t *testing.T) {
	cases := []struct {
		raw      string
		wantSPDX string
	}{
		{"MIT", "MIT"},
		{"Apache-2.0", "Apache-2.0"},
		{"GPL-3.0-only", "GPL-3.0-only"},
		{"LGPL-2.1-only", "LGPL-2.1-only"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			spdx, _ := NormalizeLicense(tc.raw)
			if spdx != tc.wantSPDX {
				t.Errorf("NormalizeLicense(%q) = %q, want %q", tc.raw, spdx, tc.wantSPDX)
			}
		})
	}
}

// The trove-classifier fallback lives inline in ExtractLicenseFromMetadata
// (the sole production consumer of "Classifier: License :: ..." lines).  These
// tests drive that production path directly.
func TestExtractLicenseFromMetadata_ClassifierFormat(t *testing.T) {
	raw, spdx, tier := ExtractLicenseFromMetadata("Classifier: License :: OSI Approved :: MIT License\n")
	if raw != "MIT License" {
		t.Errorf("got raw %q, want %q", raw, "MIT License")
	}
	if spdx != "MIT" {
		t.Errorf("got spdx %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("got tier %q, want permissive", tier)
	}
}

func TestExtractLicenseFromMetadata_ClassifierUnknown(t *testing.T) {
	raw, spdx, tier := ExtractLicenseFromMetadata("Classifier: License :: OSI Approved :: Nonexistent License\n")
	if raw != "Nonexistent License" {
		t.Errorf("got raw %q, want %q", raw, "Nonexistent License")
	}
	if spdx != "" {
		t.Errorf("got spdx %q, want empty", spdx)
	}
	if tier != "unknown" {
		t.Errorf("got tier %q, want unknown", tier)
	}
}

func TestLicenseMapOverlay(t *testing.T) {
	overlay := LicenseMap{
		SPDXMap: map[string]string{"custom internal lib": "LicenseRef-Internal"},
		TierMap: map[string]string{"LicenseRef-Internal": "proprietary"},
		Version: 5,
	}
	ApplyOverlay(overlay)
	defer ResetToDefaults()

	spdx, tier := NormalizeLicense("custom internal lib")
	if spdx != "LicenseRef-Internal" {
		t.Errorf("got spdx %q, want LicenseRef-Internal", spdx)
	}
	if tier != "proprietary" {
		t.Errorf("got tier %q, want proprietary", tier)
	}

	spdx2, _ := NormalizeLicense("MIT License")
	if spdx2 != "MIT" {
		t.Errorf("overlay broke defaults: got %q, want MIT", spdx2)
	}
}

func TestExtractLicenseFromMetadata(t *testing.T) {
	metadata := "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: Python HTTP for Humans.\nLicense: Apache-2.0\nClassifier: License :: OSI Approved :: Apache Software License\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "Apache-2.0" {
		t.Errorf("raw = %q, want Apache-2.0", raw)
	}
	if spdx != "Apache-2.0" {
		t.Errorf("spdx = %q, want Apache-2.0", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

func TestExtractLicenseFromMetadata_ClassifierFallback(t *testing.T) {
	metadata := "Metadata-Version: 2.1\nName: some-pkg\nVersion: 1.0.0\nClassifier: License :: OSI Approved :: MIT License\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "MIT License" {
		t.Errorf("raw = %q, want 'MIT License'", raw)
	}
	if spdx != "MIT" {
		t.Errorf("spdx = %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

func TestExtractLicenseFromMetadata_NoLicense(t *testing.T) {
	metadata := "Metadata-Version: 2.1\nName: unlicensed-pkg\nVersion: 0.0.1\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "" {
		t.Errorf("raw = %q, want empty", raw)
	}
	if spdx != "" {
		t.Errorf("spdx = %q, want empty", spdx)
	}
	if tier != "unknown" {
		t.Errorf("tier = %q, want unknown", tier)
	}
}

func TestExtractLicenseFromMetadata_HeaderBoundary(t *testing.T) {
	// The real license is the RFC822 header field ("License: MIT"). The long-
	// description body after the blank line is an embedded README that itself
	// contains a "License: GPL-3.0" line — it must NOT override the header.
	metadata := "Metadata-Version: 2.1\n" +
		"Name: some-pkg\n" +
		"Version: 1.0.0\n" +
		"License: MIT\n" +
		"\n" +
		"# some-pkg\n" +
		"\n" +
		"License: GPL-3.0\n" +
		"This project is distributed under the terms above.\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "MIT" {
		t.Errorf("raw = %q, want MIT (body License: line leaked through)", raw)
	}
	if spdx != "MIT" {
		t.Errorf("spdx = %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

// TestExtractLicenseFromMetadata_LicenseExpressionSimple — a PEP 639
// "License-Expression: MIT" header (setuptools >=77, no legacy License: field)
// resolves directly to the SPDX id + tier.
func TestExtractLicenseFromMetadata_LicenseExpressionSimple(t *testing.T) {
	metadata := "Metadata-Version: 2.4\nName: modern-pkg\nVersion: 2.0.0\nLicense-Expression: MIT\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "MIT" {
		t.Errorf("raw = %q, want MIT", raw)
	}
	if spdx != "MIT" {
		t.Errorf("spdx = %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

// TestExtractLicenseFromMetadata_LicenseExpressionCompound — a compound SPDX
// expression is resolved by its first operand (Apache-2.0) while the full
// original expression is preserved as the raw license.
func TestExtractLicenseFromMetadata_LicenseExpressionCompound(t *testing.T) {
	metadata := "Metadata-Version: 2.4\nName: dual-pkg\nVersion: 1.2.3\nLicense-Expression: Apache-2.0 OR MIT\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "Apache-2.0 OR MIT" {
		t.Errorf("raw = %q, want %q (full expression preserved)", raw, "Apache-2.0 OR MIT")
	}
	if spdx != "Apache-2.0" {
		t.Errorf("spdx = %q, want Apache-2.0 (first operand)", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

// TestExtractLicenseFromMetadata_LicenseExpressionWinsOverLegacy — per PEP 639,
// License-Expression takes precedence over both a legacy License: header and
// Trove classifiers when all are present.
func TestExtractLicenseFromMetadata_LicenseExpressionWinsOverLegacy(t *testing.T) {
	metadata := "Metadata-Version: 2.4\n" +
		"Name: mixed-pkg\n" +
		"Version: 1.0.0\n" +
		"License: GPL-3.0\n" +
		"License-Expression: MIT\n" +
		"Classifier: License :: OSI Approved :: GNU General Public License v3 (GPLv3)\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "MIT" {
		t.Errorf("raw = %q, want MIT (License-Expression must win)", raw)
	}
	if spdx != "MIT" {
		t.Errorf("spdx = %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

// TestExtractLicenseFromMetadata_LicenseExpressionBodyIgnored — a
// "License-Expression:" line that appears in the long-description body (after
// the RFC822 blank line) must NOT override the real header field.
func TestExtractLicenseFromMetadata_LicenseExpressionBodyIgnored(t *testing.T) {
	metadata := "Metadata-Version: 2.4\n" +
		"Name: body-pkg\n" +
		"Version: 1.0.0\n" +
		"License: MIT\n" +
		"\n" +
		"# body-pkg\n" +
		"\n" +
		"License-Expression: GPL-3.0-only\n"
	raw, spdx, tier := ExtractLicenseFromMetadata(metadata)
	if raw != "MIT" {
		t.Errorf("raw = %q, want MIT (body License-Expression leaked through)", raw)
	}
	if spdx != "MIT" {
		t.Errorf("spdx = %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

func TestExtractLicenseFromCondaJSON(t *testing.T) {
	condaJSON := `{"name": "numpy", "version": "1.26.4", "license": "BSD 3-Clause License"}`
	raw, spdx, tier := ExtractLicenseFromCondaJSON([]byte(condaJSON))
	if raw != "BSD 3-Clause License" {
		t.Errorf("raw = %q, want 'BSD 3-Clause License'", raw)
	}
	if spdx != "BSD-3-Clause" {
		t.Errorf("spdx = %q, want BSD-3-Clause", spdx)
	}
	if tier != "permissive" {
		t.Errorf("tier = %q, want permissive", tier)
	}
}

func TestExtractLicenseFromCondaJSON_Missing(t *testing.T) {
	condaJSON := `{"name": "pkg", "version": "1.0"}`
	raw, spdx, tier := ExtractLicenseFromCondaJSON([]byte(condaJSON))
	if raw != "" || spdx != "" {
		t.Errorf("expected empty, got raw=%q spdx=%q", raw, spdx)
	}
	if tier != "unknown" {
		t.Errorf("tier = %q, want unknown", tier)
	}
}

// TestNormalizeLicense_BareAndTroveCopyleft pins the fix for the
// previously-missed bare/Trove-classifier license strings that silently
// resolved to tier "unknown" — letting a copyleft-flagging policy miss
// GPL/LGPL/AGPL packages.  Each string must now resolve to a concrete
// SPDX id and a non-"unknown" copyleft/permissive tier.
func TestNormalizeLicense_BareAndTroveCopyleft(t *testing.T) {
	cases := []struct {
		raw      string
		wantSPDX string
		wantTier string
	}{
		// LGPL — weak-copyleft; unversioned resolves to -3.0-only, matching
		// the existing bare "lgpl" convention.
		{"GNU Library or Lesser General Public License (LGPL)", "LGPL-3.0-only", "weak-copyleft"},
		{"GNU Lesser General Public License (LGPL)", "LGPL-3.0-only", "weak-copyleft"},
		// GPL — strong-copyleft.
		{"GNU General Public License (GPL)", "GPL-3.0-only", "strong-copyleft"},
		{"GPL", "GPL-3.0-only", "strong-copyleft"},
		// AGPL — strong-copyleft.
		{"GNU Affero General Public License (AGPL)", "AGPL-3.0-only", "strong-copyleft"},
		{"AGPL", "AGPL-3.0-only", "strong-copyleft"},
		// Apache — permissive.
		{"Apache", "Apache-2.0", "permissive"},
		{"Apache License", "Apache-2.0", "permissive"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			spdx, tier := NormalizeLicense(tc.raw)
			if spdx != tc.wantSPDX {
				t.Errorf("NormalizeLicense(%q) spdx = %q, want %q", tc.raw, spdx, tc.wantSPDX)
			}
			if tier != tc.wantTier {
				t.Errorf("NormalizeLicense(%q) tier = %q, want %q", tc.raw, tier, tc.wantTier)
			}
			if tier == "unknown" {
				t.Errorf("NormalizeLicense(%q) regressed to tier=unknown", tc.raw)
			}
		})
	}
}

// TestExtractLicenseFromMetadata_TroveCopyleftClassifiers drives the same
// strings through the production Trove-classifier fallback path — the real
// consumer of these bare license names in pip METADATA.
func TestExtractLicenseFromMetadata_TroveCopyleftClassifiers(t *testing.T) {
	cases := []struct {
		classifier string
		wantRaw    string
		wantSPDX   string
		wantTier   string
	}{
		{
			"Classifier: License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)\n",
			"GNU Library or Lesser General Public License (LGPL)", "LGPL-3.0-only", "weak-copyleft",
		},
		{
			"Classifier: License :: OSI Approved :: GNU General Public License (GPL)\n",
			"GNU General Public License (GPL)", "GPL-3.0-only", "strong-copyleft",
		},
	}
	for _, tc := range cases {
		t.Run(tc.wantSPDX, func(t *testing.T) {
			raw, spdx, tier := ExtractLicenseFromMetadata(tc.classifier)
			if raw != tc.wantRaw {
				t.Errorf("raw = %q, want %q", raw, tc.wantRaw)
			}
			if spdx != tc.wantSPDX {
				t.Errorf("spdx = %q, want %q", spdx, tc.wantSPDX)
			}
			if tier != tc.wantTier {
				t.Errorf("tier = %q, want %q", tier, tc.wantTier)
			}
		})
	}
}

func TestExtractLicenseFromDpkgStatus(t *testing.T) {
	content := "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nLicense: MIT\n"
	raw := ExtractLicenseFromDebCopyright(content)
	if raw != "MIT" {
		t.Errorf("got %q, want MIT", raw)
	}
}
