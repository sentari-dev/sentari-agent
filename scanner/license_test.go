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

func TestNormalizeLicense_ClassifierFormat(t *testing.T) {
	spdx, tier := NormalizeLicenseClassifier("License :: OSI Approved :: MIT License")
	if spdx != "MIT" {
		t.Errorf("got spdx %q, want MIT", spdx)
	}
	if tier != "permissive" {
		t.Errorf("got tier %q, want permissive", tier)
	}
}

func TestNormalizeLicenseClassifier_Unknown(t *testing.T) {
	spdx, tier := NormalizeLicenseClassifier("License :: Other/Proprietary License")
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

func TestExtractLicenseFromDpkgStatus(t *testing.T) {
	content := "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nLicense: MIT\n"
	raw := ExtractLicenseFromDebCopyright(content)
	if raw != "MIT" {
		t.Errorf("got %q, want MIT", raw)
	}
}
