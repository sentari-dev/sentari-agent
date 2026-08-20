package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// TestResolveLicensesFromRecordSPDX: a record carrying both a normalized SPDX
// id and a raw license string projects the SPDX-expression CycloneDX form and
// populates both SPDX fields from the record.
func TestResolveLicensesFromRecordSPDX(t *testing.T) {
	pkg := scanner.PackageRecord{
		Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip,
		LicenseSPDX: "Apache-2.0", LicenseRaw: "Apache License 2.0",
	}
	got := resolveComponentLicenses(pkg, newLicenseIndex(nil))
	if len(got.cyclonedx) != 1 || got.cyclonedx[0].Expression != "Apache-2.0" || got.cyclonedx[0].License != nil {
		t.Errorf("cyclonedx = %+v, want [{Expression:Apache-2.0}]", got.cyclonedx)
	}
	if got.concluded != "Apache-2.0" {
		t.Errorf("concluded = %q, want Apache-2.0", got.concluded)
	}
	if got.declared != "Apache License 2.0" {
		t.Errorf("declared = %q, want Apache License 2.0", got.declared)
	}
}

// TestResolveLicensesRawOnlyNameFallback: a record with only a raw license and
// no SPDX id projects the CycloneDX name form (a deliberate superset over the
// server, which omits it) and leaves concluded as NOASSERTION.
func TestResolveLicensesRawOnlyNameFallback(t *testing.T) {
	pkg := scanner.PackageRecord{
		Name: "legacycorp-sdk", Version: "4.2.0", EnvType: "npm",
		LicenseRaw: "Custom Corp License",
	}
	got := resolveComponentLicenses(pkg, newLicenseIndex(nil))
	if len(got.cyclonedx) != 1 || got.cyclonedx[0].License == nil || got.cyclonedx[0].License.Name != "Custom Corp License" {
		t.Errorf("cyclonedx = %+v, want [{License:{Name:Custom Corp License}}]", got.cyclonedx)
	}
	if got.cyclonedx[0].Expression != "" {
		t.Errorf("expression = %q, want empty", got.cyclonedx[0].Expression)
	}
	if got.concluded != "NOASSERTION" {
		t.Errorf("concluded = %q, want NOASSERTION", got.concluded)
	}
	if got.declared != "Custom Corp License" {
		t.Errorf("declared = %q, want Custom Corp License", got.declared)
	}
}

// TestResolveLicensesUnknownOmitted: no license anywhere → CycloneDX licenses
// omitted (nil, never a NOASSERTION placeholder), SPDX triple all NOASSERTION.
func TestResolveLicensesUnknownOmitted(t *testing.T) {
	pkg := scanner.PackageRecord{Name: "mystery", Version: "1.0.0", EnvType: scanner.EnvPip}
	got := resolveComponentLicenses(pkg, newLicenseIndex(nil))
	if got.cyclonedx != nil {
		t.Errorf("cyclonedx = %+v, want nil", got.cyclonedx)
	}
	if got.concluded != "NOASSERTION" || got.declared != "NOASSERTION" || got.copyright != "NOASSERTION" {
		t.Errorf("triple = (%q,%q,%q), want all NOASSERTION", got.concluded, got.declared, got.copyright)
	}
}

// TestResolveLicensesEvidenceSpdxFallback: record has no license fields but
// LicenseEvidence carries an SPDX id for the coordinate → that id drives the
// CycloneDX expression and concluded field.
func TestResolveLicensesEvidenceSpdxFallback(t *testing.T) {
	pkg := scanner.PackageRecord{Name: "evidence-pkg", Version: "1.0.0", EnvType: scanner.EnvPip}
	idx := newLicenseIndex([]deptree.LicenseEvidence{
		{PackageName: "evidence-pkg", PackageVersion: "1.0.0", Ecosystem: "pypi", SpdxID: "MIT", Confidence: 0.9},
	})
	got := resolveComponentLicenses(pkg, idx)
	if len(got.cyclonedx) != 1 || got.cyclonedx[0].Expression != "MIT" {
		t.Errorf("cyclonedx = %+v, want [{Expression:MIT}]", got.cyclonedx)
	}
	if got.concluded != "MIT" {
		t.Errorf("concluded = %q, want MIT", got.concluded)
	}
}

// TestResolveLicensesEvidenceCopyrightText: evidence RawText becomes the SPDX
// copyrightText while record fields still drive concluded/declared.
func TestResolveLicensesEvidenceCopyrightText(t *testing.T) {
	pkg := scanner.PackageRecord{
		Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip,
		LicenseSPDX: "Apache-2.0", LicenseRaw: "Apache License 2.0",
	}
	idx := newLicenseIndex([]deptree.LicenseEvidence{
		{PackageName: "requests", PackageVersion: "2.31.0", Ecosystem: "pypi", SpdxID: "Apache-2.0", Confidence: 0.95, RawText: "Copyright 2024 Example"},
	})
	got := resolveComponentLicenses(pkg, idx)
	if got.copyright != "Copyright 2024 Example" {
		t.Errorf("copyright = %q, want Copyright 2024 Example", got.copyright)
	}
	if got.concluded != "Apache-2.0" || got.declared != "Apache License 2.0" {
		t.Errorf("concluded/declared = (%q,%q), want (Apache-2.0, Apache License 2.0)", got.concluded, got.declared)
	}
}

// TestLicenseIndexBestPickDeterministic: two evidence rows for one coordinate,
// with the lower-confidence row listed first and again in reversed input order,
// must resolve to the same pick (Confidence desc, then Source/SpdxID/RawText
// asc) regardless of input order.
func TestLicenseIndexBestPickDeterministic(t *testing.T) {
	low := deptree.LicenseEvidence{PackageName: "pkg", PackageVersion: "1.0.0", Ecosystem: "pypi", SpdxID: "MIT", Confidence: 0.5}
	high := deptree.LicenseEvidence{PackageName: "pkg", PackageVersion: "1.0.0", Ecosystem: "pypi", SpdxID: "Apache-2.0", Confidence: 0.9}
	key := coordKey("pypi", "pkg", "1.0.0")

	forward := newLicenseIndex([]deptree.LicenseEvidence{low, high})
	reversed := newLicenseIndex([]deptree.LicenseEvidence{high, low})
	if forward[key].SpdxID != "Apache-2.0" {
		t.Errorf("forward pick = %q, want Apache-2.0 (higher confidence)", forward[key].SpdxID)
	}
	if reversed[key].SpdxID != "Apache-2.0" {
		t.Errorf("reversed pick = %q, want Apache-2.0 (higher confidence)", reversed[key].SpdxID)
	}
}

// TestLicenseIndexKeyFolding: evidence naming "Typing_Extensions" resolves for
// a record named "typing-extensions" through the shared coordKey/foldName.
func TestLicenseIndexKeyFolding(t *testing.T) {
	pkg := scanner.PackageRecord{Name: "typing-extensions", Version: "4.9.0", EnvType: scanner.EnvPip}
	idx := newLicenseIndex([]deptree.LicenseEvidence{
		{PackageName: "Typing_Extensions", PackageVersion: "4.9.0", Ecosystem: "pypi", SpdxID: "PSF-2.0", Confidence: 0.9},
	})
	got := resolveComponentLicenses(pkg, idx)
	if got.concluded != "PSF-2.0" {
		t.Errorf("concluded = %q, want PSF-2.0 (evidence matched via name folding)", got.concluded)
	}
}

// TestCycloneDXComponentCarriesLicenses generates a document with three license
// states and asserts the rendered "licenses" key by unmarshalling to raw maps
// (proving the key is present or absent, not just the typed field).
func TestCycloneDXComponentCarriesLicenses(t *testing.T) {
	res := &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, LicenseSPDX: "Apache-2.0", LicenseRaw: "Apache License 2.0"},
			{Name: "legacycorp-sdk", Version: "4.2.0", EnvType: "npm", LicenseRaw: "LegacyCorp Proprietary"},
			{Name: "mystery", Version: "1.0.0", EnvType: scanner.EnvPip},
		},
	}
	data, err := GenerateCycloneDX(res)
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	byName := map[string]map[string]any{}
	for _, c := range doc["components"].([]any) {
		m := c.(map[string]any)
		byName[m["name"].(string)] = m
	}

	// SPDX-expression form.
	spdxLic := byName["requests"]["licenses"].([]any)
	if len(spdxLic) != 1 {
		t.Fatalf("requests licenses = %v, want one entry", spdxLic)
	}
	if spdxLic[0].(map[string]any)["expression"] != "Apache-2.0" {
		t.Errorf("requests license = %v, want {expression: Apache-2.0}", spdxLic[0])
	}

	// Raw name-form fallback.
	rawLic := byName["legacycorp-sdk"]["licenses"].([]any)
	nested := rawLic[0].(map[string]any)["license"].(map[string]any)
	if nested["name"] != "LegacyCorp Proprietary" {
		t.Errorf("legacycorp-sdk license = %v, want {license:{name: LegacyCorp Proprietary}}", rawLic[0])
	}

	// Unknown → no licenses key at all.
	if _, present := byName["mystery"]["licenses"]; present {
		t.Errorf("mystery has a licenses key, want omitted")
	}
}

// TestCycloneDXComponentsSortedByRef asserts components are emitted in stable
// ref order regardless of input order.
func TestCycloneDXComponentsSortedByRef(t *testing.T) {
	res := &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "Newtonsoft.Json", Version: "13.0.3", EnvType: "nuget"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip},
			{Name: "org.apache.commons:commons-lang3", Version: "3.14.0", EnvType: "jvm"},
		},
	}
	data, err := GenerateCycloneDX(res)
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{
		"pkg:maven/org.apache.commons/commons-lang3@3.14.0",
		"pkg:nuget/Newtonsoft.Json@13.0.3",
		"pkg:pypi/requests@2.31.0",
	}
	for i, w := range want {
		if bom.Components[i].BOMRef != w {
			t.Errorf("component[%d] ref = %q, want %q", i, bom.Components[i].BOMRef, w)
		}
	}
}
