package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// multiEcosystemResult builds a ScanResult with one record per relevant
// ecosystem so the SBOM generators can be checked for correct per-record
// purl typing.
func multiEcosystemResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		DeviceID:     "dev-1",
		Hostname:     "host-1",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip},
			{Name: "lodash", Version: "4.17.21", EnvType: "npm"},
			{Name: "openssl", Version: "3.0.2", EnvType: scanner.EnvSystemDeb},
		},
	}
}

// TestCycloneDXPurlPerEcosystem asserts each component gets a purl whose type
// matches its ecosystem rather than a hardcoded pkg:pypi/ prefix.
func TestCycloneDXPurlPerEcosystem(t *testing.T) {
	data, err := GenerateCycloneDX(multiEcosystemResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]string{
		"requests": "pkg:pypi/",
		"lodash":   "pkg:npm/",
		"openssl":  "pkg:deb/",
	}
	for _, c := range bom.Components {
		prefix, ok := want[c.Name]
		if !ok {
			continue
		}
		if !strings.HasPrefix(c.Purl, prefix) {
			t.Errorf("component %q: purl = %q, want prefix %q", c.Name, c.Purl, prefix)
		}
	}
}

// TestSPDXPurlPerEcosystem asserts the same per-ecosystem purl typing in SPDX
// external references.
func TestSPDXPurlPerEcosystem(t *testing.T) {
	data, err := GenerateSPDX(multiEcosystemResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]string{
		"requests": "pkg:pypi/",
		"lodash":   "pkg:npm/",
		"openssl":  "pkg:deb/",
	}
	for _, p := range doc.Packages {
		prefix, ok := want[p.Name]
		if !ok {
			continue
		}
		var purl string
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" {
				purl = ref.ReferenceLocator
			}
		}
		if purl == "" {
			t.Errorf("package %q: no purl external ref", p.Name)
			continue
		}
		if !strings.HasPrefix(purl, prefix) {
			t.Errorf("package %q: purl = %q, want prefix %q", p.Name, purl, prefix)
		}
	}
}

// TestPurlForMaven checks the maven group:artifact name is split into the
// pkg:maven/<group>/<artifact> shape.
func TestPurlForMaven(t *testing.T) {
	got := purlFor(scanner.PackageRecord{
		Name:    "org.apache.commons:commons-lang3",
		Version: "3.12.0",
		EnvType: "jvm",
	})
	want := "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
	if got != want {
		t.Errorf("purlFor maven = %q, want %q", got, want)
	}
}

// TestPurlForNpm checks npm purl construction for both unscoped and scoped
// packages. Per the package-url spec a scoped npm package is encoded as a
// namespace + name: the scope's leading "@" becomes "%40" and the "/" between
// scope and name is preserved as a real path separator (NOT %2F). Unscoped
// packages stay pkg:npm/<name>@<ver>.
func TestPurlForNpm(t *testing.T) {
	cases := []struct {
		name string
		pkg  string
		want string
	}{
		{"unscoped", "lodash", "pkg:npm/lodash@4.17.21"},
		{"scoped", "@angular/core", "pkg:npm/%40angular/core@4.17.21"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := purlFor(scanner.PackageRecord{
				Name:    tc.pkg,
				Version: "4.17.21",
				EnvType: "npm",
			})
			if got != tc.want {
				t.Errorf("purlFor npm %q = %q, want %q", tc.pkg, got, tc.want)
			}
		})
	}
}

// TestPurlForNoEcosystem checks that ecosystems with no meaningful purl
// (ai_agent, runtime/unknown) get an empty purl rather than a wrong one.
func TestPurlForNoEcosystem(t *testing.T) {
	for _, env := range []string{"ai_agent", "tcc", "container", "unknown_thing"} {
		got := purlFor(scanner.PackageRecord{Name: "foo", Version: "1.0", EnvType: env})
		if got != "" {
			t.Errorf("purlFor(%q) = %q, want empty", env, got)
		}
	}
}

// TestPurlForEmptyVersion checks no purl is emitted when version is empty
// (avoids pkg:npm/foo@ with a dangling separator).
func TestPurlForEmptyVersion(t *testing.T) {
	got := purlFor(scanner.PackageRecord{Name: "foo", Version: "", EnvType: "npm"})
	if got != "" {
		t.Errorf("purlFor empty version = %q, want empty", got)
	}
}

// TestSPDXRelationshipsDescribes asserts the SPDX document carries a
// DESCRIBES relationship from the document to every package.
func TestSPDXRelationshipsDescribes(t *testing.T) {
	data, err := GenerateSPDX(multiEcosystemResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Relationships) != len(doc.Packages) {
		t.Fatalf("relationships = %d, want %d (one DESCRIBES per package)",
			len(doc.Relationships), len(doc.Packages))
	}
	for _, p := range doc.Packages {
		found := false
		for _, r := range doc.Relationships {
			if r.SPDXElementID == "SPDXRef-DOCUMENT" &&
				r.RelationshipType == "DESCRIBES" &&
				r.RelatedSPDXElement == p.SPDXID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no DESCRIBES relationship for %q (%s)", p.Name, p.SPDXID)
		}
	}
}

// TestSPDXLicenseFields asserts every package sets licenseConcluded and
// licenseDeclared explicitly to NOASSERTION.
func TestSPDXLicenseFields(t *testing.T) {
	data, err := GenerateSPDX(multiEcosystemResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range doc.Packages {
		if p.LicenseConcluded != "NOASSERTION" {
			t.Errorf("package %q: licenseConcluded = %q, want NOASSERTION", p.Name, p.LicenseConcluded)
		}
		if p.LicenseDeclared != "NOASSERTION" {
			t.Errorf("package %q: licenseDeclared = %q, want NOASSERTION", p.Name, p.LicenseDeclared)
		}
	}
}

// TestCycloneDXBomRefPresent asserts every component (and the metadata
// component) carries a non-empty bom-ref.
func TestCycloneDXBomRefPresent(t *testing.T) {
	data, err := GenerateCycloneDX(multiEcosystemResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, c := range bom.Components {
		if c.BOMRef == "" {
			t.Errorf("component %d (%q): empty bom-ref", i, c.Name)
		}
	}
	if bom.Metadata.Component == nil {
		t.Fatalf("metadata.component is nil")
	}
	if bom.Metadata.Component.BOMRef == "" {
		t.Errorf("metadata.component has empty bom-ref")
	}
}
