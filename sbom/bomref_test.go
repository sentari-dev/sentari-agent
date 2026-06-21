package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// duplicateComponentResult builds a ScanResult where the SAME package
// (identical name + version + ecosystem) appears in two different
// environments (distinct install paths). CycloneDX requires every
// bom-ref to be unique within the BOM, so these two components must NOT
// share a bom-ref even though they share a purl.
func duplicateComponentResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		DeviceID:     "dev-1",
		Hostname:     "host-1",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-a"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-b"},
		},
	}
}

// TestCycloneDXBomRefUniqueAcrossEnvironments asserts that when the same
// package appears in multiple environments, each emitted component still
// gets a distinct bom-ref (CycloneDX uniqueness requirement).
func TestCycloneDXBomRefUniqueAcrossEnvironments(t *testing.T) {
	data, err := GenerateCycloneDX(duplicateComponentResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(bom.Components) != 2 {
		t.Fatalf("got %d components, want 2", len(bom.Components))
	}
	seen := map[string]bool{}
	for i, c := range bom.Components {
		if c.BOMRef == "" {
			t.Errorf("component %d (%q): empty bom-ref", i, c.Name)
		}
		if seen[c.BOMRef] {
			t.Errorf("duplicate bom-ref %q (component %d)", c.BOMRef, i)
		}
		seen[c.BOMRef] = true
	}
	// The valid purl must be preserved on both (don't regress purl typing).
	for _, c := range bom.Components {
		if c.Purl != "pkg:pypi/requests@2.31.0" {
			t.Errorf("component %q: purl = %q, want pkg:pypi/requests@2.31.0", c.Name, c.Purl)
		}
	}
}

// TestCycloneDXBomRefUniqueManyDuplicates exercises the general uniqueness
// invariant across a larger set with several collisions, including
// components that have no purl (comp-* fallback) which must also stay
// unique.
func TestCycloneDXBomRefUniqueManyDuplicates(t *testing.T) {
	res := &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/a"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/b"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/c"},
			// No purl (ai_agent) — comp-* fallback path.
			{Name: "weird", Version: "1.0", EnvType: "ai_agent"},
			{Name: "weird2", Version: "1.0", EnvType: "ai_agent"},
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
	seen := map[string]bool{}
	for i, c := range bom.Components {
		if seen[c.BOMRef] {
			t.Errorf("duplicate bom-ref %q (component %d, %q)", c.BOMRef, i, c.Name)
		}
		seen[c.BOMRef] = true
	}
}
