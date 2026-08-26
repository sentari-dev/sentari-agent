package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func supplierTestResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, Supplier: "Kenneth Reitz"},
			{Name: "nosupplier", Version: "1.0.0", EnvType: scanner.EnvPip},
		},
	}
}

// TestCycloneDXEmitsSupplier proves the agent-local CycloneDX generator emits
// supplier.name for records that carry a supplier and omits it otherwise —
// parity with the server SBOM (SBOM-completeness v2).
func TestCycloneDXEmitsSupplier(t *testing.T) {
	doc, err := GenerateCycloneDX(supplierTestResult())
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct {
			Name     string             `json:"name"`
			Supplier *CycloneDXSupplier `json:"supplier"`
		} `json:"components"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil {
		t.Fatal(err)
	}
	byName := map[string]*CycloneDXSupplier{}
	for _, c := range bom.Components {
		byName[c.Name] = c.Supplier
	}
	if byName["requests"] == nil || byName["requests"].Name != "Kenneth Reitz" {
		t.Errorf("requests supplier = %+v, want {Name:Kenneth Reitz}", byName["requests"])
	}
	if byName["nosupplier"] != nil {
		t.Errorf("nosupplier supplier = %+v, want omitted", byName["nosupplier"])
	}
}

// TestSPDXEmitsSupplier proves the agent-local SPDX generator emits the
// "Organization: <name>" supplier grammar and omits it when absent.
func TestSPDXEmitsSupplier(t *testing.T) {
	doc, err := GenerateSPDX(supplierTestResult())
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Packages []struct {
			Name     string `json:"name"`
			Supplier string `json:"supplier"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, p := range d.Packages {
		byName[p.Name] = p.Supplier
	}
	if byName["requests"] != "Organization: Kenneth Reitz" {
		t.Errorf("requests supplier = %q, want %q", byName["requests"], "Organization: Kenneth Reitz")
	}
	if byName["nosupplier"] != "" {
		t.Errorf("nosupplier supplier = %q, want empty/omitted", byName["nosupplier"])
	}
}
