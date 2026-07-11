package sbom

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func specTestResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		DeviceID:     "dev-1",
		Hostname:     "host-1",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv"},
		},
	}
}

// TestCycloneDXSpecVersionPinned decodes GenerateCycloneDX output and asserts
// the document declares bomFormat "CycloneDX" and specVersion "1.6".  Until now
// the "1.6" literal was emitted but never verified, so a stray edit could ship
// a document claiming an unsupported spec version undetected.
func TestCycloneDXSpecVersionPinned(t *testing.T) {
	data, err := GenerateCycloneDX(specTestResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Fatalf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Fatalf("specVersion = %q, want 1.6", doc.SpecVersion)
	}
}

// TestSPDXVersionPinned decodes GenerateSPDX output and asserts the document
// declares spdxVersion "SPDX-2.3" — the SPDX counterpart to the CycloneDX pin
// (the --sbom-format=spdx path emits this document).
func TestSPDXVersionPinned(t *testing.T) {
	data, err := GenerateSPDX(specTestResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal SPDX: %v", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
}
