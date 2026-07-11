//go:build enterprise

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func sbomTestResult() *scanner.ScanResult {
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

// TestNormalizeSBOMFormat covers the --sbom-format validation the CLI performs
// at startup: the two accepted formats (case-insensitively), the empty default,
// and the invalid-value error path.
func TestNormalizeSBOMFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "cyclonedx", false},
		{"cyclonedx", "cyclonedx", false},
		{"CycloneDX", "cyclonedx", false},
		{"spdx", "spdx", false},
		{" SPDX ", "spdx", false},
		{"json", "", true},
		{"cdx", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeSBOMFormat(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("normalizeSBOMFormat(%q): want error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeSBOMFormat(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeSBOMFormat(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestWriteSBOMFileSPDX proves the --sbom-out x.json --sbom-format=spdx path
// dispatches to the SPDX writer and produces an SPDX 2.3 document.
func TestWriteSBOMFileSPDX(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sbom.json")
	if err := writeSBOMFile(sbomTestResult(), out, "spdx"); err != nil {
		t.Fatalf("writeSBOMFile spdx: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
}

// TestWriteSBOMFileCycloneDXDefault proves the default format dispatches to the
// CycloneDX writer (bomFormat marker present, no SPDX marker).
func TestWriteSBOMFileCycloneDXDefault(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sbom.json")
	if err := writeSBOMFile(sbomTestResult(), out, "cyclonedx"); err != nil {
		t.Fatalf("writeSBOMFile cyclonedx: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Fatalf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SPDXVersion != "" {
		t.Fatalf("unexpected spdxVersion %q in CycloneDX output", doc.SPDXVersion)
	}
}
