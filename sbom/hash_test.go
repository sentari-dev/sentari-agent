package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

var testSHA = strings.Repeat("ab", 32)

func hashTestResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "guava", Version: "31.0", EnvType: "maven", Sha256: testSHA},
			{Name: "nohash", Version: "1.0.0", EnvType: scanner.EnvPip},
		},
	}
}

// TestCycloneDXEmitsSha256 proves the agent-local CycloneDX generator emits a
// SHA-256 hash entry for records that carry one and omits it otherwise.
func TestCycloneDXEmitsSha256(t *testing.T) {
	doc, err := GenerateCycloneDX(hashTestResult())
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct {
			Name   string          `json:"name"`
			Hashes []CycloneDXHash `json:"hashes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil {
		t.Fatal(err)
	}
	byName := map[string][]CycloneDXHash{}
	for _, c := range bom.Components {
		byName[c.Name] = c.Hashes
	}
	if len(byName["guava"]) != 1 || byName["guava"][0].Alg != "SHA-256" || byName["guava"][0].Content != testSHA {
		t.Errorf("guava hashes = %+v, want one SHA-256 entry", byName["guava"])
	}
	if byName["nohash"] != nil {
		t.Errorf("nohash hashes = %+v, want omitted", byName["nohash"])
	}
}

// TestSPDXEmitsChecksum proves the agent-local SPDX generator emits a SHA256
// checksum for records that carry one and omits it otherwise.
func TestSPDXEmitsChecksum(t *testing.T) {
	doc, err := GenerateSPDX(hashTestResult())
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Packages []struct {
			Name      string         `json:"name"`
			Checksums []SPDXChecksum `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatal(err)
	}
	byName := map[string][]SPDXChecksum{}
	for _, p := range d.Packages {
		byName[p.Name] = p.Checksums
	}
	if len(byName["guava"]) != 1 || byName["guava"][0].Algorithm != "SHA256" || byName["guava"][0].ChecksumValue != testSHA {
		t.Errorf("guava checksums = %+v, want one SHA256 entry", byName["guava"])
	}
	if byName["nohash"] != nil {
		t.Errorf("nohash checksums = %+v, want omitted", byName["nohash"])
	}
}
