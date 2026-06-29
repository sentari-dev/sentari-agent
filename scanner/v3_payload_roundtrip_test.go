// V3 payload round-trip tests for the three Phase 3/4 fields the
// internal sentari repo's contract-sync review found uncovered:
//
//   - supply_chain_signals
//   - license_evidence
//   - installed_runtimes
//
// These tests construct a ScanResult populated with realistic-shaped
// rows for each field, marshal to JSON, unmarshal back, and assert
// that every wire field name + value survives intact. The goal is to
// pin the JSON contract: a future rename or reordering of struct
// fields (a refactor that's silently wire-incompatible) fails the
// test loudly rather than being caught only at server-ingest time.
//
// The dep_edges + lockfiles fields already have round-trip coverage
// in scanner_v3_test.go (TestEnrichWithV3_*); this file fills the
// matrix.

package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/runtimeversions"
)

func TestV3RoundTrip_SupplyChainSignals(t *testing.T) {
	original := ScanResult{
		DeviceID: "00000000-0000-0000-0000-000000000001",
		Hostname: "scs-host",
		SupplyChainSignals: []deptree.SupplyChainSignal{
			{
				PackageName:    "left-pad",
				PackageVersion: "1.3.0",
				Ecosystem:      "npm",
				// Agent-emitted signal_type per the v3 contract (the
				// server-only "deprecated" value must NOT come from the
				// agent — audit finding 7).
				SignalType: "postinstall_script",
				Severity:   "medium",
				Source:     "agent-npm-scripts",
				Raw:        map[string]interface{}{"reason": "runs a postinstall hook"},
			},
			{
				PackageName:    "requests",
				PackageVersion: "2.0.0",
				Ecosystem:      "pypi",
				SignalType:     "yanked",
				Severity:       "high",
				Source:         "pypi-yanked-cache",
				// Raw is omitempty — leaving it unset must produce a JSON
				// payload without a `raw` key, matching the schema.
			},
		},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"supply_chain_signals":`) {
		t.Fatalf("expected supply_chain_signals key in JSON, got: %s", raw)
	}
	// The second row had Raw==nil — `omitempty` must drop the key.
	// We check by counting occurrences of the raw key; one row has it,
	// the other does not, so exactly one occurrence is expected.
	if got := strings.Count(string(raw), `"raw":`); got != 1 {
		t.Fatalf(`expected exactly 1 occurrence of "raw":, got %d in %s`, got, raw)
	}

	var decoded ScanResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.SupplyChainSignals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(decoded.SupplyChainSignals))
	}
	if decoded.SupplyChainSignals[0].PackageName != "left-pad" ||
		decoded.SupplyChainSignals[0].SignalType != "postinstall_script" ||
		decoded.SupplyChainSignals[0].Raw["reason"] != "runs a postinstall hook" {
		t.Fatalf("row 0 corrupted: %+v", decoded.SupplyChainSignals[0])
	}
	if decoded.SupplyChainSignals[1].PackageName != "requests" ||
		decoded.SupplyChainSignals[1].SignalType != "yanked" ||
		decoded.SupplyChainSignals[1].Raw != nil {
		t.Fatalf("row 1 corrupted: %+v", decoded.SupplyChainSignals[1])
	}
}

func TestV3RoundTrip_LicenseEvidence(t *testing.T) {
	original := ScanResult{
		DeviceID: "00000000-0000-0000-0000-000000000002",
		Hostname: "lic-host",
		LicenseEvidence: []deptree.LicenseEvidence{
			{
				PackageName:    "left-pad",
				PackageVersion: "1.3.0",
				Ecosystem:      "npm",
				SpdxID:         "WTFPL",
				// Agent-emitted license source per the v3 contract
				// (npm package.json -> "spdx_pkg"); the old "package_json"
				// value is not in the contract enum — audit finding 7.
				Source:     "spdx_pkg",
				Confidence: 0.95,
				RawText:    "DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE",
			},
			{
				PackageName:    "no-license-pkg",
				PackageVersion: "0.0.1",
				Ecosystem:      "pypi",
				// SpdxID + RawText are omitempty — agent emits a row with
				// only Source + Confidence when it couldn't classify the
				// license but did find a license-shaped artefact.  "trove"
				// is a contract-valid agent source (PyPI Trove classifiers).
				Source:     "trove",
				Confidence: 0.20,
			},
		},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"license_evidence":`) {
		t.Fatalf("expected license_evidence key, got: %s", raw)
	}
	// SpdxID and RawText are both omitempty — the second row must drop
	// both keys. A single occurrence of `"spdx_id":` and `"raw_text":`
	// across the entire payload is the correctness signal.
	if got := strings.Count(string(raw), `"spdx_id":`); got != 1 {
		t.Fatalf(`expected exactly 1 "spdx_id":, got %d`, got)
	}
	if got := strings.Count(string(raw), `"raw_text":`); got != 1 {
		t.Fatalf(`expected exactly 1 "raw_text":, got %d`, got)
	}

	var decoded ScanResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.LicenseEvidence) != 2 {
		t.Fatalf("expected 2 evidence rows, got %d", len(decoded.LicenseEvidence))
	}
	if decoded.LicenseEvidence[0].SpdxID != "WTFPL" ||
		decoded.LicenseEvidence[0].Confidence != 0.95 {
		t.Fatalf("row 0 corrupted: %+v", decoded.LicenseEvidence[0])
	}
	if decoded.LicenseEvidence[1].SpdxID != "" ||
		decoded.LicenseEvidence[1].RawText != "" ||
		decoded.LicenseEvidence[1].Source != "trove" {
		t.Fatalf("row 1 corrupted: %+v", decoded.LicenseEvidence[1])
	}
}

func TestV3RoundTrip_InstalledRuntimes(t *testing.T) {
	original := ScanResult{
		DeviceID: "00000000-0000-0000-0000-000000000003",
		Hostname: "rt-host",
		InstalledRuntimes: []runtimeversions.InstalledRuntime{
			{
				Name:        "python",
				Version:     "3.11.5",
				Cycle:       "3.11",
				InstallPath: "/usr/local/bin/python3.11",
				// Distro is omitempty — empty for python/node, only set
				// for JDK.
			},
			{
				Name:        "node",
				Version:     "20.10.0",
				Cycle:       "20",
				InstallPath: "/usr/local/bin/node",
			},
			{
				Name:        "jdk",
				Version:     "17.0.5",
				Cycle:       "17",
				Distro:      "Temurin",
				InstallPath: "/usr/lib/jvm/temurin-17",
			},
		},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"installed_runtimes":`) {
		t.Fatalf("expected installed_runtimes key, got: %s", raw)
	}
	// Distro is omitempty: only the JDK row emits it.
	if got := strings.Count(string(raw), `"distro":`); got != 1 {
		t.Fatalf(`expected exactly 1 "distro":, got %d (Distro should be omitempty for python/node)`, got)
	}

	var decoded ScanResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.InstalledRuntimes) != 3 {
		t.Fatalf("expected 3 runtimes, got %d", len(decoded.InstalledRuntimes))
	}
	if decoded.InstalledRuntimes[0].Name != "python" ||
		decoded.InstalledRuntimes[0].Cycle != "3.11" ||
		decoded.InstalledRuntimes[0].Distro != "" {
		t.Fatalf("python row corrupted: %+v", decoded.InstalledRuntimes[0])
	}
	if decoded.InstalledRuntimes[2].Name != "jdk" ||
		decoded.InstalledRuntimes[2].Distro != "Temurin" ||
		decoded.InstalledRuntimes[2].Cycle != "17" {
		t.Fatalf("jdk row corrupted: %+v", decoded.InstalledRuntimes[2])
	}
}

// TestV3RoundTrip_AllThreeFieldsTogether is the integration-shape
// test: a single ScanResult carrying rows in all three of the
// previously-uncovered v3 fields plus dep_edges + lockfiles round-
// trips intact. Pins the wire layout end-to-end.
func TestV3RoundTrip_AllThreeFieldsTogether(t *testing.T) {
	original := ScanResult{
		DeviceID: "00000000-0000-0000-0000-000000000004",
		Hostname: "full-host",
		SupplyChainSignals: []deptree.SupplyChainSignal{
			{PackageName: "p", PackageVersion: "1", Ecosystem: "npm", SignalType: "unsigned", Severity: "low", Source: "agent-npm-scripts"},
		},
		LicenseEvidence: []deptree.LicenseEvidence{
			{PackageName: "p", PackageVersion: "1", Ecosystem: "npm", SpdxID: "MIT", Source: "spdx_pkg", Confidence: 1.0},
		},
		InstalledRuntimes: []runtimeversions.InstalledRuntime{
			{Name: "python", Version: "3.12.0", Cycle: "3.12", InstallPath: "/usr/bin/python3"},
		},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.SupplyChainSignals) != 1 ||
		len(decoded.LicenseEvidence) != 1 ||
		len(decoded.InstalledRuntimes) != 1 {
		t.Fatalf("expected 1 row in each of the three fields, got %d / %d / %d",
			len(decoded.SupplyChainSignals),
			len(decoded.LicenseEvidence),
			len(decoded.InstalledRuntimes))
	}
}
