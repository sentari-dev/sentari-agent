package sbom

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// depGraphResult builds a scan with requests → {urllib3, certifi}, all three
// installed, plus an unresolved edge (child not installed).
func depGraphResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip},
			{Name: "urllib3", Version: "2.2.1", EnvType: scanner.EnvPip},
			{Name: "certifi", Version: "2024.2.2", EnvType: scanner.EnvPip},
		},
		DepEdges: []deptree.DepEdge{
			{ParentName: "requests", ParentVersion: "2.31.0", ChildName: "urllib3", ChildVersion: "2.2.1", Ecosystem: "pypi", Resolved: true},
			{ParentName: "requests", ParentVersion: "2.31.0", ChildName: "certifi", ChildVersion: "2024.2.2", Ecosystem: "pypi", Resolved: true},
		},
	}
}

// cdxDependencies unmarshals the top-level dependencies array as raw maps.
func cdxDependencies(t *testing.T, res *scanner.ScanResult) ([]map[string]any, map[string]bool) {
	t.Helper()
	data, err := GenerateCycloneDX(res)
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	refs := map[string]bool{}
	if comps, ok := doc["components"].([]any); ok {
		for _, c := range comps {
			if m, ok := c.(map[string]any); ok {
				if r, ok := m["bom-ref"].(string); ok {
					refs[r] = true
				}
			}
		}
	}
	var deps []map[string]any
	if raw, ok := doc["dependencies"].([]any); ok {
		for _, d := range raw {
			deps = append(deps, d.(map[string]any))
		}
	}
	return deps, refs
}

func TestCycloneDXDependenciesFromDepEdges(t *testing.T) {
	deps, refs := cdxDependencies(t, depGraphResult())
	if len(deps) != 1 {
		t.Fatalf("got %d dependency entries, want 1 (only requests has edges)", len(deps))
	}
	entry := deps[0]
	if entry["ref"] != "pkg:pypi/requests@2.31.0" {
		t.Errorf("entry ref = %v, want pkg:pypi/requests@2.31.0", entry["ref"])
	}
	dependsOn := entry["dependsOn"].([]any)
	if len(dependsOn) != 2 {
		t.Fatalf("got %d dependsOn, want 2", len(dependsOn))
	}
	// sorted: certifi < urllib3
	if dependsOn[0] != "pkg:pypi/certifi@2024.2.2" || dependsOn[1] != "pkg:pypi/urllib3@2.2.1" {
		t.Errorf("dependsOn = %v, want sorted [certifi, urllib3]", dependsOn)
	}
	// every ref/dependsOn member must resolve to a component bom-ref.
	if !refs[entry["ref"].(string)] {
		t.Errorf("entry ref %v is not a component bom-ref", entry["ref"])
	}
	for _, d := range dependsOn {
		if !refs[d.(string)] {
			t.Errorf("dependsOn %v is not a component bom-ref", d)
		}
	}
}

func TestCycloneDXDependenciesSkipUnresolvedEndpoints(t *testing.T) {
	res := depGraphResult()
	// child not installed:
	res.DepEdges = append(res.DepEdges, deptree.DepEdge{
		ParentName: "requests", ParentVersion: "2.31.0", ChildName: "ghost", ChildVersion: "9.9.9", Ecosystem: "pypi",
	})
	// version mismatch (urllib3 installed at 2.2.1, edge references 1.0.0):
	res.DepEdges = append(res.DepEdges, deptree.DepEdge{
		ParentName: "requests", ParentVersion: "2.31.0", ChildName: "urllib3", ChildVersion: "1.0.0", Ecosystem: "pypi",
	})
	// parent not installed → whole entry absent:
	res.DepEdges = append(res.DepEdges, deptree.DepEdge{
		ParentName: "phantom", ParentVersion: "1.0.0", ChildName: "certifi", ChildVersion: "2024.2.2", Ecosystem: "pypi",
	})
	deps, _ := cdxDependencies(t, res)
	if len(deps) != 1 {
		t.Fatalf("got %d entries, want 1 (phantom parent dropped)", len(deps))
	}
	dependsOn := deps[0]["dependsOn"].([]any)
	if len(dependsOn) != 2 {
		t.Fatalf("got %d dependsOn, want 2 (ghost + mismatched urllib3 dropped)", len(dependsOn))
	}
}

func TestCycloneDXDependenciesDeduped(t *testing.T) {
	res := depGraphResult()
	res.DepEdges = append(res.DepEdges, res.DepEdges[0]) // duplicate requests→urllib3
	deps, _ := cdxDependencies(t, res)
	if len(deps) != 1 {
		t.Fatalf("got %d entries, want 1", len(deps))
	}
	if len(deps[0]["dependsOn"].([]any)) != 2 {
		t.Errorf("dependsOn = %v, want 2 (dedup)", deps[0]["dependsOn"])
	}
}

func TestCycloneDXDependenciesDuplicateCoordinateTargetsBaseRef(t *testing.T) {
	res := depGraphResult()
	// install requests twice; the edge must still target the unsuffixed base ref.
	res.Packages[0].InstallPath = "/opt/venv-a"
	res.Packages = append(res.Packages, scanner.PackageRecord{
		Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-b",
	})
	deps, _ := cdxDependencies(t, res)
	if len(deps) != 1 {
		t.Fatalf("got %d entries, want 1", len(deps))
	}
	if deps[0]["ref"] != "pkg:pypi/requests@2.31.0" {
		t.Errorf("ref = %v, want unsuffixed pkg:pypi/requests@2.31.0", deps[0]["ref"])
	}
}

func TestCycloneDXDependenciesOmittedWhenNoEdges(t *testing.T) {
	res := depGraphResult()
	res.DepEdges = nil
	data, err := GenerateCycloneDX(res)
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := doc["dependencies"]; present {
		t.Errorf("dependencies key present with nil DepEdges, want omitted")
	}
}

// spdxDoc generates and unmarshals the SPDX document to raw maps.
func spdxDoc(t *testing.T, res *scanner.ScanResult) map[string]any {
	t.Helper()
	data, err := GenerateSPDX(res)
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

func TestSPDXLicenseFieldsPopulated(t *testing.T) {
	res := &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, LicenseSPDX: "Apache-2.0", LicenseRaw: "Apache License 2.0"},
			{Name: "mystery", Version: "1.0.0", EnvType: scanner.EnvPip},
		},
	}
	doc := spdxDoc(t, res)
	byName := map[string]map[string]any{}
	for _, p := range doc["packages"].([]any) {
		m := p.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["requests"]["licenseConcluded"] != "Apache-2.0" {
		t.Errorf("requests licenseConcluded = %v, want Apache-2.0", byName["requests"]["licenseConcluded"])
	}
	if byName["requests"]["licenseDeclared"] != "Apache License 2.0" {
		t.Errorf("requests licenseDeclared = %v, want Apache License 2.0", byName["requests"]["licenseDeclared"])
	}
	if byName["mystery"]["licenseConcluded"] != "NOASSERTION" || byName["mystery"]["licenseDeclared"] != "NOASSERTION" {
		t.Errorf("mystery license fields = (%v,%v), want both NOASSERTION",
			byName["mystery"]["licenseConcluded"], byName["mystery"]["licenseDeclared"])
	}
}

func TestSPDXCopyrightTextFromEvidence(t *testing.T) {
	res := &scanner.ScanResult{
		Hostname:     "host-1",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "test",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip},
			{Name: "mystery", Version: "1.0.0", EnvType: scanner.EnvPip},
		},
		LicenseEvidence: []deptree.LicenseEvidence{
			{PackageName: "requests", PackageVersion: "2.31.0", Ecosystem: "pypi", Confidence: 0.9, RawText: "Copyright 2024 Example"},
		},
	}
	doc := spdxDoc(t, res)
	for _, p := range doc["packages"].([]any) {
		m := p.(map[string]any)
		if _, present := m["copyrightText"]; !present {
			t.Errorf("package %v missing copyrightText key (must always be present)", m["name"])
		}
		switch m["name"] {
		case "requests":
			if m["copyrightText"] != "Copyright 2024 Example" {
				t.Errorf("requests copyrightText = %v, want Copyright 2024 Example", m["copyrightText"])
			}
		case "mystery":
			if m["copyrightText"] != "NOASSERTION" {
				t.Errorf("mystery copyrightText = %v, want NOASSERTION", m["copyrightText"])
			}
		}
	}
}

func TestSPDXPackagesSortedAndIdsSequential(t *testing.T) {
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
	doc := spdxDoc(t, res)
	pkgs := doc["packages"].([]any)
	wantNames := []string{"org.apache.commons:commons-lang3", "Newtonsoft.Json", "requests"}
	for i, wantName := range wantNames {
		m := pkgs[i].(map[string]any)
		if m["name"] != wantName {
			t.Errorf("packages[%d].name = %v, want %v", i, m["name"], wantName)
		}
		wantID := fmt.Sprintf("SPDXRef-Package-%d", i)
		if m["SPDXID"] != wantID {
			t.Errorf("packages[%d].SPDXID = %v, want %v", i, m["SPDXID"], wantID)
		}
	}
}

func TestSPDXDependsOnRelationships(t *testing.T) {
	doc := spdxDoc(t, depGraphResult())
	// map ids present in packages
	ids := map[string]bool{}
	for _, p := range doc["packages"].([]any) {
		ids[p.(map[string]any)["SPDXID"].(string)] = true
	}
	rels := doc["relationships"].([]any)
	// All DESCRIBES first (one per package), then DEPENDS_ON.
	pkgCount := len(doc["packages"].([]any))
	var describes, dependsOn int
	seenDependsOn := false
	for _, r := range rels {
		m := r.(map[string]any)
		rt := m["relationshipType"].(string)
		switch rt {
		case "DESCRIBES":
			if seenDependsOn {
				t.Errorf("DESCRIBES appears after DEPENDS_ON — ordering violated")
			}
			describes++
		case "DEPENDS_ON":
			seenDependsOn = true
			dependsOn++
			if !ids[m["relatedSpdxElement"].(string)] || !ids[m["spdxElementId"].(string)] {
				t.Errorf("DEPENDS_ON references an id not in packages: %v", m)
			}
		default:
			t.Errorf("unexpected relationshipType %q", rt)
		}
	}
	if describes != pkgCount {
		t.Errorf("got %d DESCRIBES, want %d (one per package)", describes, pkgCount)
	}
	if dependsOn != 2 {
		t.Errorf("got %d DEPENDS_ON, want 2 (requests→urllib3, requests→certifi)", dependsOn)
	}
}

func TestSPDXDependsOnSkipsUnresolvedEndpoints(t *testing.T) {
	res := depGraphResult()
	res.DepEdges = append(res.DepEdges, deptree.DepEdge{
		ParentName: "requests", ParentVersion: "2.31.0", ChildName: "ghost", ChildVersion: "9.9.9", Ecosystem: "pypi",
	})
	doc := spdxDoc(t, res)
	pkgCount := len(doc["packages"].([]any))
	var describes, dependsOn int
	for _, r := range doc["relationships"].([]any) {
		switch r.(map[string]any)["relationshipType"] {
		case "DESCRIBES":
			describes++
		case "DEPENDS_ON":
			dependsOn++
		}
	}
	if describes != pkgCount {
		t.Errorf("DESCRIBES count %d changed by unresolved edge, want %d", describes, pkgCount)
	}
	if dependsOn != 2 {
		t.Errorf("got %d DEPENDS_ON, want 2 (ghost edge dropped)", dependsOn)
	}
}

func TestSPDXDependsOnDeduped(t *testing.T) {
	res := depGraphResult()
	res.DepEdges = append(res.DepEdges, res.DepEdges[0])
	doc := spdxDoc(t, res)
	var dependsOn int
	for _, r := range doc["relationships"].([]any) {
		if r.(map[string]any)["relationshipType"] == "DEPENDS_ON" {
			dependsOn++
		}
	}
	if dependsOn != 2 {
		t.Errorf("got %d DEPENDS_ON, want 2 (duplicate edge deduped)", dependsOn)
	}
}
