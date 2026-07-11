package sbom

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// updateGolden regenerates the checked-in golden SBOM documents instead of
// asserting against them. Run with:
//
//	go test ./sbom/ -run TestGolden -update
//
// then review the diff and commit the regenerated fixtures.
var updateGolden = flag.Bool("update", false, "regenerate SBOM golden fixtures")

// The two SBOM generators embed exactly one nondeterministic value each — a
// crypto/rand UUID (CycloneDX serialNumber "urn:uuid:<uuid>" and SPDX
// documentNamespace "https://sentari.io/sbom/<uuid>"). Every other field is a
// pure function of the input ScanResult (the timestamp comes from ScannedAt,
// which the fixture pins). Normalizing just those two UUIDs to a fixed
// placeholder makes the whole-document output deterministic and lets a golden
// byte-compare catch any structural/field regression in the document shape.
const goldenUUIDPlaceholder = "00000000-0000-0000-0000-000000000000"

var (
	cdxSerialRe = regexp.MustCompile(`urn:uuid:[0-9a-fA-F-]{36}`)
	spdxNSRe    = regexp.MustCompile(`https://sentari\.io/sbom/[0-9a-fA-F-]{36}`)
)

// normalizeSBOM replaces the nondeterministic UUID-bearing fields with a fixed
// placeholder so repeated generations of the same ScanResult are byte-stable.
func normalizeSBOM(data []byte) []byte {
	data = cdxSerialRe.ReplaceAll(data, []byte("urn:uuid:"+goldenUUIDPlaceholder))
	data = spdxNSRe.ReplaceAll(data, []byte("https://sentari.io/sbom/"+goldenUUIDPlaceholder))
	return data
}

// goldenScanResult is a fully-populated, fixed ScanResult that exercises the
// real content paths of both SBOM generators:
//   - multiple ecosystems (pypi, scoped npm, maven group:artifact, nuget,
//     deb + rpm with source packages) so every purlFor branch is covered;
//   - an ai_agent record with no standard purl (purl omitted, comp-<i> ref);
//   - a duplicate purl (requests twice, different InstallPath) to exercise the
//     CycloneDX bom-ref "#n" de-duplication;
//   - InstallPath on several records (CycloneDX sentari:install_path property);
//   - populated DepEdges + LicenseEvidence so the golden freezes the current
//     "input carried, not yet rendered" behavior — if a generator later starts
//     consuming those, the golden diff flags it for review.
func goldenScanResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		DeviceID:     "dev-golden-1",
		Hostname:     "golden-host",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		AgentVersion: "1.2.3-test",
		Runtime:      "bare_metal",
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-a", Environment: "venv-a", LicenseSPDX: "Apache-2.0"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-b", Environment: "venv-b", LicenseSPDX: "Apache-2.0"},
			{Name: "@scope/pkg", Version: "1.0.0", EnvType: "npm", InstallPath: "/srv/app/node_modules", Environment: "node"},
			{Name: "org.apache.commons:commons-lang3", Version: "3.14.0", EnvType: "jvm", Environment: "maven"},
			{Name: "Newtonsoft.Json", Version: "13.0.3", EnvType: "nuget", Environment: "dotnet"},
			{Name: "libssl3", Version: "3.0.11-1", EnvType: scanner.EnvSystemDeb, SourcePackage: "openssl", Environment: "system"},
			{Name: "openssl-libs", Version: "3.0.7-24", EnvType: scanner.EnvSystemRpm, SourcePackage: "openssl", Environment: "system"},
			{Name: "acme-copilot", Version: "0.9.0", EnvType: "ai_agent", Environment: "ai"},
		},
		Errors: []scanner.ScanError{},
		DepEdges: []deptree.DepEdge{
			{
				ParentName: "requests", ParentVersion: "2.31.0",
				ChildName: "urllib3", ChildVersion: "2.2.1",
				Ecosystem: "pypi", Type: "runtime", Scope: "prod", Depth: 1,
				IntroducedByPath: []string{"requests", "urllib3"}, Resolved: true,
			},
			{
				ParentName: "requests", ParentVersion: "2.31.0",
				ChildName: "certifi", ChildVersion: "2024.2.2",
				Ecosystem: "pypi", Type: "runtime", Scope: "prod", Depth: 1,
				IntroducedByPath: []string{"requests", "certifi"}, Resolved: true,
			},
		},
		LicenseEvidence: []deptree.LicenseEvidence{
			{
				PackageName: "requests", PackageVersion: "2.31.0",
				Ecosystem: "pypi", SpdxID: "Apache-2.0",
				Source: "metadata", Confidence: 0.95,
			},
		},
	}
}

// TestGoldenCycloneDXDocument freezes the full CycloneDX 1.6 document shape for
// a fully-populated ScanResult. Unlike the field-level specversion/purl/bomref
// tests, this catches any structural regression (renamed keys, dropped
// sections, reordered/added fields) in the whole document.
func TestGoldenCycloneDXDocument(t *testing.T) {
	data, err := GenerateCycloneDX(goldenScanResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	assertGolden(t, "cyclonedx_full.json", normalizeSBOM(data))
}

// TestGoldenSPDXDocument freezes the full SPDX 2.3 document shape for the same
// fully-populated ScanResult.
func TestGoldenSPDXDocument(t *testing.T) {
	data, err := GenerateSPDX(goldenScanResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	assertGolden(t, "spdx_full.json", normalizeSBOM(data))
}

// TestGoldenDeterministic asserts both generators produce byte-identical
// (post-normalization) output across repeated invocations — i.e. the only
// nondeterminism is the two UUID fields we normalize, nothing else.
func TestGoldenDeterministic(t *testing.T) {
	res := goldenScanResult()
	for _, tc := range []struct {
		name string
		gen  func(*scanner.ScanResult) ([]byte, error)
	}{
		{"cyclonedx", GenerateCycloneDX},
		{"spdx", GenerateSPDX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := tc.gen(res)
			if err != nil {
				t.Fatalf("gen #1: %v", err)
			}
			second, err := tc.gen(res)
			if err != nil {
				t.Fatalf("gen #2: %v", err)
			}
			if string(normalizeSBOM(first)) != string(normalizeSBOM(second)) {
				t.Fatalf("normalized output not deterministic across runs")
			}
		})
	}
}

// assertGolden compares got against testdata/golden/<name>, or rewrites the
// fixture when -update is passed.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		t.Logf("updated golden fixture %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run `go test ./sbom/ -run TestGolden -update` to create): %v", name, err)
	}
	if string(got) != string(want) {
		t.Fatalf("SBOM document does not match golden %s.\n"+
			"If this change is intentional, regenerate with:\n"+
			"  go test ./sbom/ -run TestGolden -update\n\n--- got ---\n%s\n--- want ---\n%s",
			path, got, want)
	}
}
