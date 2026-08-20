package sbom

import (
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestEnvTypeEcosystemMapping pins the EnvType → package-URL ecosystem token
// mapping used to build coordinate keys for the dependency graph.
func TestEnvTypeEcosystemMapping(t *testing.T) {
	cases := map[string]string{
		scanner.EnvPip:       "pypi",
		scanner.EnvVenv:      "pypi",
		scanner.EnvConda:     "pypi",
		scanner.EnvPoetry:    "pypi",
		scanner.EnvPipenv:    "pypi",
		"npm":                "npm",
		"jvm":                "maven",
		"nuget":              "nuget",
		scanner.EnvSystemDeb: "",
		scanner.EnvSystemRpm: "",
		"go_binary":          "",
		"ai_agent":           "",
		"":                   "",
	}
	for envType, want := range cases {
		if got := envTypeEcosystem(envType); got != want {
			t.Errorf("envTypeEcosystem(%q) = %q, want %q", envType, got, want)
		}
	}
}

// TestFoldNamePEP503 checks name folding: lowercase for every ecosystem, plus
// PEP-503 "_"/"." → "-" normalization for PyPI only.
func TestFoldNamePEP503(t *testing.T) {
	cases := []struct {
		ecosystem, name, want string
	}{
		{"pypi", "Typing_Extensions", "typing-extensions"},
		{"pypi", "zope.interface", "zope-interface"},
		{"maven", "Org.Apache:Foo", "org.apache:foo"},
		{"npm", "@Scope/Pkg", "@scope/pkg"},
	}
	for _, tc := range cases {
		if got := foldName(tc.ecosystem, tc.name); got != tc.want {
			t.Errorf("foldName(%q, %q) = %q, want %q", tc.ecosystem, tc.name, got, tc.want)
		}
	}
}

// TestPlanComponentsSortedByRef proves the shared plan is emitted in stable
// ref order (not input order) and that a record without a purl gets the
// coordinate-form fallback ref, never an index-based id.
func TestPlanComponentsSortedByRef(t *testing.T) {
	res := &scanner.ScanResult{
		ScannedAt: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip},
			{Name: "Newtonsoft.Json", Version: "13.0.3", EnvType: "nuget"},
			{Name: "org.apache.commons:commons-lang3", Version: "3.14.0", EnvType: "jvm"},
			{Name: "acme-copilot", Version: "0.9.0", EnvType: "ai_agent"},
		},
	}
	plans, _ := planComponents(res)
	if len(plans) != 4 {
		t.Fatalf("got %d plans, want 4", len(plans))
	}
	wantOrder := []string{
		"ai_agent:acme-copilot@0.9.0",
		"pkg:maven/org.apache.commons/commons-lang3@3.14.0",
		"pkg:nuget/Newtonsoft.Json@13.0.3",
		"pkg:pypi/requests@2.31.0",
	}
	for i, want := range wantOrder {
		if plans[i].ref != want {
			t.Errorf("plans[%d].ref = %q, want %q", i, plans[i].ref, want)
		}
	}
}

// TestPlanComponentsDuplicateCoordinateTieBreak checks that when the same
// coordinate appears in two environments, install path breaks the tie
// (venv-a before venv-b regardless of input order) and the collision suffix
// disambiguates the second instance.
func TestPlanComponentsDuplicateCoordinateTieBreak(t *testing.T) {
	res := &scanner.ScanResult{
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-b"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-a"},
		},
	}
	plans, _ := planComponents(res)
	if len(plans) != 2 {
		t.Fatalf("got %d plans, want 2", len(plans))
	}
	if plans[0].pkg.InstallPath != "/opt/venv-a" {
		t.Errorf("plans[0] install path = %q, want /opt/venv-a", plans[0].pkg.InstallPath)
	}
	if plans[0].ref != "pkg:pypi/requests@2.31.0" {
		t.Errorf("plans[0].ref = %q, want pkg:pypi/requests@2.31.0", plans[0].ref)
	}
	if plans[1].ref != "pkg:pypi/requests@2.31.0#1" {
		t.Errorf("plans[1].ref = %q, want pkg:pypi/requests@2.31.0#1", plans[1].ref)
	}
}

// TestPlanComponentsRefByKeyFirstInstance checks that the coordinate → ref map
// resolves to the unsuffixed (first sorted) instance so dependency edges attach
// to the canonical graph node.
func TestPlanComponentsRefByKeyFirstInstance(t *testing.T) {
	res := &scanner.ScanResult{
		Packages: []scanner.PackageRecord{
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-b"},
			{Name: "requests", Version: "2.31.0", EnvType: scanner.EnvPip, InstallPath: "/opt/venv-a"},
		},
	}
	_, refByKey := planComponents(res)
	got := refByKey[coordKey("pypi", "requests", "2.31.0")]
	if got != "pkg:pypi/requests@2.31.0" {
		t.Errorf("refByKey = %q, want unsuffixed pkg:pypi/requests@2.31.0", got)
	}
}
