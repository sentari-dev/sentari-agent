package installgate

import (
	"os"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// orchestratorTestMap returns a verified-shape policy map with a
// single pypi proxy endpoint so Apply has work to do.
func orchestratorTestMap(pypiEndpoint string) *scanner.InstallGateMap {
	return &scanner.InstallGateMap{
		Version: 42,
		Ecosystems: map[string]scanner.InstallGateEcosystemBlock{
			"pypi": {Mode: "deny_list"},
		},
		ProxyEndpoints: map[string]string{
			"pypi": pypiEndpoint,
		},
	}
}

func TestApply_NilMap(t *testing.T) {
	res, errs := Apply(nil, ApplyOptions{})
	if len(errs) == 0 {
		t.Fatal("expected error on nil map")
	}
	if res.AnyChanged() {
		t.Error("AnyChanged should be false on nil-map error path")
	}
}

func TestApply_PipChanged(t *testing.T) {
	// Reuse the per-OS env override from pip_test.go so this test
	// passes on Windows (APPDATA-based path) as well as on
	// Linux/macOS (XDG_CONFIG_HOME / HOME).  ``want`` comes back
	// already adjusted to the platform.
	want := userHomeOverride(t, t.TempDir())

	res, errs := Apply(
		orchestratorTestMap("https://proxy.example.test/pypi/simple/"),
		ApplyOptions{
			PipScope: PipScopeUser,
			Marker: MarkerFields{
				Version: 42,
				KeyID:   "primary",
				Applied: fixedTime,
			},
		},
	)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !res.AnyChanged() {
		t.Error("expected AnyChanged=true after fresh write")
	}
	if !res.Pip.Changed {
		t.Error("expected Pip.Changed=true")
	}
	if res.Pip.Path != want {
		t.Errorf("Pip.Path: got %q, want %q", res.Pip.Path, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("pip.conf not created at %s: %v", want, err)
	}
}

func TestApply_NoProxyNoOp(t *testing.T) {
	userHomeOverride(t, t.TempDir())

	res, errs := Apply(orchestratorTestMap(""), ApplyOptions{
		PipScope: PipScopeUser,
		Marker:   MarkerFields{Applied: fixedTime},
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if res.AnyChanged() {
		t.Error("AnyChanged should be false when no proxy URL is set and no prior file exists")
	}
}
