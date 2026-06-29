package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestScannerRegistry_AllBuiltinsRegistered is the load-bearing test for
// the plugin system: it fails if a builtin scanner is ever removed from
// init() registration, or if a new scanner is added without also being
// added to the expected set.
func TestScannerRegistry_AllBuiltinsRegistered(t *testing.T) {
	want := map[string]bool{
		EnvPip:              true,
		EnvVenv:             true,
		EnvConda:            true,
		EnvPoetry:           true,
		EnvPipenv:           true,
		EnvSystemDeb:        true,
		EnvSystemRpm:        true,
		envWindowsRegistry:  true,
	}
	got := map[string]bool{}
	for _, s := range RegisteredScanners() {
		got[s.EnvType()] = true
	}
	for et := range want {
		if !got[et] {
			t.Errorf("missing registered scanner for env_type %q", et)
		}
	}
	for et := range got {
		if !want[et] {
			t.Errorf("unexpected scanner registered for env_type %q — add it to the expected set", et)
		}
	}
}

// TestScannerRegistry_NoDuplicateEnvTypes guards the invariant that each
// env_type has exactly one owning scanner.  Register() panics on collision
// today, but if registration ever moves to a path that doesn't panic, this
// assertion catches the regression.
func TestScannerRegistry_NoDuplicateEnvTypes(t *testing.T) {
	seen := map[string]string{}
	for _, s := range RegisteredScanners() {
		et := s.EnvType()
		if prev, dup := seen[et]; dup {
			t.Errorf("env_type %q registered twice (%s and %T)", et, prev, s)
		}
		seen[et] = "registered"
	}
}

// TestScannerRegistry_DoubleRegisterPanics verifies the collision guard.
func TestScannerRegistry_DoubleRegisterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	// pipScanner is already registered by pip.go's init(); re-registering
	// must panic.
	Register(pipScanner{})
}

// TestScannerFor_UnknownReturnsNil documents the lookup contract: nil for
// unknown env_types, not an error.  Callers (Runner.scanEnvironment) check
// for nil and emit a ScanError themselves.
func TestScannerFor_UnknownReturnsNil(t *testing.T) {
	if s := scannerFor("definitely-not-a-real-ecosystem"); s != nil {
		t.Errorf("expected nil for unknown env_type, got %T", s)
	}
}

// TestMarkerScanners_RoundTripFixtures is the "every marker scanner
// produces at least one package from its fixture" test.  Adding a new
// marker scanner forces adding a fixture here — the compiler won't stop
// you from skipping this but a missing entry fails the test.
//
// We deliberately do NOT include system_deb / system_rpm (require
// /var/lib/dpkg or /var/lib/rpm on the host), nor windows_registry
// (requires HKLM).  Those are RootScanners with platform- or env-
// dependent sources; they're covered separately by TestRootScanners_*.
func TestMarkerScanners_RoundTripFixtures(t *testing.T) {
	type fixture struct {
		name    string
		envType string
		build   func(t *testing.T, dir string)
	}

	fixtures := []fixture{
		{
			name:    "pip",
			envType: EnvPip,
			build: func(t *testing.T, dir string) {
				sp := filepath.Join(dir, "site-packages")
				os.MkdirAll(sp, 0o755)
				di := filepath.Join(sp, "pip_fixture-1.0.0.dist-info")
				os.MkdirAll(di, 0o755)
				os.WriteFile(filepath.Join(di, "METADATA"),
					[]byte("Metadata-Version: 2.1\nName: pip_fixture\nVersion: 1.0.0\n"), 0o644)
			},
		},
		{
			name:    "venv",
			envType: EnvVenv,
			build: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "pyvenv.cfg"),
					[]byte("home = /usr/bin\nversion = 3.11.0\n"), 0o644)
				sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
				os.MkdirAll(sp, 0o755)
				di := filepath.Join(sp, "venv_fixture-1.0.0.dist-info")
				os.MkdirAll(di, 0o755)
				os.WriteFile(filepath.Join(di, "METADATA"),
					[]byte("Metadata-Version: 2.1\nName: venv_fixture\nVersion: 1.0.0\n"), 0o644)
			},
		},
		{
			name:    "conda",
			envType: EnvConda,
			build: func(t *testing.T, dir string) {
				cm := filepath.Join(dir, "conda-meta")
				os.MkdirAll(cm, 0o755)
				payload, _ := json.Marshal(map[string]string{
					"name": "conda_fixture", "version": "1.0.0",
				})
				os.WriteFile(filepath.Join(cm, "conda_fixture-1.0.0-h0.json"), payload, 0o644)
			},
		},
		{
			name:    "poetry",
			envType: EnvPoetry,
			build: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "poetry.lock"),
					[]byte("[[package]]\nname = \"poetry_fixture\"\nversion = \"1.0.0\"\n"), 0o644)
			},
		},
		{
			name:    "pipenv",
			envType: EnvPipenv,
			build: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "Pipfile.lock"),
					[]byte(`{"_meta":{"requires":{"python_version":"3.11"}},"default":{"pipenv_fixture":{"version":"==1.0.0"}}}`), 0o644)
			},
		},
	}

	// Every MarkerScanner in the registry must have a fixture here.
	have := map[string]bool{}
	for _, f := range fixtures {
		have[f.envType] = true
	}
	for _, m := range markerScanners() {
		if !have[m.EnvType()] {
			t.Errorf("marker scanner %q has no fixture in TestMarkerScanners_RoundTripFixtures — add one", m.EnvType())
		}
	}

	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			tmp := t.TempDir()
			f.build(t, tmp)

			cfg := Config{ScanRoot: tmp, MaxDepth: 6, MaxWorkers: 2}
			r := NewRunner(cfg)
			result, err := r.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			matches := 0
			for _, p := range result.Packages {
				if p.EnvType == f.envType {
					matches++
				}
			}
			if matches == 0 {
				t.Errorf("no packages emitted for env_type %q (got %d packages total, %d errors)",
					f.envType, len(result.Packages), len(result.Errors))
			}
		})
	}
}

// TestRootScanners_DoNotFireOnScopedScan verifies that Linux dpkg/rpm
// scanners DO NOT fire when the scan is rooted at a tempdir, even on a
// host where /var/lib/dpkg/status exists.  Windows registry scanner is
// unaffected — it fires on Windows regardless of scope.
func TestRootScanners_DoNotFireOnScopedScan(t *testing.T) {
	tmp := t.TempDir()
	ctx := WithScanRoot(context.Background(), tmp)

	if IsFullSystemScan(ctx) {
		t.Fatal("tempdir should not be a full-system scan")
	}

	envs, _ := debScanner{}.DiscoverAll(ctx)
	if len(envs) != 0 {
		t.Errorf("debScanner should skip scoped scans, got %d envs", len(envs))
	}
	envs, _ = rpmScanner{}.DiscoverAll(ctx)
	if len(envs) != 0 {
		t.Errorf("rpmScanner should skip scoped scans, got %d envs", len(envs))
	}
}

// TestIsFullSystemScan covers the scope-classification helper that dpkg
// and rpm both call.  Unit-testing it in isolation protects the contract
// from churn when the helper's internals change.
func TestIsFullSystemScan(t *testing.T) {
	cases := []struct {
		root string
		want bool
	}{
		{"/", true},
		{"/opt/app", false},
		{"/tmp/fixture", false},
		{"", false},
	}
	for _, c := range cases {
		ctx := WithScanRoot(context.Background(), c.root)
		if got := IsFullSystemScan(ctx); got != c.want {
			t.Errorf("IsFullSystemScan(%q) = %v, want %v", c.root, got, c.want)
		}
	}
}
