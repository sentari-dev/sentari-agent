package runtimeversions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectPythonInVenv(t *testing.T) {
	dir := filepath.Join("testdata", "python", "venv")
	got, err := DetectPythonInDir(dir)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected an InstalledRuntime, got nil")
	}
	if got.Name != "python" || got.Version != "3.11.5" || got.Cycle != "3.11" {
		t.Errorf("wrong: %+v", got)
	}
	if got.InstallPath != dir {
		t.Errorf("InstallPath = %q, want %q", got.InstallPath, dir)
	}
}

// TestDetectPythonInDir_versionInfoBeforeVersion guards against the
// prefix-match bug: Python 3.11+ writes a `version_info = X.Y.Z.final.N`
// line into pyvenv.cfg. A naive strings.HasPrefix(line, "version") also
// matches that key. When version_info appears BEFORE the clean `version`
// line, the detector must still return the clean X.Y.Z (so server EOL
// correlation works), not "3.11.5.final.0".
func TestDetectPythonInDir_versionInfoBeforeVersion(t *testing.T) {
	dir := t.TempDir()
	cfg := "home = /usr/bin\n" +
		"version_info = 3.11.5.final.0\n" +
		"version = 3.11.5\n"
	if err := os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := DetectPythonInDir(dir)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected an InstalledRuntime, got nil")
	}
	if got.Version != "3.11.5" {
		t.Errorf("Version = %q, want clean 3.11.5 (not version_info value)", got.Version)
	}
	if got.Cycle != "3.11" {
		t.Errorf("Cycle = %q, want 3.11", got.Cycle)
	}
}

// TestDetectPythonInDir_versionInfoOnly covers uv- and PyPA-virtualenv-
// created venvs, which write ONLY a `version_info` key (no plain
// `version`). The bodies are copied verbatim from scanner/uv_test.go's
// fixtures so the two suites stay in lock-step. Both shapes must yield a
// runtime, and CPython's `3.11.0.final.0`-style value must normalise to a
// clean X.Y.Z for server EOL correlation.
func TestDetectPythonInDir_versionInfoOnly(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantVersion string
		wantCycle   string
	}{
		{
			name:        "uv-managed venv",
			body:        "home = /usr/bin\nimplementation = CPython\nuv = 0.4.18\nversion_info = 3.12.4\n",
			wantVersion: "3.12.4",
			wantCycle:   "3.12",
		},
		{
			name:        "plain cpython venv",
			body:        "home = /usr/bin\nimplementation = CPython\nversion_info = 3.11.0\ninclude-system-site-packages = false\n",
			wantVersion: "3.11.0",
			wantCycle:   "3.11",
		},
		{
			name:        "cpython version_info with release-level tag",
			body:        "home = /usr/bin\nimplementation = CPython\nversion_info = 3.12.4.final.0\n",
			wantVersion: "3.12.4",
			wantCycle:   "3.12",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := DetectPythonInDir(dir)
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}
			if got == nil {
				t.Fatal("expected an InstalledRuntime, got nil")
			}
			if got.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tc.wantVersion)
			}
			if got.Cycle != tc.wantCycle {
				t.Errorf("Cycle = %q, want %q", got.Cycle, tc.wantCycle)
			}
		})
	}
}

func TestDetectPythonInDir_noPyvenvCfg(t *testing.T) {
	dir := t.TempDir()
	got, err := DetectPythonInDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestDetectPythonInDir_pyvenvWithoutVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := DetectPythonInDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for pyvenv without version, got %+v", got)
	}
}

// TestDetectAllPythons_respectsDepthCap covers the perf fix: an
// unbounded WalkDir under /opt or /srv on hosts with deep nested
// container volumes used to dominate scan latency. The depth cap (4)
// skips any venv that lives more than 4 levels below a candidate root.
func TestDetectAllPythons_respectsDepthCap(t *testing.T) {
	root := t.TempDir()
	// Deep venv at depth 6 — beyond the default cap of 4.
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "pyvenv.cfg"), []byte("version = 3.9.18\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Shallow venv at depth 1 — within the cap.
	shallow := filepath.Join(root, "shallow-venv")
	if err := os.MkdirAll(shallow, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shallow, "pyvenv.cfg"), []byte("version = 3.11.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := DetectAllPythons(context.Background(), []string{root})
	versions := make(map[string]bool)
	for _, r := range got {
		versions[r.Version] = true
	}
	if !versions["3.11.5"] {
		t.Errorf("expected to find shallow 3.11.5 venv, got %+v", got)
	}
	if versions["3.9.18"] {
		t.Errorf("should NOT have found deep 3.9.18 venv (beyond depth cap), got %+v", got)
	}
}
