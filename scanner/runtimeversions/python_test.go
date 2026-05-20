package runtimeversions

import (
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

	got := DetectAllPythons([]string{root})
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
