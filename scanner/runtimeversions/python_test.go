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
