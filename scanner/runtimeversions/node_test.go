package runtimeversions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectNodeBinary_embeddedVersion(t *testing.T) {
	got, err := DetectNodeBinary(filepath.Join("testdata", "node", "node"))
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected an InstalledRuntime, got nil")
	}
	if got.Name != "node" || got.Version != "20.10.0" || got.Cycle != "20" {
		t.Errorf("wrong: %+v", got)
	}
}

func TestDetectNodeBinary_missingFile(t *testing.T) {
	got, err := DetectNodeBinary(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestDetectNodeBinary_noVersionMarker(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "garbage")
	if err := os.WriteFile(p, []byte("some random binary content no version here"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := DetectNodeBinary(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}
