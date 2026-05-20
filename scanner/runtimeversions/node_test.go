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

// TestDetectNodeBinary_followsSymlinkOnce covers the Homebrew /
// update-alternatives case where /usr/local/bin/node is a symlink to
// the actual binary. safeio refuses to follow leaf symlinks (correct
// security default), but the runtime detector needs ONE level of
// indirection to find the real binary. InstallPath should remain the
// original symlink path so the dashboard surfaces where the user
// expects node to live.
func TestDetectNodeBinary_followsSymlinkOnce(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-node")
	if err := os.WriteFile(real, []byte("ELF\x7fjunk\x00node-v18.5.0-linux-x64\x00more"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "node")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported on this filesystem: %v", err)
	}
	got, err := DetectNodeBinary(link)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil || got.Version != "18.5.0" {
		t.Fatalf("expected node 18.5.0 via symlink resolution, got %+v", got)
	}
	if got.InstallPath != link {
		t.Errorf("InstallPath should be the symlink path (not resolved): got %q, want %q", got.InstallPath, link)
	}
}
