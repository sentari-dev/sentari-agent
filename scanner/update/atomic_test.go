package update

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestAtomicReplace_stagesIntoInstallDir verifies that the activation
// step never leaves the install path empty even when the staged binary
// originates from a different directory (the data dir).  The staged
// source is copied into a temp file in the SAME directory as the
// install path, then renamed in place, so the final rename is always
// intra-filesystem.
func TestAtomicReplace_stagesIntoInstallDir(t *testing.T) {
	tmp := t.TempDir()
	// Simulate cross-dir layout: staged binary in a sibling "data"
	// subdir, install path elsewhere.
	stagedDir := filepath.Join(tmp, "data", "staged")
	if err := os.MkdirAll(stagedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stagedPath := filepath.Join(stagedDir, "sentari-agent.new")
	newBytes := []byte("new-binary-bytes")
	if err := os.WriteFile(stagedPath, newBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	installDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatal(err)
	}
	installPath := filepath.Join(installDir, "sentari-agent")
	if err := os.WriteFile(installPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := atomicReplace(stagedPath, installPath); err != nil {
		t.Fatalf("atomicReplace: %v", err)
	}

	got, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("read install path: %v", err)
	}
	if !bytes.Equal(got, newBytes) {
		t.Fatalf("install path holds wrong bytes: %q", got)
	}
	prev, err := os.ReadFile(installPath + ".prev")
	if err != nil {
		t.Fatalf("read .prev: %v", err)
	}
	if !bytes.Equal(prev, []byte("old-binary")) {
		t.Fatalf(".prev holds wrong bytes: %q", prev)
	}

	// The temp landing file in the install dir must not linger.
	leftover := filepath.Join(installDir, ".sentari-agent.new")
	if _, err := os.Stat(leftover); err == nil {
		t.Fatalf("temp landing file %s was not cleaned up", leftover)
	}
}

// TestCopyFileSync_roundTrips exercises the EXDEV copy fallback helper
// directly: it must reproduce the bytes and be readable + executable.
func TestCopyFileSync_roundTrips(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	dst := filepath.Join(tmp, "dst")
	want := []byte("copy-me-across-filesystems")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFileSync(src, dst, 0o755); err != nil {
		t.Fatalf("copyFileSync: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("copied bytes differ: %q", got)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Fatalf("copied file is not executable: %v", fi.Mode())
	}
}
