//go:build !windows

package secureperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardenFileSetsOwnerOnlyMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "device.key")
	if err := os.WriteFile(f, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := HardenFile(f); err != nil {
		t.Fatalf("HardenFile: %v", err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 600", perm)
	}
}

func TestHardenDirSetsOwnerOnlyMode(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "certs")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := HardenDir(sub); err != nil {
		t.Fatalf("HardenDir: %v", err)
	}
	info, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700", perm)
	}
}
