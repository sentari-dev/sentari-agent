package osrelease

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDetect_ReadsFile exercises the real file-reading path (not just parse).
func TestDetect_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := osReleasePath
	osReleasePath = p
	defer func() { osReleasePath = orig }()

	res, ok := Detect()
	if !ok || res.ID != "debian" || res.VersionID != "12" {
		t.Fatalf("Detect() = (%+v, %v), want debian/12/true", res, ok)
	}
}

// TestDetect_OversizedRefused confirms the safeio size cap is honoured: a file
// larger than maxOSReleaseSize must not be read, so Detect reports not-found.
func TestDetect_OversizedRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	big := "ID=debian\n" + strings.Repeat("X", maxOSReleaseSize+1)
	if err := os.WriteFile(p, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := osReleasePath
	osReleasePath = p
	defer func() { osReleasePath = orig }()

	if _, ok := Detect(); ok {
		t.Fatal("Detect() accepted an over-cap file; safeio cap not enforced")
	}
}

// TestDetect_Missing returns not-found rather than erroring.
func TestDetect_Missing(t *testing.T) {
	orig := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { osReleasePath = orig }()
	if _, ok := Detect(); ok {
		t.Fatal("Detect() reported ok for a missing file")
	}
}
