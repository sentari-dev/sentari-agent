package runtimeversions

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Regression: modern Node binaries push the `node-vX.Y.Z` marker past the old
// fixed 16 MiB read window (~26 MiB in Node 20+), so the detector silently
// missed it. The streaming scan must find a marker that lives beyond the first
// chunk and one that straddles a chunk boundary. Tiny chunk/overlap sizes
// exercise the same logic without multi-MiB inputs.
func TestScanForNodeVersion_beyondFirstChunk(t *testing.T) {
	data := append(bytes.Repeat([]byte{0x00}, 200), []byte("node-v22.1.0\x00")...)
	got, ok := scanForNodeVersionChunked(bytes.NewReader(data), 16, 32)
	if !ok || got != "22.1.0" {
		t.Fatalf("beyond-chunk: want 22.1.0/true, got %q/%v", got, ok)
	}
}

func TestScanForNodeVersion_straddlesChunkBoundary(t *testing.T) {
	const chunk = 16
	// Marker begins 4 bytes before the first chunk boundary, so it spans into
	// the next chunk — only the overlap retention catches it.
	data := append(bytes.Repeat([]byte{0x41}, chunk-4), []byte("node-v18.20.4\x00")...)
	got, ok := scanForNodeVersionChunked(bytes.NewReader(data), chunk, 32)
	if !ok || got != "18.20.4" {
		t.Fatalf("straddle: want 18.20.4/true, got %q/%v", got, ok)
	}
}

func TestScanForNodeVersion_noMarker(t *testing.T) {
	data := bytes.Repeat([]byte("not a node binary "), 50)
	if got, ok := scanForNodeVersionChunked(bytes.NewReader(data), 16, 32); ok || got != "" {
		t.Fatalf("no-marker: want empty/false, got %q/%v", got, ok)
	}
}

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

// TestDetectNodeInDir_respectsDepthCap mirrors the JDK/Python depth-cap
// tests: an unbounded WalkDir under deep container/volume mounts used to
// dominate scan latency. The cap (4) skips any node binary that lives
// more than 4 levels below the search dir.
func TestDetectNodeInDir_respectsDepthCap(t *testing.T) {
	root := t.TempDir()
	// Deep node at depth 6 — beyond the default cap of 4.
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "node"), []byte("ELF\x00junk\x00node-v16.20.2\x00more"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Shallow node at depth 1 — within the cap.
	shallow := filepath.Join(root, "shallow")
	if err := os.MkdirAll(shallow, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shallow, "node"), []byte("ELF\x00junk\x00node-v20.10.0\x00more"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := DetectNodeInDir(root)
	versions := make(map[string]bool)
	for _, r := range got {
		versions[r.Version] = true
	}
	if !versions["20.10.0"] {
		t.Errorf("expected to find shallow 20.10.0 node, got %+v", got)
	}
	if versions["16.20.2"] {
		t.Errorf("should NOT have found deep 16.20.2 node (beyond depth cap), got %+v", got)
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
