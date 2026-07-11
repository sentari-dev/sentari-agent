package runtimeversions

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Modern node binaries (v20+, v24) place the `node-vX.Y.Z` marker tens of MiB
// in, past the old 16 MiB cap. The streaming search must find a marker that
// sits beyond a single window and straddles window boundaries.
func TestScanNodeVersion_findsMarkerBeyondWindow(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte{0x00}, 100)) // junk well past the tiny window
	buf.WriteString("node-v24.7.0")            // marker spanning later chunks
	buf.Write(bytes.Repeat([]byte{0x00}, 40))
	got, err := scanNodeVersionChunked(&buf, 16) // 16-byte window forces streaming
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "24.7.0" {
		t.Fatalf("got %q, want 24.7.0", got)
	}
}

// scriptedReader returns one predefined slice per Read call, letting a test
// place a read boundary at an exact byte so a marker can be split
// mid-patch-component. chunkSize passed to scanNodeVersionChunked must be >=
// the longest piece so each Read surfaces exactly one piece.
type scriptedReader struct {
	pieces [][]byte
	i      int
}

func (s *scriptedReader) Read(p []byte) (int, error) {
	if s.i >= len(s.pieces) {
		return 0, io.EOF
	}
	n := copy(p, s.pieces[s.i])
	s.i++
	return n, nil
}

// TestScanNodeVersion_boundarySplitMidPatchDigit is the regression guard for
// the mis-version bug: a read boundary splits "node-v20.11.50" between the "5"
// and the trailing "0", so window 1 ends "…node-v20.11.5". A return-on-first
// -match would greedily yield the truncated (WRONG) "20.11.5". The
// defer-until-terminator logic must instead reassemble the marker and return
// the FULL "20.11.50".
func TestScanNodeVersion_boundarySplitMidPatchDigit(t *testing.T) {
	r := &scriptedReader{pieces: [][]byte{
		[]byte("\x00\x00junk\x00node-v20.11.5"), // window ends mid-patch-digit
		[]byte("0\x00\x00padding\x00"),          // trailing "0" + terminator
	}}
	got, err := scanNodeVersionChunked(r, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "20.11.50" {
		t.Fatalf("got %q, want 20.11.50 (truncated 20.11.5 indicates the boundary bug)", got)
	}
}

// TestScanNodeVersion_singleWindowMatch confirms a normal, non-boundary match
// (marker fully inside one window with a terminator after it) still returns
// immediately and correctly.
func TestScanNodeVersion_singleWindowMatch(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("ELF\x00node-v22.3.1\x00trailing")
	got, err := scanNodeVersionChunked(&buf, 4096)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "22.3.1" {
		t.Fatalf("got %q, want 22.3.1", got)
	}
}

// TestScanNodeVersion_matchAtEOFAccepted confirms a marker whose final digit is
// the very last byte of the stream (no trailing terminator) is accepted at EOF
// rather than deferred forever.
func TestScanNodeVersion_matchAtEOFAccepted(t *testing.T) {
	// n>0 together with io.EOF on the final read.
	r := &scriptedReader{pieces: [][]byte{
		[]byte("\x00\x00node-v18.20.4"), // marker ends exactly at end-of-stream
	}}
	got, err := scanNodeVersionChunked(r, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "18.20.4" {
		t.Fatalf("got %q, want 18.20.4", got)
	}
}

// TestScanNodeVersion_deferredMatchFlushedAtEOF covers the split-then-EOF path:
// window 1 ends mid-patch-digit (deferred) and EOF arrives with no further
// digits, so the deferred marker must be flushed and accepted as-is.
func TestScanNodeVersion_deferredMatchFlushedAtEOF(t *testing.T) {
	r := &scriptedReader{pieces: [][]byte{
		[]byte("\x00node-v16.14.2"), // deferred: ends at boundary, not EOF
		[]byte("\x00rest"),          // terminator arrives, no extra digit
	}}
	got, err := scanNodeVersionChunked(r, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "16.14.2" {
		t.Fatalf("got %q, want 16.14.2", got)
	}
}

func TestScanNodeVersion_noMarker(t *testing.T) {
	got, err := scanNodeVersionChunked(bytes.NewReader(bytes.Repeat([]byte("ELF\x00junk"), 50)), 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
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

// TestDetectNodeBinary_followsMultiHopChain models the Debian/Ubuntu
// update-alternatives layout, which is a genuine multi-hop symlink chain:
//
//	node -> alternatives/node -> nodejs (>= 2 hops) -> real binary
//
// A 1-hop cap silently missed apt-installed Node; the bounded walk must
// resolve the whole chain and still surface the ORIGINAL entry path.
func TestDetectNodeBinary_followsMultiHopChain(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "nodejs-real")
	if err := os.WriteFile(real, []byte("ELF\x7fjunk\x00node-v18.5.0-linux-x64\x00more"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Build the chain from the leaf backwards: nodejs -> real,
	// alternatives/node -> nodejs, node -> alternatives/node.
	nodejs := filepath.Join(dir, "nodejs")
	altNode := filepath.Join(dir, "alternatives-node")
	entry := filepath.Join(dir, "node")
	if err := os.Symlink(real, nodejs); err != nil {
		t.Skipf("symlink unsupported on this filesystem: %v", err)
	}
	if err := os.Symlink(nodejs, altNode); err != nil {
		t.Skipf("symlink unsupported on this filesystem: %v", err)
	}
	if err := os.Symlink(altNode, entry); err != nil {
		t.Skipf("symlink unsupported on this filesystem: %v", err)
	}
	got, err := DetectNodeBinary(entry)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil || got.Version != "18.5.0" {
		t.Fatalf("expected node 18.5.0 via multi-hop chain, got %+v", got)
	}
	if got.InstallPath != entry {
		t.Errorf("InstallPath should be the original entry path: got %q, want %q", got.InstallPath, entry)
	}
}

// TestDetectNodeBinary_chainExceedingHopCapRefused guards the bound: a
// chain longer than maxNodeSymlinkHops (or a symlink cycle) must be
// refused without an infinite loop or panic. Here the leaf is a real
// binary but sits one hop past the cap, so it is intentionally not read.
func TestDetectNodeBinary_chainExceedingHopCapRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "node-real")
	if err := os.WriteFile(real, []byte("ELF\x7fjunk\x00node-v20.0.0-linux-x64\x00more"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Chain of maxNodeSymlinkHops+1 symlinks in front of the real binary,
	// so resolving it fully would need more hops than allowed.
	target := real
	for i := 0; i <= maxNodeSymlinkHops; i++ {
		link := filepath.Join(dir, "hop"+itoa(i))
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unsupported on this filesystem: %v", err)
		}
		target = link
	}
	// target is now the outermost symlink (the entry point).
	got, err := DetectNodeBinary(target)
	// Must not resolve to a version: either an error or (nil, nil) is an
	// acceptable "refused" outcome. The contract is: no version, no panic,
	// no hang.
	if got != nil {
		t.Fatalf("expected refusal (no runtime) past hop cap, got %+v (err=%v)", got, err)
	}
}

// itoa is a tiny dependency-free int-to-string helper for building
// deterministic symlink names in the hop-cap test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
