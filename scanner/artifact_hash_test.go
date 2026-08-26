package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// resetArtifactHashMemo clears the process-global memo so a test's memo
// behaviour is not perturbed by earlier tests (go test runs a package's tests
// sequentially, so this is race-free).
func resetArtifactHashMemo() {
	artifactHashMemoMu.Lock()
	artifactHashMemo = make(map[artifactHashMemoKey]string)
	artifactHashMemoMu.Unlock()
}

// TestHashArtifactMemoSkipsRehash proves the memo short-circuits the expensive
// hash on the second call (the assertion a same-value check cannot make).
func TestHashArtifactMemoSkipsRehash(t *testing.T) {
	resetArtifactHashMemo()
	dir := t.TempDir()
	path := filepath.Join(dir, "memo.bin")
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls int
	orig := artifactHasher
	artifactHasher = func(r io.Reader, max int64) (string, error) {
		calls++
		return orig(r, max)
	}
	defer func() { artifactHasher = orig }()

	first := HashArtifact(path, 1<<20)
	second := HashArtifact(path, 1<<20)
	if first == "" || first != second {
		t.Fatalf("hash mismatch: %q vs %q", first, second)
	}
	if calls != 1 {
		t.Errorf("hasher invoked %d times, want 1 (memo must short-circuit)", calls)
	}
}

func TestHashArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	content := []byte("sentari-sbom-artifact-content")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(func() []byte { s := sha256.Sum256(content); return s[:] }())

	got := HashArtifact(path, 1<<20)
	if got != want {
		t.Errorf("HashArtifact = %q, want %q", got, want)
	}
	// Memoized: a second call returns the same value.
	if again := HashArtifact(path, 1<<20); again != want {
		t.Errorf("second HashArtifact = %q, want %q", again, want)
	}
}

func TestHashArtifactMissing(t *testing.T) {
	if got := HashArtifact(filepath.Join(t.TempDir(), "nope.bin"), 1<<20); got != "" {
		t.Errorf("missing file HashArtifact = %q, want empty", got)
	}
}

func TestHashArtifactOverCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(path, make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	// Cap below the file size → refused (returns "" rather than a truncated hash).
	if got := HashArtifact(path, 1024); got != "" {
		t.Errorf("over-cap HashArtifact = %q, want empty", got)
	}
}

func TestHashArtifactRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if got := HashArtifact(link, 1<<20); got != "" {
		t.Errorf("symlink HashArtifact = %q, want empty (symlink refused)", got)
	}
}

func TestHashArtifactMemoInvalidatesOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mut.bin")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1 := HashArtifact(path, 1<<20)
	// Rewrite with different content AND a changed size so the (path,mtime,size)
	// key differs even if mtime resolution is coarse — the memo must not serve
	// the stale hash.
	if err := os.WriteFile(path, []byte("v2-longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2 := HashArtifact(path, 1<<20)
	if h1 == h2 {
		t.Errorf("memo served stale hash after content change: %q", h1)
	}
}

// fakeHashCache is an in-memory ArtifactHashCache for tests, keyed the same way
// the real SQLite cache is: one entry per path, validated on (mtime, size).
type fakeHashCache struct {
	rows map[string]struct {
		mtime, size int64
		sha         string
	}
	puts int
}

func newFakeHashCache() *fakeHashCache {
	return &fakeHashCache{rows: map[string]struct {
		mtime, size int64
		sha         string
	}{}}
}

func (f *fakeHashCache) GetHash(path string, mtime, size int64) (string, bool) {
	r, ok := f.rows[path]
	if !ok || r.mtime != mtime || r.size != size {
		return "", false
	}
	return r.sha, true
}

func (f *fakeHashCache) PutHash(path string, mtime, size int64, sha string) {
	f.puts++
	f.rows[path] = struct {
		mtime, size int64
		sha         string
	}{mtime, size, sha}
}

// TestHashArtifactPersistentCacheSkipsRehashAcrossProcesses proves that once a
// hash is in the persistent cache, a FRESH process (empty in-memory memo) skips
// the expensive re-hash — the one-shot/cron re-hash the SQLite cache exists to
// prevent (SBOM-completeness v2 §4.5).
func TestHashArtifactPersistentCacheSkipsRehashAcrossProcesses(t *testing.T) {
	resetArtifactHashMemo()
	fc := newFakeHashCache()
	SetArtifactHashCache(fc)
	defer SetArtifactHashCache(nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.jar")
	if err := os.WriteFile(path, []byte("jar-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls int
	orig := artifactHasher
	artifactHasher = func(r io.Reader, max int64) (string, error) { calls++; return orig(r, max) }
	defer func() { artifactHasher = orig }()

	first := HashArtifact(path, 1<<20)
	if first == "" {
		t.Fatal("first hash empty")
	}
	if calls != 1 || fc.puts != 1 {
		t.Fatalf("first pass: calls=%d puts=%d, want 1/1", calls, fc.puts)
	}

	// Simulate a brand-new process: the in-memory memo is gone, but the
	// persistent cache survives.
	resetArtifactHashMemo()
	second := HashArtifact(path, 1<<20)
	if second != first {
		t.Fatalf("second hash %q != first %q", second, first)
	}
	if calls != 1 {
		t.Errorf("hasher invoked %d times, want 1 (persistent cache must short-circuit the re-hash)", calls)
	}
}

// TestHashArtifactPersistentCacheStaleOnChange confirms a changed file (new
// size) is a cache MISS and gets re-hashed, not served stale.
func TestHashArtifactPersistentCacheStaleOnChange(t *testing.T) {
	resetArtifactHashMemo()
	fc := newFakeHashCache()
	SetArtifactHashCache(fc)
	defer SetArtifactHashCache(nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "mut.jar")
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	h1 := HashArtifact(path, 1<<20)
	resetArtifactHashMemo()
	if err := os.WriteFile(path, []byte("v2-different-size"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2 := HashArtifact(path, 1<<20)
	if h1 == h2 {
		t.Errorf("persistent cache served stale hash after content change: %q", h1)
	}
}
