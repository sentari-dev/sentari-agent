package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// artifactHashMemoKey identifies a hashed file by identity+content signature so
// an unchanged artifact is never re-hashed within one agent process lifetime.
type artifactHashMemoKey struct {
	path  string
	mtime int64
	size  int64
}

// artifactHashMemoMaxEntries bounds the process-lifetime memo so a long-lived
// serve-loop cannot accumulate entries without limit (mirrors the same guard in
// scanner/supplychain/maven_checksum.go). Above the cap we stop inserting —
// hashing still works, only the memo saving is forfeit for the rare overflow.
const artifactHashMemoMaxEntries = 100_000

var (
	artifactHashMemo   = make(map[artifactHashMemoKey]string)
	artifactHashMemoMu sync.Mutex

	// artifactHasher streams a file's SHA-256; a var so tests can wrap it with a
	// call-counting spy to prove the memo short-circuits re-hashing (mirrors the
	// hashJar seam in maven_checksum.go).
	artifactHasher = streamArtifactSHA256
)

// ArtifactHashCache is an optional PERSISTENT backing store for HashArtifact,
// keyed by (path, mtime, size) to a sha256. The in-memory memo above only
// survives one process, so a one-shot upload cron invocation (a fresh process
// each run) would re-hash every eligible artifact. Wiring a persistent cache
// (the agent's SQLite cache DB) lets those runs skip re-hashing unchanged files
// (SBOM-completeness v2 section 4.5 / v1 R1). A cache.Cache satisfies this
// interface; the agent installs it via SetArtifactHashCache after opening the
// cache. Left nil (the default, and every one-shot local --scan diagnostic and
// community build), only the in-memory memo is used — HashArtifact still works,
// just without cross-process persistence.
type ArtifactHashCache interface {
	// GetHash returns the cached sha256 for the artifact at path IF the stored
	// entry's (mtime, size) match the supplied ones, else ("", false).
	GetHash(path string, mtime, size int64) (string, bool)
	// PutHash records sha256 for the artifact at (path, mtime, size).
	PutHash(path string, mtime, size int64, sha256 string)
}

// artifactHashCache is the process-wide persistent cache installed at startup;
// nil until SetArtifactHashCache is called. Guarded by artifactHashCacheMu
// because scans run under a concurrent walker.
var (
	artifactHashCache   ArtifactHashCache
	artifactHashCacheMu sync.RWMutex
)

// SetArtifactHashCache installs (or clears, with nil) the persistent artifact-
// hash cache HashArtifact consults after the in-memory memo. Call once at
// startup, before the first scan.
func SetArtifactHashCache(c ArtifactHashCache) {
	artifactHashCacheMu.Lock()
	artifactHashCache = c
	artifactHashCacheMu.Unlock()
}

func persistentHashCache() ArtifactHashCache {
	artifactHashCacheMu.RLock()
	defer artifactHashCacheMu.RUnlock()
	return artifactHashCache
}

// HashArtifact returns the lowercase-hex SHA-256 of the single regular file at
// path, or "" when it cannot be hashed (missing, symlink, non-regular, larger
// than maxBytes, or unreadable). It is the shared artifact-hash primitive for
// the SBOM sha256 element (SBOM-completeness v2, Gap 1 §4.5).
//
// Callers use it ONLY where exactly one concrete installed file maps to one
// coordinate (a plain library JAR, a .nupkg, a single-file Go binary's main
// module). Multi-file installs (deb/rpm/pip trees) and multi-coordinate
// archives get no hash — a wrong hash is worse than none.
//
// Results are memoized by (path, mtime, size) for the process lifetime so a
// long-lived agent doesn't re-hash an unchanged artifact on every scan cycle
// (mirrors scanner/supplychain/maven_checksum.go). The read is symlink-refusing
// (safeio.Open) and streamed with constant memory, bounded at maxBytes so a
// hostile oversized file cannot pin CPU — it is skipped (returns "") rather than
// truncated. The stored memo key is taken from the OPEN file descriptor's stat,
// not the pre-open Lstat, so a file swapped between the two can never poison the
// memo with a hash that doesn't match the recorded (mtime, size).
func HashArtifact(path string, maxBytes int64) string {
	// Lstat first: skip symlinks (size-cap-bypass vector) and non-regular files,
	// and derive a fast-path memo key without opening.
	li, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	if mode := li.Mode(); mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return ""
	}
	lkey := memoKeyFromInfo(path, li)
	if cached, ok := memoLookup(lkey); ok {
		return cached
	}
	// Persistent cache (if installed): a fresh process — e.g. a one-shot
	// ``--upload`` cron run — starts with an empty in-memory memo, so consult the
	// on-disk cache before paying the full-file read. A hit is promoted into the
	// in-memory memo so repeat lookups this process stay lock-cheap.
	if pc := persistentHashCache(); pc != nil {
		if sum, ok := pc.GetHash(path, lkey.mtime, lkey.size); ok {
			memoStore(lkey, sum)
			return sum
		}
	}
	if li.Size() > maxBytes {
		return ""
	}

	// safeio.Open refuses a symlink at the leaf and re-verifies regular-file on
	// the held fd (no path-based TOCTOU).
	f, err := safeio.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	// Authoritative signature from the opened descriptor: the memo keys stored
	// below match the exact bytes hashed, closing the Lstat→Open swap window.
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	if fi.Size() > maxBytes {
		return ""
	}

	sum, err := artifactHasher(f, maxBytes)
	if err != nil {
		return ""
	}
	fkey := memoKeyFromInfo(path, fi)
	memoStore(fkey, sum)
	if pc := persistentHashCache(); pc != nil {
		pc.PutHash(path, fkey.mtime, fkey.size, sum)
	}
	return sum
}

func memoKeyFromInfo(path string, fi os.FileInfo) artifactHashMemoKey {
	return artifactHashMemoKey{path: path, mtime: fi.ModTime().UnixNano(), size: fi.Size()}
}

func memoLookup(key artifactHashMemoKey) (string, bool) {
	artifactHashMemoMu.Lock()
	defer artifactHashMemoMu.Unlock()
	v, ok := artifactHashMemo[key]
	return v, ok
}

func memoStore(key artifactHashMemoKey, sum string) {
	artifactHashMemoMu.Lock()
	defer artifactHashMemoMu.Unlock()
	if len(artifactHashMemo) >= artifactHashMemoMaxEntries {
		return // bounded: forfeit the memo saving rather than grow without limit
	}
	artifactHashMemo[key] = sum
}

// streamArtifactSHA256 hashes r with constant memory, refusing to hash more than
// maxBytes: LimitReader(maxBytes+1) makes a file that grew past the cap since the
// stat detectable, so it errors rather than hashing a truncated prefix.
func streamArtifactSHA256(r io.Reader, maxBytes int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBytes {
		return "", fmt.Errorf("artifact exceeds %d bytes", maxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
