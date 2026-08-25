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
	if cached, ok := memoLookup(memoKeyFromInfo(path, li)); ok {
		return cached
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
	// Authoritative signature from the opened descriptor: the memo key stored
	// below matches the exact bytes hashed, closing the Lstat→Open swap window.
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
	memoStore(memoKeyFromInfo(path, fi), sum)
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
