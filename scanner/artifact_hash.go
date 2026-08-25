package scanner

import (
	"crypto/sha256"
	"encoding/hex"
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

var (
	artifactHashMemo   = make(map[artifactHashMemoKey]string)
	artifactHashMemoMu sync.Mutex
)

// HashArtifact returns the lowercase-hex SHA-256 of the single regular file at
// path, or "" when it cannot be hashed (missing, symlink, non-regular, larger
// than maxBytes, or unreadable). It is the shared artifact-hash primitive for
// the SBOM “sha256“ element (SBOM-completeness v2, Gap 1 §4.5).
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
// truncated.
func HashArtifact(path string, maxBytes int64) string {
	// Lstat first: skip symlinks (size-cap-bypass vector) and non-regular files,
	// and read mtime+size for the memo key without opening.
	li, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	if mode := li.Mode(); mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return ""
	}

	key := artifactHashMemoKey{path: path, mtime: li.ModTime().UnixNano(), size: li.Size()}
	artifactHashMemoMu.Lock()
	cached, ok := artifactHashMemo[key]
	artifactHashMemoMu.Unlock()
	if ok {
		return cached
	}

	if li.Size() > maxBytes {
		return ""
	}

	f, err := safeio.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	// LimitReader to maxBytes+1 so a file that grew past the cap since Lstat is
	// detectable — refuse rather than hash a truncated prefix.
	n, err := io.Copy(h, io.LimitReader(f, maxBytes+1))
	if err != nil || n > maxBytes {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))

	artifactHashMemoMu.Lock()
	artifactHashMemo[key] = sum
	artifactHashMemoMu.Unlock()
	return sum
}
