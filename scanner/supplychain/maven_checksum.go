package supplychain

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA1 is mandated by the Maven checksum spec
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const (
	// maxJarBytes is the maximum jar size we read for checksum verification.
	// 200 MiB is generous but bounded; jars over this are skipped silently.
	maxJarBytes = 200 * 1024 * 1024

	// maxSHA1FileBytes is the maximum size of the .sha1 sidecar file.
	// SHA1 hex is 40 chars; 256 bytes allows for trailing whitespace / newlines.
	maxSHA1FileBytes = 256

	// checksumMemoMaxEntries bounds the process-lifetime hash memo so a
	// long-running daemon scanning an ever-growing ~/.m2 over months of
	// uptime cannot accumulate memo entries without limit.  On overflow the
	// whole map is reset — a cheap, allocation-light strategy that trades a
	// rare cold re-hash for a hard upper bound.
	checksumMemoMaxEntries = 100_000
)

// checksumMemoKey identifies a jar by the tuple (path, mtime, size).  A jar
// whose bytes changed also changes its mtime and/or size on any sane
// filesystem, so this key both dedupes unchanged jars across scan cycles and
// invalidates automatically when a jar is rewritten in place.
type checksumMemoKey struct {
	path  string
	mtime int64 // ModTime().UnixNano()
	size  int64
}

var (
	// checksumMemo caches the computed SHA1 hex of each jar so an unchanged
	// jar is not re-hashed on every hourly scan cycle.  We memo the computed
	// hash rather than the match verdict on purpose: the .sha1 sidecar can be
	// rewritten independently of the jar, so we still compare against a fresh
	// expected value each cycle — only the expensive jar hashing is skipped.
	checksumMemoMu sync.Mutex
	checksumMemo   = make(map[checksumMemoKey]string)

	// hashJar streams a jar's bytes through SHA1 with constant memory.  It is
	// a var so tests can wrap it with a call-counting spy to prove the memo
	// short-circuits re-hashing.
	hashJar = streamJarSHA1
)

// streamJarSHA1 computes the SHA1 of the file at path using a bounded,
// constant-memory streaming read.  It refuses symlinks and non-regular files
// (via safeio.Open) and errors if the jar exceeds maxJarBytes rather than
// pulling the whole payload into memory.
func streamJarSHA1(path string) (string, error) {
	f, err := safeio.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha1.New() //nolint:gosec // SHA1 is mandated by the Maven checksum spec
	// LimitReader to maxJarBytes+1 so a read that yields more than the cap is
	// detectable — we refuse rather than silently hash a truncated prefix.
	n, err := io.Copy(h, io.LimitReader(f, maxJarBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxJarBytes {
		return "", fmt.Errorf("jar exceeds %d bytes: %s", maxJarBytes, path)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// computeJarSHA1 returns the SHA1 hex of the jar at path, consulting the
// process-lifetime memo keyed on (path, mtime, size) first.  The memo is
// guarded by a mutex because the detector may run under a concurrent walker.
func computeJarSHA1(path string, info fs.FileInfo) (string, error) {
	key := checksumMemoKey{path: path, mtime: info.ModTime().UnixNano(), size: info.Size()}

	checksumMemoMu.Lock()
	cached, ok := checksumMemo[key]
	checksumMemoMu.Unlock()
	if ok {
		return cached, nil
	}

	computed, err := hashJar(path)
	if err != nil {
		return "", err
	}

	checksumMemoMu.Lock()
	// Reset wholesale on overflow to keep the memo bounded over long uptimes.
	if len(checksumMemo) >= checksumMemoMaxEntries {
		checksumMemo = make(map[checksumMemoKey]string)
	}
	checksumMemo[key] = computed
	checksumMemoMu.Unlock()

	return computed, nil
}

// DetectChecksumMismatches walks m2Dir looking for .jar files that have a
// sibling .sha1 file. For each such pair it reads the .sha1 file, computes
// the SHA1 of the jar bytes, and emits a maven_checksum_mismatch signal
// when they disagree.
//
// Jars that have no .sha1 sibling are silently skipped — we cannot verify
// without a reference checksum.
//
// Javadoc and sources jars are ignored; they are not runtime artefacts.
func DetectChecksumMismatches(ctx context.Context, m2Dir string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(m2Dir, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if err != nil {
			return nil
		}
		// Skip symlinks
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if pathfilter.ShouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".jar") {
			return nil
		}
		// Skip javadoc / sources jars
		base := filepath.Base(path)
		if strings.HasSuffix(base, "-javadoc.jar") || strings.HasSuffix(base, "-sources.jar") {
			return nil
		}

		sha1Path := path + ".sha1"
		// Attempt to read the .sha1 sidecar directly via safeio.
		// Missing sidecar and unreadable cases both collapse to skip — no signal.
		sha1Bytes, readErr := safeio.ReadFile(sha1Path, maxSHA1FileBytes)
		if readErr != nil {
			return nil // no sidecar, or unreadable — skip
		}
		expected := strings.TrimSpace(strings.ToLower(string(sha1Bytes)))

		// Stat via the walker's DirEntry to key the memo on (path, mtime,
		// size) — unchanged jars are served from the memo instead of being
		// re-hashed every scan cycle.
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil // vanished between walk and stat — skip
		}

		// Compute SHA1 with a constant-memory streaming hash, memoised.
		computed, hashErr := computeJarSHA1(path, info)
		if hashErr != nil {
			// Jar is too large, a symlink/non-regular file, or unreadable — skip.
			return nil
		}

		if computed == expected {
			return nil
		}

		name, version := mavenCoordsFromJarPath(m2Dir, path)
		if name == "" {
			return nil
		}
		signals = append(signals, deptree.SupplyChainSignal{
			PackageName:    name,
			PackageVersion: version,
			Ecosystem:      "maven",
			SignalType:     "maven_checksum_mismatch",
			Severity:       "high",
			Source:         "agent-maven-sha1",
			Raw: map[string]interface{}{
				"jar_path": path,
				"expected": expected,
				"computed": computed,
			},
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
	}
	return signals, nil
}
