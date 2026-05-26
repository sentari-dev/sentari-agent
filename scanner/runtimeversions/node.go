package runtimeversions

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// _defaultNodeWalkDepth caps how deep DetectNodeInDir descends below the
// search dir, mirroring _defaultJDKWalkDepth / _defaultPythonWalkDepth. An
// unbounded WalkDir under deep container/volume mounts used to dominate
// scan latency; a cap of 4 still finds every real-world node layout.
const _defaultNodeWalkDepth = 4

// The `node-vX.Y.Z` marker lives in .rodata, but its offset has crept well
// past any fixed prefix: modern Node binaries embed a large V8 snapshot + ICU
// data that pushes it deep into the file (~26 MiB in Node 20+, in a ~190 MiB
// binary). The old "read the first 16 MiB" approach silently missed it. We now
// STREAM the binary in bounded-memory chunks, keeping a small overlap so the
// marker can't be split across a chunk boundary, capped at maxNodeScanBytes.
const (
	nodeScanChunkBytes = 8 * 1024 * 1024
	// "node-vMAJOR.MINOR.PATCH" is ~25 bytes; 64 is a generous boundary overlap.
	nodeScanOverlap = 64
	// Hard ceiling so a pathological huge file can't pin the scan indefinitely.
	maxNodeScanBytes = 256 * 1024 * 1024
)

var nodeVersionRe = regexp.MustCompile(`node-v(\d+\.\d+\.\d+)`)

// DetectNodeBinary reads the binary at `path` and extracts the embedded
// `node-vX.Y.Z` marker. Returns (nil, nil) when the file is missing or
// no marker is found.
//
// If `path` is itself a symlink (common on macOS/Homebrew where
// /usr/local/bin/node points into the Cellar, or under
// update-alternatives on Debian/Ubuntu), this resolves one level of
// indirection and retries on the target. InstallPath in the returned
// runtime is the ORIGINAL symlink path, so the dashboard shows where
// the user thinks node lives rather than the resolved Cellar dir.
func DetectNodeBinary(path string) (*InstalledRuntime, error) {
	return detectNodeBinaryWithLimit(path, path, 1)
}

func detectNodeBinaryWithLimit(originalPath, path string, redirectsLeft int) (*InstalledRuntime, error) {
	f, err := safeio.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if errors.Is(err, safeio.ErrSymlink) && redirectsLeft > 0 {
			// Common case: /usr/local/bin/node is a symlink into Homebrew's
			// Cellar or a node-version-manager dir. Resolve once and try
			// the real path. We deliberately limit to ONE indirection so
			// we don't follow arbitrarily long chains.
			resolved, rerr := os.Readlink(path)
			if rerr != nil {
				return nil, nil
			}
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(path), resolved)
			}
			return detectNodeBinaryWithLimit(originalPath, resolved, redirectsLeft-1)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Stream the binary looking for the marker — see the const doc above for
	// why a fixed-prefix read is no longer enough.
	version, ok := scanForNodeVersion(f)
	if !ok {
		return nil, nil
	}
	return &InstalledRuntime{
		Name:    "node",
		Version: version,
		Cycle:   CycleFor("node", version),
		// InstallPath stays the ORIGINAL path (the caller's candidate) so
		// the dashboard shows where the user expects node to live, not
		// the resolved Cellar / nvm dir.
		InstallPath: originalPath,
	}, nil
}

// scanForNodeVersion streams r looking for the embedded `node-vX.Y.Z` marker,
// returning the version and true on the first match. It reads the whole binary
// (up to maxNodeScanBytes) in bounded-memory chunks, retaining a small overlap
// between chunks so a marker straddling a chunk boundary is still found.
func scanForNodeVersion(r io.Reader) (string, bool) {
	return scanForNodeVersionChunked(r, nodeScanChunkBytes, nodeScanOverlap)
}

// scanForNodeVersionChunked is the testable core of scanForNodeVersion; the
// chunk/overlap sizes are parameters so tests can exercise boundary-straddling
// matches without multi-MiB inputs.
func scanForNodeVersionChunked(r io.Reader, chunk, overlap int) (string, bool) {
	if chunk < 1 {
		chunk = 1
	}
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, 0, chunk+overlap)
	tmp := make([]byte, chunk)
	var scanned int64
	for scanned < maxNodeScanBytes {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if m := nodeVersionRe.FindSubmatch(buf); m != nil {
				return string(m[1]), true
			}
			scanned += int64(n)
			// Retain only the trailing overlap bytes so the next chunk can
			// still match a boundary-straddling marker, without growing buf.
			if len(buf) > overlap {
				copy(buf, buf[len(buf)-overlap:])
				buf = buf[:overlap]
			}
		}
		if err != nil {
			break // io.EOF or a read error — stop scanning.
		}
	}
	return "", false
}

// DetectAllNodes scans candidate binary paths.
func DetectAllNodes(paths []string) []InstalledRuntime {
	var out []InstalledRuntime
	for _, p := range paths {
		rt, err := DetectNodeBinary(p)
		if err != nil || rt == nil {
			continue
		}
		out = append(out, *rt)
	}
	return out
}

// DetectNodeInDir is a convenience for callers that have a parent
// directory and want to probe well-known binary names.
func DetectNodeInDir(dir string) []InstalledRuntime {
	return detectNodeInDirWithDepth(dir, _defaultNodeWalkDepth)
}

func detectNodeInDirWithDepth(dir string, maxDepth int) []InstalledRuntime {
	candidates := []string{"node", "node.exe"}
	rootClean := filepath.Clean(dir)
	var out []InstalledRuntime
	for _, name := range candidates {
		_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if pathfilter.ShouldSkipDir(path) {
					return filepath.SkipDir
				}
				// Depth cap — measured in path separators below rootClean.
				if path != rootClean {
					rel, rerr := filepath.Rel(rootClean, path)
					if rerr == nil {
						if strings.Count(rel, string(filepath.Separator))+1 > maxDepth {
							return filepath.SkipDir
						}
					}
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if filepath.Base(path) != name {
				return nil
			}
			rt, err := DetectNodeBinary(path)
			if err != nil || rt == nil {
				return nil
			}
			out = append(out, *rt)
			return nil
		})
	}
	return out
}
