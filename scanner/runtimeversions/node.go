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

// Node binaries embed the `node-vX.Y.Z` marker in .rodata. The old detector
// read only the first 16 MiB, but modern builds (v20+, v24) are 80–180 MiB and
// place the marker ~20–26 MiB in, so that cap silently missed them. We instead
// stream the file in bounded windows (constant memory) and search each window,
// carrying a small overlap so the marker is never split across a chunk
// boundary. A generous hard ceiling guards against pathological reads.
const (
	_nodeReadChunk   = 8 * 1024 * 1024   // streaming window size
	_nodeReadCeiling = 512 * 1024 * 1024 // never read past this many bytes
	// Overlap kept between windows — must exceed the longest possible marker
	// ("node-v" + three numeric components) so a marker straddling a window
	// boundary is reassembled in the next iteration.
	_nodeMarkerOverlap = 64
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

	// Streaming search — node binaries are large and the marker can sit tens
	// of MiB in (see const doc). A bounded window + overlap keeps memory flat
	// while covering the whole file up to the ceiling.
	version, err := scanNodeVersion(io.LimitReader(f, _nodeReadCeiling))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if version == "" {
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

// scanNodeVersion streams r in bounded windows and returns the first
// `node-vX.Y.Z` version found (or "" if none). The last _nodeMarkerOverlap
// bytes of each window are prepended to the next so a marker spanning a
// read boundary is still matched.
func scanNodeVersion(r io.Reader) (string, error) {
	return scanNodeVersionChunked(r, _nodeReadChunk)
}

// scanNodeVersionChunked is the testable core of scanNodeVersion with an
// injectable window size so tests can exercise the cross-boundary overlap
// without materializing multi-MiB inputs.
func scanNodeVersionChunked(r io.Reader, chunkSize int) (string, error) {
	chunk := make([]byte, chunkSize)
	var carry []byte
	for {
		n, rerr := r.Read(chunk)
		if n > 0 {
			hay := append(carry, chunk[:n]...)
			if m := nodeVersionRe.FindSubmatch(hay); m != nil {
				return string(m[1]), nil
			}
			if len(hay) > _nodeMarkerOverlap {
				carry = append(carry[:0], hay[len(hay)-_nodeMarkerOverlap:]...)
			} else {
				carry = append(carry[:0], hay...)
			}
		}
		if errors.Is(rerr, io.EOF) {
			return "", nil
		}
		if rerr != nil {
			return "", rerr
		}
	}
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
