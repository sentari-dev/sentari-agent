package runtimeversions

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxNodeBinaryBytes is intentionally bounded to the first 16 MiB of the
// binary. The `node-vX.Y.Z` marker is embedded in .rodata and is reliably
// present near the start of the binary across all Node versions we've seen.
// Reading 100+ MiB just to grep for a 15-byte marker is wasteful.
// If a future Node binary moves the marker past the cap, this detector
// will silently miss it; a streaming search is the proper Phase 5 fix.
const maxNodeBinaryBytes = 16 * 1024 * 1024

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

	// Bounded read — we never need the full binary. See doc on
	// maxNodeBinaryBytes for the rationale.
	raw, err := io.ReadAll(io.LimitReader(f, maxNodeBinaryBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	m := nodeVersionRe.FindSubmatch(raw)
	if m == nil {
		return nil, nil
	}
	version := string(m[1])
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
	candidates := []string{"node", "node.exe"}
	var out []InstalledRuntime
	for _, name := range candidates {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
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
