package runtimeversions

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const maxNodeBinaryBytes = 200 * 1024 * 1024 // 200 MiB — node ~100 MiB on Linux x64

var nodeVersionRe = regexp.MustCompile(`node-v(\d+\.\d+\.\d+)`)

// DetectNodeBinary reads the binary at `path` and extracts the embedded
// `node-vX.Y.Z` marker. Returns (nil, nil) when the file is missing or
// no marker is found.
func DetectNodeBinary(path string) (*InstalledRuntime, error) {
	raw, err := safeio.ReadFile(path, maxNodeBinaryBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, safeio.ErrSymlink) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	m := nodeVersionRe.FindSubmatch(raw)
	if m == nil {
		return nil, nil
	}
	version := string(m[1])
	return &InstalledRuntime{
		Name:        "node",
		Version:     version,
		Cycle:       CycleFor("node", version),
		InstallPath: path,
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
