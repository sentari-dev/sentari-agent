package runtimeversions

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const maxPyvenvCfgBytes = 64 * 1024

// _defaultPythonWalkDepth caps how deep DetectAllPythons descends below
// each candidate root. Python venvs typically live at depth 1-3
// (`~/.virtualenvs/<name>/pyvenv.cfg`, `/opt/<svc>/.venv/pyvenv.cfg`,
// `/srv/<app>/<env>/.venv/pyvenv.cfg`). A cap of 4 keeps the walk cheap
// on hosts with deep container/volume mounts while still finding every
// real-world layout we know about.
const _defaultPythonWalkDepth = 4

// DetectPythonInDir reads <dir>/pyvenv.cfg for a Python virtualenv;
// the `version = X.Y.Z` line gives us the runtime version. When only a
// `version_info` line is present (uv- and PyPA-virtualenv-created venvs
// write no plain `version` key) we fall back to that, normalised to
// X.Y.Z. Returns (nil, nil) when no pyvenv.cfg or no version field is
// present.
//
// System Pythons (not in a venv) are NOT detected here — this path only
// reads pyvenv.cfg. The underlying interpreter installs (Homebrew,
// python.org framework, distro packages, the Windows installer) are
// surfaced separately by DetectAllSystemPythons in python_system.go.
func DetectPythonInDir(dir string) (*InstalledRuntime, error) {
	cfgPath := filepath.Join(dir, "pyvenv.cfg")
	raw, err := safeio.ReadFile(cfgPath, maxPyvenvCfgBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, safeio.ErrSymlink) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", cfgPath, err)
	}
	version := parsePyvenvVersion(raw)
	if version == "" {
		return nil, nil
	}
	return &InstalledRuntime{
		Name:        RuntimePython,
		Version:     version,
		Cycle:       CycleFor(RuntimePython, version),
		InstallPath: dir,
	}, nil
}

// DetectAllPythons walks candidate roots looking for venvs.  Depth is
// capped at _defaultPythonWalkDepth levels below each root.
func DetectAllPythons(ctx context.Context, roots []string) []InstalledRuntime {
	return detectAllPythonsWithDepth(ctx, roots, _defaultPythonWalkDepth)
}

func detectAllPythonsWithDepth(ctx context.Context, roots []string, maxDepth int) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		if ctx.Err() != nil {
			return out
		}
		rootClean := filepath.Clean(root)
		_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if err != nil || !d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			// Skip cloud-synced subtrees (always) and network-mounted
			// subtrees (opt-in via --exclude-network-paths) before
			// descending — iCloud Drive on macOS otherwise stalls the
			// walker for minutes pulling files on demand.
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
			rt, derr := DetectPythonInDir(path)
			if derr != nil || rt == nil {
				return nil
			}
			out = append(out, *rt)
			return filepath.SkipDir
		})
	}
	return out
}

func parsePyvenvVersion(raw []byte) string {
	var versionInfo string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		// Match the key EXACTLY. Python 3.11+ also writes a
		// `version_info = X.Y.Z.final.N` line; a prefix match on
		// "version" would wrongly capture that value.
		switch strings.TrimSpace(parts[0]) {
		case "version":
			// The clean `version = X.Y.Z` key always wins.
			return strings.TrimSpace(parts[1])
		case "version_info":
			// Fallback: uv and PyPA-virtualenv write ONLY a
			// `version_info` key (no plain `version`). Keep it in
			// case no clean `version` line appears.
			versionInfo = strings.TrimSpace(parts[1])
		}
	}
	// No clean `version` line — normalise the version_info fallback.
	return normalizeVersionInfo(versionInfo)
}

// normalizeVersionInfo turns a pyvenv.cfg `version_info` value into a clean
// X.Y.Z string. CPython writes `3.12.4.final.0`; uv and virtualenv write a
// plain `3.12.4`. When more than three dot-separated components are present
// and the 4th is a non-numeric release-level tag (e.g. `final`, `candidate`),
// we keep only the first three so server EOL correlation sees `3.12.4`.
func normalizeVersionInfo(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) > 3 && !isAllDigits(parts[3]) {
		return strings.Join(parts[:3], ".")
	}
	return v
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
