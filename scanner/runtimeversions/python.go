package runtimeversions

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
// the `version = X.Y.Z` line gives us the runtime version. Returns
// (nil, nil) when no pyvenv.cfg or no version field is present.
//
// System Pythons (not in a venv) are NOT detected here — they require
// reading the interpreter's _sysconfigdata file or similar; that's
// out of scope for Phase 4 (most fleet installs run code in venvs).
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
		Name:        "python",
		Version:     version,
		Cycle:       CycleFor("python", version),
		InstallPath: dir,
	}, nil
}

// DetectAllPythons walks candidate roots looking for venvs.  Depth is
// capped at _defaultPythonWalkDepth levels below each root.
func DetectAllPythons(roots []string) []InstalledRuntime {
	return detectAllPythonsWithDepth(roots, _defaultPythonWalkDepth)
}

func detectAllPythonsWithDepth(roots []string, maxDepth int) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		rootClean := filepath.Clean(root)
		_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
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
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "version") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
