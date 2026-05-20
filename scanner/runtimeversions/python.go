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

// DetectAllPythons walks candidate roots looking for venvs.
func DetectAllPythons(roots []string) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			rt, err := DetectPythonInDir(path)
			if err != nil || rt == nil {
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
