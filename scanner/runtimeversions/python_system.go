package runtimeversions

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
)

// System-Python detection — separate from DetectAllPythons (which only
// reads `pyvenv.cfg` and therefore finds venvs but never the underlying
// interpreters they're spawned from).  For NIS2 / EOL evidence we also
// need to surface the actual interpreter installs: Homebrew on macOS,
// python.org framework, distro packages on Linux, and the per-user
// Windows installer.
//
// We deliberately do NOT run any interpreter binary (CLAUDE.md
// constraint "No binary invocation").  Instead each layout has a
// recognisable on-disk shape we read directly:
//
//   * Homebrew Cellar:
//       /opt/homebrew/Cellar/python@<series>/<full-version>/
//       /usr/local/Cellar/python@<series>/<full-version>/         (Intel)
//     Both levels of the path carry the version explicitly.
//
//   * Python.framework (python.org installer / Xcode CLT shim):
//       /Library/Frameworks/Python.framework/Versions/<series>/
//     Only the series (X.Y) is in the path; the patch version sits
//     inside the install but isn't worth a second walk — series-only
//     is what endoflife.date keys on anyway.
//
//   * Linux distro headers:
//       /usr/lib/python<series>/         (Debian/Ubuntu)
//       /usr/lib64/python<series>/       (RHEL/Fedora)
//       /usr/local/lib/python<series>/   (compiled-from-source)
//     The directory name carries the series.
//
//   * Windows per-user / per-machine:
//       <ProgramFiles>\Python<XY>\          (e.g. Python311\)
//       %LOCALAPPDATA%\Programs\Python\Python<XY>\
//     The directory name carries a flattened series ("311" => "3.11").
//
//   * pyenv / asdf version managers:
//       ~/.pyenv/versions/<full-version>/
//       ~/.asdf/installs/python/<full-version>/
//     One child dir per installed interpreter, named by the full
//     version.  Package scanning already walks these via
//     extraScanRoots; surfacing the interpreters here keeps the
//     runtime and package views symmetric.
//
// Versions are emitted as the most specific value the path reveals.
// The server's runtime_eol_cycle.py re-derives the cycle key from the
// X.Y series, so over-specific versions are harmless; missing-patch
// versions are tolerated.

// homebrewCellarRe matches the inner full-version directory of a
// Homebrew formula, e.g. `3.13.7` or `3.11.10_1`.
var homebrewCellarRe = regexp.MustCompile(`^\d+\.\d+\.\d+(?:_\d+)?$`)

// seriesDirRe matches `X.Y` (framework Versions/ entries).
var seriesDirRe = regexp.MustCompile(`^\d+\.\d+$`)

// pythonSeriesDirRe matches distro lib dirs like `python3.11`.
var pythonSeriesDirRe = regexp.MustCompile(`^python(\d+\.\d+)$`)

// windowsPythonDirRe matches Windows install dirs like `Python311` →
// captures the flattened series.
var windowsPythonDirRe = regexp.MustCompile(`^Python(\d)(\d+)$`)

// versionedPythonDirRe matches a pyenv/asdf install dir named by its
// version, e.g. `3.8.18` or `3.11`.  pyenv (~/.pyenv/versions) and asdf
// (~/.asdf/installs/python) both lay out one child dir per installed
// interpreter under a shared parent, with the child's name being the
// full version.
var versionedPythonDirRe = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// DetectAllSystemPythons walks the supplied roots and emits one
// InstalledRuntime per recognised interpreter install.  The shape of
// each root selects the layout reader — we don't try every reader
// against every root because each one assumes a specific naming
// convention.
//
// Unrecognised roots are skipped silently — the caller has already
// filtered to existing dirs, but a future Homebrew layout change or
// a hand-crafted /opt symlink shouldn't make the scan log noisy.
func DetectAllSystemPythons(ctx context.Context, roots []string) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		if ctx.Err() != nil {
			return out
		}
		clean := filepath.Clean(root)
		base := filepath.Base(clean)
		switch {
		case strings.HasSuffix(clean, "Cellar"):
			out = append(out, detectHomebrewPythons(clean)...)
		case base == "Versions" && strings.Contains(clean, "Python.framework"):
			out = append(out, detectFrameworkPythons(clean)...)
		case (base == "versions" && strings.Contains(clean, ".pyenv")) ||
			(base == "python" && strings.Contains(clean, ".asdf")):
			// pyenv (~/.pyenv/versions) and asdf
			// (~/.asdf/installs/python): one version-named child dir
			// per installed interpreter — same reader handles both.
			out = append(out, detectVersionedPythons(clean)...)
		case base == "lib" || base == "lib64" || base == "local":
			out = append(out, detectLinuxLibPythons(ctx, clean)...)
		case base == "Python" || base == "Programs":
			// Windows: <ProgramFiles>\Python<XY>\ or
			// %LOCALAPPDATA%\Programs\Python\Python<XY>\.
			out = append(out, detectWindowsPythons(clean)...)
		case strings.HasPrefix(base, "Python"):
			// A direct `<ProgramFiles>\Python311\` root.
			if rt := windowsPythonFromDir(clean); rt != nil {
				out = append(out, *rt)
			}
		}
	}
	return out
}

// detectHomebrewPythons scans <root>/python@<series>/<full-version>/
// and emits one runtime per inner full-version directory.  Homebrew can
// keep multiple patch versions side-by-side (LRU pruning is opt-in), so
// every dir on the list is a real interpreter.
func detectHomebrewPythons(root string) []InstalledRuntime {
	var out []InstalledRuntime
	formulas, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, f := range formulas {
		if !f.IsDir() || !strings.HasPrefix(f.Name(), "python@") {
			continue
		}
		if pathfilter.ShouldSkipDir(filepath.Join(root, f.Name())) {
			continue
		}
		formulaDir := filepath.Join(root, f.Name())
		patches, err := os.ReadDir(formulaDir)
		if err != nil {
			continue
		}
		for _, p := range patches {
			if !p.IsDir() || !homebrewCellarRe.MatchString(p.Name()) {
				continue
			}
			out = append(out, InstalledRuntime{
				Name:        RuntimePython,
				Version:     strings.SplitN(p.Name(), "_", 2)[0], // strip `_N` revision
				Cycle:       CycleFor(RuntimePython, p.Name()),
				InstallPath: filepath.Join(formulaDir, p.Name()),
			})
		}
	}
	return out
}

// detectFrameworkPythons scans Python.framework/Versions/<series>/.
// Only the X.Y series is recorded — the framework layout doesn't carry
// the patch number in the path and we don't open the interpreter to
// ask.  The server-side cycle derivation only needs X.Y anyway.
func detectFrameworkPythons(root string) []InstalledRuntime {
	var out []InstalledRuntime
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() || !seriesDirRe.MatchString(e.Name()) {
			continue
		}
		out = append(out, InstalledRuntime{
			Name:        RuntimePython,
			Version:     e.Name(),
			Cycle:       CycleFor(RuntimePython, e.Name()),
			InstallPath: filepath.Join(root, e.Name()),
		})
	}
	return out
}

// detectLinuxLibPythons reads <root>/python<series>/ subdirs.  Each
// such dir is a distro-installed interpreter's lib directory; the
// series is in the name.
func detectLinuxLibPythons(ctx context.Context, root string) []InstalledRuntime {
	var out []InstalledRuntime
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if werr != nil {
			// EACCES on /usr/local/lib is common on locked-down hosts —
			// skip without bubbling, like the Python venv walker does.
			if path == root {
				return werr
			}
			return nil
		}
		if path == root {
			return nil // recurse into root, don't try to match it
		}
		if d.IsDir() {
			if m := pythonSeriesDirRe.FindStringSubmatch(filepath.Base(path)); m != nil {
				out = append(out, InstalledRuntime{
					Name:        RuntimePython,
					Version:     m[1],
					Cycle:       CycleFor(RuntimePython, m[1]),
					InstallPath: path,
				})
			}
			// Only descend one level: distro layouts put pythonX.Y/
			// directly under the root, never nested.
			if path != root {
				return filepath.SkipDir
			}
		}
		return nil
	})
	return out
}

// detectWindowsPythons reads a <ProgramFiles>\Python or Programs\Python
// directory and emits one runtime per recognised `Python<XY>\` child.
func detectWindowsPythons(root string) []InstalledRuntime {
	var out []InstalledRuntime
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if rt := windowsPythonFromDir(filepath.Join(root, e.Name())); rt != nil {
			out = append(out, *rt)
		}
	}
	return out
}

// detectVersionedPythons reads a pyenv (~/.pyenv/versions) or asdf
// (~/.asdf/installs/python) root and emits one runtime per installed
// interpreter.  Each child dir must (a) be named like a version and
// (b) carry a real interpreter payload — a `bin/` launcher dir or a
// `lib/python<X.Y>/` stdlib dir.  The payload check keeps stray
// version-shaped dirs (a half-deleted install, or an empty scaffold)
// out of the runtime list, while a non-version name (a pyenv-virtualenv
// like "my-env") is already rejected by the regexp.
func detectVersionedPythons(root string) []InstalledRuntime {
	var out []InstalledRuntime
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() || !versionedPythonDirRe.MatchString(e.Name()) {
			continue
		}
		installDir := filepath.Join(root, e.Name())
		if !hasInterpreterPayload(installDir) {
			continue
		}
		out = append(out, InstalledRuntime{
			Name:        RuntimePython,
			Version:     e.Name(),
			Cycle:       CycleFor(RuntimePython, e.Name()),
			InstallPath: installDir,
		})
	}
	return out
}

// hasInterpreterPayload reports whether dir looks like a real CPython
// install rather than a stray version-named directory: it must contain
// a `bin/` launcher dir or a `lib/python<X.Y>/` stdlib dir.  Cheap
// stat/readdir checks only — no interpreter invocation.
func hasInterpreterPayload(dir string) bool {
	if st, err := os.Stat(filepath.Join(dir, "bin")); err == nil && st.IsDir() {
		return true
	}
	libEntries, err := os.ReadDir(filepath.Join(dir, "lib"))
	if err != nil {
		return false
	}
	for _, e := range libEntries {
		if e.IsDir() && pythonSeriesDirRe.MatchString(e.Name()) {
			return true
		}
	}
	return false
}

// windowsPythonFromDir parses `Python<XY>` into an InstalledRuntime,
// or returns nil if the name doesn't match.
func windowsPythonFromDir(dir string) *InstalledRuntime {
	m := windowsPythonDirRe.FindStringSubmatch(filepath.Base(dir))
	if m == nil {
		return nil
	}
	version := m[1] + "." + m[2]
	return &InstalledRuntime{
		Name:        RuntimePython,
		Version:     version,
		Cycle:       CycleFor(RuntimePython, version),
		InstallPath: dir,
	}
}
