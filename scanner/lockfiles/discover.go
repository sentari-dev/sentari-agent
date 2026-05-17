// Package lockfiles walks a project root and discovers known lockfile
// formats. For each match it produces a deptree.LockfileMeta with
// path, format, ecosystem, sha256, last_modified, and a quick
// declared_packages_count heuristic.
//
// The agent does NOT upload lockfile contents — only the metadata.
// The server uses sha256 to detect drift between scans.
package lockfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"gopkg.in/yaml.v3"
)

// filenameMatcher pairs a filename pattern with the format + ecosystem
// it represents. Patterns are exact basename matches (case-sensitive
// on Linux/macOS, case-insensitive on Windows due to FS semantics).
type filenameMatcher struct {
	basename  string
	format    string
	ecosystem string
}

var knownLockfiles = []filenameMatcher{
	// npm family
	{"package-lock.json", "package_lock_v3", "npm"}, // version detected at read time
	{"yarn.lock", "yarn_v1", "npm"},
	{"pnpm-lock.yaml", "pnpm_lock", "npm"},
	// Maven
	{"pom.xml", "pom_xml", "maven"},
	// NuGet
	{"packages.lock.json", "packages_lock_json", "nuget"},
	{"project.assets.json", "project_assets_json", "nuget"},
	// PyPI
	{"poetry.lock", "poetry_lock", "pypi"},
	{"uv.lock", "uv_lock", "pypi"},
	{"Pipfile.lock", "pipfile_lock", "pypi"},
	{"requirements.txt", "requirements_txt", "pypi"},
}

// Default max walk depth — deep enough to catch monorepos with N levels
// of nesting, shallow enough to avoid traversing massive node_modules
// trees (handled explicitly by skip rules below).
const defaultMaxDepth = 8

// Directories to skip during the walk. These are common per-language
// vendored-dep directories that we DON'T want to recurse into because
// (a) they contain nested lockfiles that aren't the project's own and
// (b) they can be enormous.
var skipDirs = map[string]struct{}{
	"node_modules": {},
	".git":         {},
	".hg":          {},
	".svn":         {},
	"venv":         {},
	".venv":        {},
	"__pycache__":  {},
	"target":       {}, // Java/Rust build output
	"build":        {},
	"dist":         {},
	".gradle":      {},
	".idea":        {},
	".vscode":      {},
}

// DiscoverInRoot walks `root` looking for lockfiles. The walk skips
// common vendored-dependency directories (node_modules, venv, target,
// etc.) and caps recursion at defaultMaxDepth levels.
//
// Returns the collected metadata. Individual file errors (e.g. open
// failure on a single lockfile) are logged via the returned error;
// the slice still contains everything that could be read successfully.
func DiscoverInRoot(root string) ([]deptree.LockfileMeta, error) {
	var results []deptree.LockfileMeta
	var firstErr error

	rootClean := filepath.Clean(root)
	walkErr := filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Inaccessible paths shouldn't abort the whole walk.
			return nil
		}
		if d.IsDir() {
			if path != rootClean {
				name := d.Name()
				if _, skip := skipDirs[name]; skip {
					return filepath.SkipDir
				}
				// Depth cap.
				rel, _ := filepath.Rel(rootClean, path)
				if depthOf(rel) > defaultMaxDepth {
					return filepath.SkipDir
				}
			}
			return nil
		}
		name := d.Name()
		for _, matcher := range knownLockfiles {
			if matcher.basename != name {
				continue
			}
			meta, mErr := buildMeta(path, matcher)
			if mErr != nil {
				if firstErr == nil {
					firstErr = mErr
				}
				return nil
			}
			results = append(results, meta)
			return nil
		}
		return nil
	})
	if walkErr != nil && firstErr == nil {
		firstErr = walkErr
	}
	return results, firstErr
}

func depthOf(rel string) int {
	if rel == "." || rel == "" {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}

func buildMeta(path string, matcher filenameMatcher) (deptree.LockfileMeta, error) {
	st, err := os.Stat(path)
	if err != nil {
		return deptree.LockfileMeta{}, fmt.Errorf("stat %s: %w", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return deptree.LockfileMeta{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return deptree.LockfileMeta{}, fmt.Errorf("hash %s: %w", path, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	// Detect npm package-lock format version at read time.
	format := matcher.format
	if matcher.basename == "package-lock.json" {
		if v, err := detectPackageLockVersion(path); err == nil {
			format = v
		}
	}
	count := declaredCount(path, matcher.basename)
	return deptree.LockfileMeta{
		Path:                  path,
		Format:                format,
		Ecosystem:             matcher.ecosystem,
		SHA256:                sum,
		LastModified:          st.ModTime().UTC(),
		DeclaredPackagesCount: count,
		DriftStatus:           "unknown", // server stamps the real value during ingest
	}, nil
}

func detectPackageLockVersion(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var probe struct {
		LockfileVersion int `json:"lockfileVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	switch probe.LockfileVersion {
	case 2:
		return "package_lock_v2", nil
	case 3:
		return "package_lock_v3", nil
	default:
		// v1 or unknown — keep contract enum stable by reporting v3
		// (the server has no enum entry for v1 and v1 is rare with npm 7+).
		return "package_lock_v3", nil
	}
}

// declaredCount is a quick heuristic per lockfile format.
// Returns 0 on parse failure rather than propagating an error —
// drift detection doesn't rely on this field's accuracy.
func declaredCount(path, basename string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	switch basename {
	case "package-lock.json":
		var p struct {
			Packages map[string]json.RawMessage `json:"packages"`
		}
		if err := json.Unmarshal(raw, &p); err == nil {
			// Subtract the root entry (key "") from the count.
			n := len(p.Packages)
			if _, ok := p.Packages[""]; ok && n > 0 {
				n--
			}
			return n
		}
	case "packages.lock.json":
		var p struct {
			Dependencies map[string]map[string]json.RawMessage `json:"dependencies"`
		}
		if err := json.Unmarshal(raw, &p); err == nil {
			total := 0
			for _, perFw := range p.Dependencies {
				total += len(perFw)
			}
			return total
		}
	case "project.assets.json":
		var p struct {
			Targets map[string]map[string]json.RawMessage `json:"targets"`
		}
		if err := json.Unmarshal(raw, &p); err == nil {
			total := 0
			for _, perTfm := range p.Targets {
				total += len(perTfm)
			}
			return total
		}
	case "Pipfile.lock":
		var p struct {
			Default map[string]json.RawMessage `json:"default"`
			Develop map[string]json.RawMessage `json:"develop"`
		}
		if err := json.Unmarshal(raw, &p); err == nil {
			return len(p.Default) + len(p.Develop)
		}
	case "yarn.lock":
		// Each section header begins a new package entry. Count
		// lines that are non-indented and end with ":".
		n := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasSuffix(line, ":") {
				n++
			}
		}
		return n
	case "pnpm-lock.yaml":
		var lock struct {
			Packages map[string]json.RawMessage `yaml:"packages"`
		}
		if err := yaml.Unmarshal(raw, &lock); err == nil {
			return len(lock.Packages)
		}
	case "requirements.txt":
		n := 0
		for _, line := range strings.Split(string(raw), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
				continue
			}
			n++
		}
		return n
	}
	return 0
}

// ErrNotFound is returned when a specific lockfile lookup fails. Not
// used by DiscoverInRoot (which always returns a slice + first error),
// but exported for callers that want to do single-file probes.
var ErrNotFound = errors.New("lockfile not found")
