// Package lockfiles walks a project root and discovers known lockfile
// formats. For each match it produces a deptree.LockfileMeta with
// path, format, ecosystem, sha256, last_modified, and a quick
// declared_packages_count heuristic.
//
// The agent does NOT upload lockfile contents — only the metadata.
// The server uses sha256 to detect drift between scans.
package lockfiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
	"gopkg.in/yaml.v3"
)

// Per-lockfile read caps.  Lockfiles in large monorepos can be tens of
// megabytes; metadata files (pom.xml, .nuspec) are tiny.  These caps
// are loose enough to never reject a legitimate lockfile and tight
// enough to refuse pathological inputs.
const (
	maxLockfileBytes = 50 << 20 // 50 MiB — package-lock / yarn.lock / pnpm-lock
	maxMetadataBytes = 1 << 20  // 1 MiB  — pom.xml / .nuspec
)

// yarnBerryProbeBytes bounds how much of a yarn.lock head is inspected
// to distinguish berry (v2+) from classic (v1).  The `__metadata:`
// marker always sits at the very top (after a two-line comment header),
// so a small window is sufficient and a marker further down is ignored
// by design — a classic v1 lockfile that happens to contain the literal
// string deeper in the file must NOT be misclassified as berry.
const yarnBerryProbeBytes = 256

// readLockfile reads a lockfile's bytes with the shared size cap.  It is
// a package var so tests can install a call-counting spy proving
// buildMeta reads each file exactly once (before this refactor a single
// lockfile was read up to three times: kind/version probe, drift hash,
// and declared-count parse).  safeio.ReadFile refuses symlinks and
// non-regular files and returns ErrTooLarge — never a partial buffer —
// for a file over the cap, so an oversized lockfile is refused rather
// than streamed byte-by-byte through the hash as it was before.
var readLockfile = func(path string) ([]byte, error) {
	return safeio.ReadFile(path, maxLockfileBytes)
}

// errSkipLockfile is returned by buildMeta when a discovered file
// matches a known filename but the agent intentionally drops it from
// the v3 payload (e.g. a v1 npm package-lock.json — no schema enum
// entry exists for it, and silently remapping to v3 makes downstream
// parsers log warnings).  See packageLockFormat for details.
var errSkipLockfile = errors.New("lockfile intentionally skipped")

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
//
// The walk honours ctx cancellation: a cancelled scan (operator Ctrl-C,
// supervisor timeout) stops the walk within one directory step via
// fs.SkipAll rather than running the full tree to completion.
func DiscoverInRoot(ctx context.Context, root string) ([]deptree.LockfileMeta, error) {
	var results []deptree.LockfileMeta
	var firstErr error

	rootClean := filepath.Clean(root)
	walkErr := filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			// Cancelled — stop the walk cleanly (fs.SkipAll makes
			// WalkDir return nil); partial results already collected
			// are still returned. The caller re-checks ctx.Err().
			return fs.SkipAll
		}
		if err != nil {
			// Inaccessible paths shouldn't abort the whole walk.
			return nil
		}
		// Refuse to descend through symlinked directories and refuse to
		// read symlinked file leaves — defends against a vendored dep
		// linking into /etc or an attacker-controlled tree (safeio
		// already enforces leaf refusal on the read path, but skipping
		// here also saves the open() syscall).
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != rootClean {
				name := d.Name()
				if _, skip := skipDirs[name]; skip {
					return filepath.SkipDir
				}
				// Skip cloud-synced subtrees (always) and network mounts
				// (opt-in) so lockfile discovery on a Mac doesn't stall
				// the agent for minutes pulling files from iCloud.
				if pathfilter.ShouldSkipDir(path) {
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
				if errors.Is(mErr, errSkipLockfile) {
					// Intentional drop (e.g. v1 package-lock).  Not an
					// error — emit nothing and move on.
					return nil
				}
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
	// mtime is stat-only; the drift hash + kind detection + declared
	// count all derive from ONE read of the bytes below.
	st, err := os.Stat(path)
	if err != nil {
		return deptree.LockfileMeta{}, fmt.Errorf("stat %s: %w", path, err)
	}

	// Single, size-capped read.  safeio.ReadFile refuses a symlinked
	// leaf and a non-regular file, and returns ErrTooLarge (never a
	// partial buffer) for a lockfile over maxLockfileBytes — so an
	// oversized lockfile is refused here instead of being streamed
	// unbounded through the hash as the previous safeio.Open+io.Copy did.
	raw, err := readLockfile(path)
	if err != nil {
		return deptree.LockfileMeta{}, fmt.Errorf("read %s: %w", path, err)
	}

	// Detect npm package-lock format version BEFORE we commit to
	// emitting metadata — v1 lockfiles intentionally drop out (see
	// packageLockFormat for rationale).
	format := matcher.format
	if matcher.basename == "package-lock.json" {
		v, verr := packageLockFormat(raw)
		if verr == nil && v == "" {
			return deptree.LockfileMeta{}, errSkipLockfile
		}
		if verr == nil {
			format = v
		}
	}
	// yarn.lock: distinguish berry (v2+) from classic (v1).  Berry
	// lockfiles open with a `__metadata:` block; the v1 dep-tree parser
	// emits garbage on the berry format, so classify it distinctly and
	// let the parser bail (ParseYarnLock returns nil for berry).
	if matcher.basename == "yarn.lock" && isYarnBerry(raw) {
		format = "yarn_berry"
	}

	// Drift hash over the capped bytes.  For every legitimate lockfile
	// (always well under maxLockfileBytes — see the const comment) this
	// is identical to a whole-file SHA256; oversized files were already
	// refused by readLockfile above, so the hash is never taken over a
	// truncated prefix.
	sum := sha256.Sum256(raw)

	count := declaredCountFromBytes(raw, matcher.basename)
	// Workspace Phase 5 §A — extract the .NET Target Framework Monikers a
	// project.assets.json declares, for server-side TFM EOL correlation.
	var tfms []string
	if matcher.basename == "project.assets.json" {
		tfms = targetFrameworksFromAssets(raw)
	}
	return deptree.LockfileMeta{
		Path:                  path,
		Format:                format,
		Ecosystem:             matcher.ecosystem,
		SHA256:                hex.EncodeToString(sum[:]),
		LastModified:          st.ModTime().UTC(),
		DeclaredPackagesCount: count,
		DriftStatus:           "unknown", // server stamps the real value during ingest
		TargetFrameworks:      tfms,
	}, nil
}

// targetFrameworksFromAssets pulls the short-form TFMs a project targets from a
// NuGet project.assets.json. The `project.frameworks` object is keyed by the
// short moniker (`net8.0`, `netstandard2.0`) — exactly what the server's
// tfm_map expects — so we return its sorted key set. Falls back to nil (never a
// partial guess) when the structure is absent or unparseable. Returns nil for
// an empty set so the omitempty JSON tag drops the field entirely.
func targetFrameworksFromAssets(raw []byte) []string {
	var p struct {
		Project struct {
			Frameworks map[string]json.RawMessage `json:"frameworks"`
		} `json:"project"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	if len(p.Project.Frameworks) == 0 {
		return nil
	}
	tfms := make([]string, 0, len(p.Project.Frameworks))
	for tfm := range p.Project.Frameworks {
		tfms = append(tfms, tfm)
	}
	sort.Strings(tfms)
	return tfms
}

// packageLockFormat inspects the lockfileVersion field of an npm
// package-lock.json (already read into raw) and maps it to the on-wire
// format enum.
//
// Returns ("", nil) for v1 (and any other unknown version): the v3
// contract enum lists only package_lock_v2 / package_lock_v3, and
// silently remapping v1 → v3 used to cause the downstream parser to
// emit warnings.  v1 is rare with npm 7+, so dropping it from the
// payload entirely is the least-noisy outcome.  Callers (buildMeta)
// translate the empty sentinel into errSkipLockfile.
func packageLockFormat(raw []byte) (string, error) {
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
		// v1 or unknown — drop intentionally.  See docstring.
		return "", nil
	}
}

// isYarnBerry reports whether a yarn.lock (already read into raw) uses
// the yarn v2+ ("berry") format, identified by a top-level
// `__metadata:` block that classic v1 lockfiles never contain.  Only
// the first yarnBerryProbeBytes bytes are inspected: the comment header
// plus the `__metadata:` line always sit at the very top of a berry
// lockfile, so a marker deeper in the file is ignored by design.
func isYarnBerry(raw []byte) bool {
	head := raw
	if len(head) > yarnBerryProbeBytes {
		head = head[:yarnBerryProbeBytes]
	}
	for _, line := range strings.Split(string(head), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "__metadata:") {
			return true
		}
	}
	return false
}

// declaredCountFromBytes is a quick heuristic per lockfile format,
// operating on the already-read bytes.  Returns 0 on parse failure
// rather than propagating an error — drift detection doesn't rely on
// this field's accuracy.
func declaredCountFromBytes(raw []byte, basename string) int {
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
