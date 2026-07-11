package deptree

import (
	"bufio"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxLockfileBytes caps a single lockfile read across the deptree
// parsers.  Mirrors scanner/lockfiles: large monorepo lockfiles can be
// tens of megabytes, so 50 MiB is loose enough to never reject a
// legitimate lockfile and tight enough to refuse pathological inputs.
// All deptree reads route through safeio so a symlinked or oversize
// lockfile is refused before any byte reaches a parser.
const maxLockfileBytes = 50 << 20 // 50 MiB

// pypiSyntheticRoot is the sentinel parent used when a lockfile carries
// no real project package (poetry.lock) and one must be synthesized so
// every top-level dep is anchored to a single root. It matches the
// sentinel the other pypi emitters already use.
const pypiSyntheticRoot = "(unknown)"

// pypiPkgInfo is the per-package summary used internally by the PyPI
// graph builders. Names in the map keys are PEP 503-normalized.
type pypiPkgInfo struct {
	version string
	deps    []string
}

// pep503SepRe matches any run of the PEP 503 name separators (-, _, .).
var pep503SepRe = regexp.MustCompile(`[-_.]+`)

// normalizePyPIName applies PEP 503 name normalization: lowercase, then
// collapse every run of "-", "_", or "." into a single "-". This is what
// lets a requirements/lock name like "Typing_Extensions" join against a
// dist-info / dependency reference of "typing-extensions" — plain
// strings.ToLower left the underscore/hyphen/dot mismatch in place and
// silently broke the edge. deptree cannot import scanner.normalizePEP503
// (that lives in the separate `scanner` package), so this small helper
// mirrors it locally.
func normalizePyPIName(name string) string {
	return pep503SepRe.ReplaceAllString(strings.ToLower(name), "-")
}

// ParseUvLock reads uv.lock (TOML) and emits dep-graph edges.
// The file has [[package]] entries each with name, version, and an
// optional "dependencies" array of { name = "...", marker = "..." } tables.
//
// Root inference: anything not appearing in another package's
// dependencies is a root candidate. uv.lock typically has exactly one
// root (the project itself).
func ParseUvLock(path string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(path, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock uvLock
	if _, err := toml.Decode(string(raw), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	pkgs := map[string]pypiPkgInfo{}
	for _, p := range lock.Packages {
		name := normalizePyPIName(p.Name)
		var deps []string
		for _, d := range p.Dependencies {
			if d.Name != "" {
				deps = append(deps, normalizePyPIName(d.Name))
			}
		}
		pkgs[name] = pypiPkgInfo{version: p.Version, deps: deps}
	}

	allChildren := map[string]bool{}
	for _, info := range pkgs {
		for _, d := range info.deps {
			allChildren[d] = true
		}
	}
	roots := []string{}
	for name := range pkgs {
		if !allChildren[name] {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)
	if len(roots) == 0 {
		return nil, nil
	}
	rootName := pickPypiRoot(roots, path)
	rootVersion := pkgs[rootName].version

	return buildPypiEdges(pkgs, rootName, rootVersion), nil
}

// pickPypiRootDirMatch reports the candidate whose name matches the
// lockfile's containing directory name (case-insensitive, PEP 503
// normalized), identifying a genuine self-referential project root.
// The bool is false when no candidate matches the directory name.
func pickPypiRootDirMatch(roots []string, lockPath string) (string, bool) {
	dirName := strings.ToLower(filepath.Base(filepath.Dir(lockPath)))
	if dirName != "" && dirName != "." && dirName != string(filepath.Separator) {
		// roots carry PEP 503-normalized names, so normalize the directory
		// name the same way before comparing (e.g. dir "my_app" matches a
		// root normalized to "my-app").
		normDir := normalizePyPIName(dirName)
		for _, r := range roots {
			if r == normDir {
				return r, true
			}
		}
	}
	return "", false
}

// pickPypiRoot chooses the project root among several no-incoming-edge
// candidates.  Candidates are pre-sorted, so roots[0] is the
// deterministic alphabetical default.  When the lockfile's containing
// directory name matches one of the candidates (case-insensitive),
// that candidate is the real project root and wins the tie-break —
// e.g. /srv/myapp/uv.lock with candidates {aaa-lib, myapp} resolves to
// "myapp" rather than the alphabetically-first "aaa-lib".
func pickPypiRoot(roots []string, lockPath string) string {
	if r, ok := pickPypiRootDirMatch(roots, lockPath); ok {
		return r
	}
	return roots[0]
}

// ParsePoetryLock reads poetry.lock (TOML, similar to uv.lock).
// [[package]] entries have name, version, and dependencies (a table
// mapping dep-name → version-spec OR an inline table with version + extras).
func ParsePoetryLock(path string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(path, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock poetryLock
	if _, err := toml.Decode(string(raw), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	pkgs := map[string]pypiPkgInfo{}
	for _, p := range lock.Packages {
		name := normalizePyPIName(p.Name)
		var deps []string
		for depName := range p.Dependencies {
			deps = append(deps, normalizePyPIName(depName))
		}
		pkgs[name] = pypiPkgInfo{version: p.Version, deps: deps}
	}
	allChildren := map[string]bool{}
	for _, info := range pkgs {
		for _, d := range info.deps {
			allChildren[d] = true
		}
	}
	roots := []string{}
	for name := range pkgs {
		if !allChildren[name] {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)
	if len(roots) == 0 {
		// No no-incoming-edge candidate — the whole graph is a cycle, so
		// no root is derivable. Fall back to all-direct emission under an
		// unknown synthetic root.
		return buildPypiAllDirect(pkgs, pypiSyntheticRoot, ""), nil
	}
	// A poetry.lock (unlike uv.lock) does NOT contain the project package
	// itself: it lists only resolved deps, each carrying its own
	// [package.dependencies]. Therefore EVERY no-incoming-edge candidate is
	// a real top-level direct dep — not a set of rival roots to elect one
	// from. Electing a single root (the old behavior) silently dropped
	// every sibling top-level dep and its entire subtree.
	//
	// Exception: when the lockfile's directory name matches a candidate,
	// that candidate is a genuine self-referential project root (the
	// dir-name tie-break heuristic); BFS from it directly, preserving the
	// uv-style single-root semantics.
	if realRoot, ok := pickPypiRootDirMatch(roots, path); ok {
		return buildPypiEdges(pkgs, realRoot, pkgs[realRoot].version), nil
	}
	// Otherwise synthesize ONE virtual root whose direct children are ALL
	// the top-level candidates (depth 1), then let buildPypiEdges BFS each
	// subtree so transitives receive correct root-anchored depth>=2 paths.
	rootDeps := append([]string{}, roots...)
	sort.Strings(rootDeps)
	pkgs[pypiSyntheticRoot] = pypiPkgInfo{version: "", deps: rootDeps}
	return buildPypiEdges(pkgs, pypiSyntheticRoot, ""), nil
}

// ParsePipfileLock reads Pipfile.lock (JSON). All packages are treated
// as depth-1 edges from a synthetic root since Pipfile.lock doesn't
// carry per-dep parent info. "default" packages become Type="direct",
// "develop" packages become Type="dev".
func ParsePipfileLock(path string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(path, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock pipfileLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	rootName := "(unknown)"
	rootVersion := ""

	type srcKind struct {
		entries map[string]pipfilePackage
		kind    string
	}
	var edges []DepEdge
	for _, src := range []srcKind{{lock.Default, "direct"}, {lock.Develop, "dev"}} {
		names := make([]string, 0, len(src.entries))
		for n := range src.entries {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			info := src.entries[name]
			version := strings.TrimPrefix(info.Version, "==")
			edges = append(edges, DepEdge{
				ParentName:       rootName,
				ParentVersion:    rootVersion,
				ChildName:        name,
				ChildVersion:     version,
				Ecosystem:        "pypi",
				Type:             src.kind,
				Scope:            "",
				Depth:            1,
				IntroducedByPath: []string{rootName, name},
				Resolved:         true,
			})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Type != edges[j].Type {
			return edges[i].Type < edges[j].Type
		}
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
}

// requirementsLineRe matches a hand-written requirements.txt line per
// PEP 508 / PEP 440.  It captures:
//
//	[1] package name (with optional [extras])
//	[2] the version specifier — may be empty for bare-name lines
//
// Accepts:
//   - "requests==2.31.0"   (pinned)
//   - "requests===2.31.0"  (arbitrary equality — also pinned)
//   - "urllib3>=1.26"      (lower bound, NOT pinned)
//   - "urllib3~=1.26.0"    (compatible release, NOT pinned)
//   - "flask[async]>=2.0"  (extras stripped from name)
//   - "django"             (bare name, no version — NOT pinned)
//
// Inline environment markers (";  python_version>='3.8'") are stripped
// inside ParseRequirementsTxt below before this regex sees the line.
// Hash trailers (--hash=sha256:...) are not removed but are tolerated
// because the regex matches a prefix and ignores the trailer.  VCS /
// URL forms ("pkg @ git+https://...") match the name only — version
// stays empty.
//
// Whitespace between the name, the comparator, and the version is
// accepted (e.g. "requests == 2.31.0" or ">= 1.26") — PEP 440/508
// permit it and hand-written requirements files commonly use it.
var requirementsLineRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._\-]*(?:\[[^\]]*\])?)\s*((?:===|==|!=|~=|>=|<=|>|<)\s*[^;#\s]*)?`)

// maxRequirementsIncludeDepth bounds `-r`/`-c` include recursion so a
// self-referential or maliciously deep include chain cannot drive the
// parser into a runaway loop or stack blow-up.  Layered requirements
// layouts are shallow in practice (a root that pulls base/dev/test), so
// a cap of 8 — matching maxReactorDepth for the Maven reactor walk —
// leaves ample headroom while still terminating on abuse.  A visited-set
// additionally short-circuits cycles before the depth cap is reached.
const maxRequirementsIncludeDepth = 8

// ParseRequirementsTxt reads a requirements.txt and emits direct edges.
// `-r`/`--requirement` and `-c`/`--constraint` includes are followed
// (resolved relative to the including file's directory) and their edges
// are merged in, so a layered file that is just `-r requirements/base.txt`
// still yields the base file's dependencies.  Other option lines
// (`--hash=...`, `--index-url`, `-e`, …) are ignored, and remote `http(s)`
// include targets are skipped (the agent never fetches over the network
// for data).
//
// All PEP 440 specifiers are accepted. Pinned (`==` / `===`) edges
// carry a concrete version in ChildVersion. Range / compatible-release
// edges (`>=`, `~=`, `!=`, `<`, ...) and bare names cannot be resolved
// to a concrete version from requirements.txt alone, so ChildVersion is
// the empty string — the raw specifier is never stuffed into the
// version field (it is not a version). Resolved stays true for every
// pypi edge; the v3 contract reserves Resolved=false for Maven
// BOM-imported deps only.
//
// Extras (`pkg[async]`) are stripped from the emitted name; environment
// markers (`; python_version >= "3.8"`) are dropped from the line.
func ParseRequirementsTxt(path string) ([]DepEdge, error) {
	visited := map[string]bool{}
	edges, err := collectRequirementsEdges(path, visited, 0)
	if err != nil {
		return edges, err
	}
	// Sort once at the top level so merged-in include edges share the
	// single deterministic ChildName ordering the callers rely on.
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
}

// requirementIncludePath recognises a pip include directive
// (`-r`/`--requirement <file>` or `-c`/`--constraint <file>`, in both
// space- and `=`-separated forms) and returns the raw referenced path.
// Any other leading-`-` option line yields ("", false) so the caller
// keeps ignoring it.
func requirementIncludePath(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	opt := fields[0]
	var arg string
	if i := strings.IndexByte(opt, '='); i >= 0 {
		// `--requirement=base.txt` / `-r=base.txt` form.
		arg = opt[i+1:]
		opt = opt[:i]
	} else if len(fields) >= 2 {
		arg = fields[1]
	}
	switch opt {
	case "-r", "--requirement", "-c", "--constraint":
		arg = strings.Trim(strings.TrimSpace(arg), `"'`)
		if arg == "" {
			return "", false
		}
		return arg, true
	}
	return "", false
}

// collectRequirementsEdges parses one requirements file and recurses into
// its `-r`/`-c` includes, returning the UNSORTED union of all edges (the
// public ParseRequirementsTxt sorts once at the top).  visited is keyed
// by cleaned absolute path to break include cycles; depth is bounded by
// maxRequirementsIncludeDepth as a second, belt-and-braces guard.
func collectRequirementsEdges(path string, visited map[string]bool, depth int) ([]DepEdge, error) {
	if depth > maxRequirementsIncludeDepth {
		return nil, nil
	}
	// Canonicalise for the visited-set so the same file reached via two
	// different relative includes is only parsed once (safeio refuses
	// symlinks, so the cleaned abs path is a stable identity here).
	key := path
	if abs, aErr := filepath.Abs(path); aErr == nil {
		key = filepath.Clean(abs)
	}
	if visited[key] {
		return nil, nil
	}
	visited[key] = true

	f, err := safeio.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// safeio.Open refuses symlinks/non-regular files but does NOT cap
	// size — enforce the same maxLockfileBytes ceiling the buffered
	// parsers get, so an oversize requirements.txt is refused up front
	// (and is reported as safeio.ErrTooLarge for consistent handling).
	if st, sErr := f.Stat(); sErr == nil && st.Size() > maxLockfileBytes {
		return nil, fmt.Errorf("read %s: %w", path, safeio.ErrTooLarge)
	}

	rootName := "(unknown)"
	rootVersion := ""
	var edges []DepEdge
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		// Strip a leading UTF-8 BOM on the first line; otherwise the BOM
		// bytes prefix the first package name and the line is dropped.
		if first {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			// `-r`/`-c` includes are followed; every other option line
			// (--hash, --index-url, -e, ...) is ignored as before.
			inc, ok := requirementIncludePath(line)
			if !ok {
				continue
			}
			// Never fetch a remote include over the network — the agent
			// reads local files only (air-gap / no-telemetry charter).
			if strings.Contains(inc, "://") {
				continue
			}
			target := inc
			if !filepath.IsAbs(target) {
				// Resolve relative to the INCLUDING file's directory, per
				// pip semantics.
				target = filepath.Join(filepath.Dir(path), target)
			}
			// Best-effort: a missing/unreadable include (or one already
			// visited / past the depth cap) contributes no edges but does
			// not fail the whole parse.
			childEdges, cErr := collectRequirementsEdges(target, visited, depth+1)
			if cErr == nil {
				edges = append(edges, childEdges...)
			}
			continue
		}
		// Drop inline " #" comments.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Drop environment markers ("; python_version >= ...").
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		// Skip lines whose leading token is a direct URL or VCS reference
		// ("git+https://...", a bare "https://.../foo-1.0.tar.gz", etc.).
		// The name regex would otherwise capture the URL/VCS scheme token
		// ("git", "https") as a phantom package name. The leading-token
		// check (rather than "contains ://") preserves the documented
		// "pkg @ git+https://..." form, whose real name precedes the URL.
		firstTok := line
		if i := strings.IndexAny(firstTok, " \t"); i >= 0 {
			firstTok = firstTok[:i]
		}
		if strings.Contains(firstTok, "://") ||
			strings.HasPrefix(firstTok, "git+") ||
			strings.HasPrefix(firstTok, "hg+") ||
			strings.HasPrefix(firstTok, "svn+") ||
			strings.HasPrefix(firstTok, "bzr+") {
			continue
		}
		m := requirementsLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		nameWithExtras := m[1]
		spec := strings.TrimSpace(m[2])

		// Strip extras from the emitted name — "flask[async]" → "flask".
		emitName := nameWithExtras
		if i := strings.Index(emitName, "["); i >= 0 {
			emitName = emitName[:i]
		}

		// child_version carries a concrete version ONLY when the line is
		// pinned with "==" / "===".  Every other operator (>=, ~=, !=, <,
		// ...) and bare names cannot be resolved to a concrete version
		// from requirements.txt alone, so child_version is the empty
		// string — never a raw specifier.  Stuffing ">=1.26" into a
		// version field violates the v3 contract's child_version
		// semantics (it is a version string, not a constraint).
		var version string
		switch {
		case strings.HasPrefix(spec, "==="):
			version = strings.TrimSpace(strings.TrimPrefix(spec, "==="))
		case strings.HasPrefix(spec, "=="):
			version = strings.TrimSpace(strings.TrimPrefix(spec, "=="))
		default:
			version = ""
		}

		edges = append(edges, DepEdge{
			ParentName:       rootName,
			ParentVersion:    rootVersion,
			ChildName:        emitName,
			ChildVersion:     version,
			Ecosystem:        "pypi",
			Type:             "direct",
			Scope:            "",
			Depth:            1,
			IntroducedByPath: []string{rootName, emitName},
			// resolved=false is reserved by the v3 contract for Maven
			// BOM-imported deps; an unpinned pypi requirement is still a
			// discovered, resolved edge that merely lacks a concrete
			// pinned version, so resolved stays true.
			Resolved: true,
		})
	}
	if err := scanner.Err(); err != nil {
		return edges, err
	}
	// Unsorted on purpose — the public ParseRequirementsTxt sorts the
	// merged edge set (own + included) once, at the top level.
	return edges, nil
}

// buildPypiEdges runs BFS from rootName through the (name → deps) graph
// and emits edges per the standard direct/transitive convention.
//
// Each emitted edge carries a PER-EDGE introduced_by_path and depth:
// the path is the BFS resolution path to the emitting parent plus the
// child, and depth is len(path)-1.  A child with multiple parents thus
// gets a distinct, parent-anchored path (and depth) on each of its
// edges — the earlier version reused the child's single BFS depth/path
// on every edge, which broke the v3 invariant depth==len(path)-1 for
// all but one parent.  Parents that are unreachable from the chosen
// root (dev/optional subgraphs, multi-root leftovers, orphans) are
// dropped rather than emitted with a fabricated depth-0 / 2-element
// path.
// rootVersion is accepted for signature symmetry with buildPypiAllDirect
// but is intentionally unused here: parent_version for every emitted edge
// (root or not) is read from the pkgs map.
func buildPypiEdges(pkgs map[string]pypiPkgInfo, rootName, rootVersion string) []DepEdge {
	type queueItem struct {
		name string
		path []string
	}
	// pathByName holds ONE root→node resolution path per reachable node.
	// depth is always len(path)-1, so it is derived, never stored.
	pathByName := map[string][]string{rootName: {rootName}}
	queue := []queueItem{}

	// Direct deps from root, sorted for determinism.
	rootDeps := append([]string{}, pkgs[rootName].deps...)
	sort.Strings(rootDeps)
	for _, child := range rootDeps {
		if _, seen := pathByName[child]; seen {
			continue
		}
		pathByName[child] = []string{rootName, child}
		queue = append(queue, queueItem{name: child, path: pathByName[child]})
	}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		children := append([]string{}, pkgs[head.name].deps...)
		sort.Strings(children)
		for _, child := range children {
			if _, seen := pathByName[child]; seen {
				continue
			}
			childPath := append(append([]string{}, head.path...), child)
			pathByName[child] = childPath
			queue = append(queue, queueItem{name: child, path: childPath})
		}
	}

	// Emit edges deterministically by iterating sorted parent keys.
	parents := make([]string, 0, len(pkgs))
	for p := range pkgs {
		parents = append(parents, p)
	}
	sort.Strings(parents)
	var edges []DepEdge
	for _, parent := range parents {
		parentPath, reached := pathByName[parent]
		if !reached {
			continue // parent not reachable from root — drop its edges
		}
		info := pkgs[parent]
		children := append([]string{}, info.deps...)
		sort.Strings(children)
		for _, child := range children {
			edgeType := "transitive"
			if parent == rootName {
				edgeType = "direct"
			}
			childPath := append(append([]string{}, parentPath...), child)
			edges = append(edges, DepEdge{
				ParentName:       parent,
				ParentVersion:    info.version,
				ChildName:        child,
				ChildVersion:     pkgs[child].version,
				Ecosystem:        "pypi",
				Type:             edgeType,
				Scope:            "",
				Depth:            len(childPath) - 1,
				IntroducedByPath: childPath,
				Resolved:         true,
			})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Depth != edges[j].Depth {
			return edges[i].Depth < edges[j].Depth
		}
		if edges[i].ParentName != edges[j].ParentName {
			return edges[i].ParentName < edges[j].ParentName
		}
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges
}

func buildPypiAllDirect(pkgs map[string]pypiPkgInfo, rootName, rootVersion string) []DepEdge {
	names := make([]string, 0, len(pkgs))
	for n := range pkgs {
		names = append(names, n)
	}
	sort.Strings(names)
	var edges []DepEdge
	for _, name := range names {
		info := pkgs[name]
		edges = append(edges, DepEdge{
			ParentName:       rootName,
			ParentVersion:    rootVersion,
			ChildName:        name,
			ChildVersion:     info.version,
			Ecosystem:        "pypi",
			Type:             "direct",
			Scope:            "",
			Depth:            1,
			IntroducedByPath: []string{rootName, name},
			Resolved:         true,
		})
	}
	return edges
}

type uvLock struct {
	Packages []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name         string            `toml:"name"`
	Version      string            `toml:"version"`
	Dependencies []uvPackageDepRef `toml:"dependencies"`
}

type uvPackageDepRef struct {
	Name string `toml:"name"`
}

type poetryLock struct {
	Packages []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name         string                    `toml:"name"`
	Version      string                    `toml:"version"`
	Dependencies map[string]toml.Primitive `toml:"dependencies"`
}

type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}
