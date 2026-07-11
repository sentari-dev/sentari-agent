package deptree

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
	"gopkg.in/yaml.v3"
)

// ParsePnpmLock reads pnpm-lock.yaml (lockfileVersion 5.x/6.x/9.x) and
// emits dep-graph edges. Like yarn, pnpm-lock alone doesn't fully
// distinguish direct vs transitive without the workspace's
// package.json, but pnpm-lock DOES carry an `importers` map keyed by
// workspace path with declared deps. We use that to identify directs.
//
// The dep graph is keyed on concrete (name, version) nodes — exactly as
// npm.go / npm_yarn.go do — so a package present at several versions
// stays several distinct nodes.  Keying the graph on the bare name (as
// an earlier revision did) collapsed multi-version packages
// last-write-wins, and which version survived depended on Go's
// non-deterministic map iteration order.
func ParsePnpmLock(lockPath string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(lockPath, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", lockPath, err)
	}
	var lock pnpmLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", lockPath, err)
	}

	// Root importer (single-workspace projects).
	rootImporter, ok := lock.Importers["."]
	if !ok {
		// Some pnpm-lock variants without workspaces lack an importers
		// block entirely — fall back to deriving directs from the lockfile
		// dependencies block at root level (older v5 format).
		if lock.Dependencies != nil || lock.DevDependencies != nil || lock.OptionalDependencies != nil {
			rootImporter = pnpmImporter{
				Dependencies:         lock.Dependencies,
				DevDependencies:      lock.DevDependencies,
				OptionalDependencies: lock.OptionalDependencies,
			}
		}
	}

	// Choose the source of per-package dependency lists.  pnpm >= 9
	// keeps them under `snapshots:`; the `packages:` block then holds
	// only resolution/engines metadata (empty deps).  Older v5/v6
	// lockfiles inline deps under `packages:` and have no `snapshots:`.
	// Prefer `snapshots:` whenever present so v9 transitive edges are
	// produced; fall back to `packages:` for the legacy layout.
	depSource := lock.Packages
	if len(lock.Snapshots) > 0 {
		depSource = lock.Snapshots
	}

	rootName := "(root)"
	rootVersion := ""

	// Concrete (name, version) node graph.  A package that appears at
	// two versions is two distinct nodes; nodeID concatenates the two so
	// BFS, depth, and path bookkeeping never collapse them.
	type node struct{ name, version string }
	nodeID := func(n node) string { return n.name + "@" + n.version }

	// adjacency: parent nodeID → ordered list of concrete child nodes.
	// nodesByID: parent nodeID → the parent node (name/version) so the
	// transitive emitter can recover its identity.  nameToVersion is a
	// last-resort fallback used only to resolve a root direct whose
	// importer entry omits the concrete version.
	adjacency := map[string][]node{}
	nodesByID := map[string]node{}
	nameToVersion := map[string]string{}

	// adjacencyByChild accumulates each concrete parent's child set, keyed on
	// the parent pid (name@version) and then on the child pid so duplicates are
	// deduped.  pnpm >= 9 emits the SAME name@version under several snapshot
	// keys that differ ONLY by peer context — foo@1.0.0(react@17.0.0) vs
	// foo@1.0.0(react@18.0.0) — each with its own resolved child set.
	// pnpmKeyParts strips the peer suffix, so all of them collapse to one pid.
	// We must therefore (1) iterate depSource in SORTED key order and (2) MERGE
	// (union) the child sets rather than overwrite, so the surviving adjacency
	// is the deterministic union of every peer-context snapshot instead of
	// whichever key won Go's non-deterministic map iteration.  Overwriting keyed
	// on the peer-stripped pid was the exact non-determinism the concrete-node
	// keying (see file header) set out to eliminate.
	adjacencyByChild := map[string]map[string]node{}
	depKeys := make([]string, 0, len(depSource))
	for key := range depSource {
		depKeys = append(depKeys, key)
	}
	sort.Strings(depKeys)
	for _, key := range depKeys {
		entry := depSource[key]
		name, version := pnpmKeyParts(key)
		if name == "" {
			continue
		}
		p := node{name: name, version: version}
		pid := nodeID(p)
		nodesByID[pid] = p
		nameToVersion[name] = version
		// The snapshot/package dependency VALUE carries the concrete
		// child version (e.g. `qs: 6.11.0`), possibly peer-decorated;
		// use it directly so each child edge points at the exact version
		// its parent resolved to.  Fold optionalDependencies in alongside
		// Dependencies so transitive optional deps (e.g. a pkg optionally
		// pulling fsevents) are not dropped; a runtime dep wins if a name
		// appears in both maps WITHIN this snapshot entry.
		childVersions := make(map[string]string, len(entry.Dependencies)+len(entry.OptionalDependencies))
		for cn, cv := range entry.OptionalDependencies {
			childVersions[cn] = cv
		}
		for cn, cv := range entry.Dependencies {
			childVersions[cn] = cv
		}
		childSet := adjacencyByChild[pid]
		if childSet == nil {
			childSet = map[string]node{}
			adjacencyByChild[pid] = childSet
		}
		// Union this snapshot key's children into the parent's merged set,
		// deduping on the child's concrete name@version.  Two peer contexts
		// that resolve a child to DIFFERENT versions keep both distinct child
		// nodes (lossless); two that resolve it to the SAME version collapse to
		// one entry.
		for cn, cv := range childVersions {
			ch := node{name: cn, version: pnpmDepVersion(cv)}
			childSet[nodeID(ch)] = ch
		}
	}
	// Materialise each parent's merged child set as a deterministically ordered
	// slice: by child name, then child version (so same-name/different-version
	// children from divergent peer contexts have a stable order).  This mirrors
	// the workspace-member child ordering below and makes ParsePnpmLock's edge
	// output byte-identical across repeated runs of the same lockfile.
	for pid, childSet := range adjacencyByChild {
		children := make([]node, 0, len(childSet))
		for _, ch := range childSet {
			children = append(children, ch)
		}
		sort.Slice(children, func(i, j int) bool {
			if children[i].name != children[j].name {
				return children[i].name < children[j].name
			}
			return children[i].version < children[j].version
		})
		adjacency[pid] = children
	}

	// resolveDirect maps a root-declared dep to a concrete node.  The
	// importer entry usually carries the resolved version; fall back to
	// the last-seen version for that name when it doesn't.
	resolveDirect := func(name string, v interface{}) node {
		ver := pnpmEntryVersion(v)
		if ver == "" {
			ver = nameToVersion[name]
		}
		return node{name: name, version: ver}
	}

	// Workspace members: a pnpm monorepo has one importer per member
	// (importers: {".":{...}, "packages/api":{express}, ...}).  The root
	// "." importer keeps its direct semantics below; every OTHER importer
	// is a workspace member whose declared deps + transitive closure would
	// be dropped if only "." were seeded.  Mirror npm.go's workspace-member
	// anchoring: create a synthetic depth-1 node per member (identity = the
	// importer key, e.g. "packages/api"), give it an adjacency built from
	// its declared dependencies + devDependencies + optionalDependencies,
	// and seed it into the BFS below at [root, member].  Its subtree then
	// gets correct root->member->...->child paths, and the member's own
	// deps surface at depth 2 as transitive (direct<=>depth1, so a depth-2
	// edge can never be "direct").
	memberKeys := make([]string, 0, len(lock.Importers))
	for key := range lock.Importers {
		if key == "." {
			continue
		}
		memberKeys = append(memberKeys, key)
	}
	sort.Strings(memberKeys)
	members := make([]node, 0, len(memberKeys))
	for _, key := range memberKeys {
		imp := lock.Importers[key]
		member := node{name: key, version: ""}
		mid := nodeID(member)
		nodesByID[mid] = member
		// Fold the member's three declared dep maps into one concrete-node
		// child list; a runtime dep wins if a name repeats across maps.
		childByID := map[string]node{}
		foldMemberDeps := func(deps map[string]interface{}) {
			for name, v := range deps {
				ch := resolveDirect(name, v)
				childByID[nodeID(ch)] = ch
			}
		}
		foldMemberDeps(imp.OptionalDependencies)
		foldMemberDeps(imp.DevDependencies)
		foldMemberDeps(imp.Dependencies)
		childIDs := make([]string, 0, len(childByID))
		for cid := range childByID {
			childIDs = append(childIDs, cid)
		}
		sort.Strings(childIDs)
		children := make([]node, 0, len(childIDs))
		for _, cid := range childIDs {
			children = append(children, childByID[cid])
		}
		adjacency[mid] = children
		members = append(members, member)
	}

	// BFS from the root importer over concrete nodes to compute depth +
	// introduced_by_path.  depthByNode / pathByNode are keyed on the
	// (name@version) node id so two versions of one package get separate
	// depths and paths.
	rootID := nodeID(node{name: rootName, version: rootVersion})
	depthByNode := map[string]int{rootID: 0}
	pathByNode := map[string][]string{rootID: {rootName}}
	type queueItem struct {
		n     node
		path  []string
		depth int
	}
	queue := []queueItem{}

	seed := func(deps map[string]interface{}) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			ch := resolveDirect(name, deps[name])
			id := nodeID(ch)
			if _, seen := depthByNode[id]; seen {
				continue
			}
			childPath := []string{rootName, ch.name}
			depthByNode[id] = 1
			pathByNode[id] = childPath
			queue = append(queue, queueItem{n: ch, path: childPath, depth: 1})
		}
	}
	seed(rootImporter.Dependencies)
	seed(rootImporter.DevDependencies)
	// Root optionalDependencies are declared directs too — seed them so
	// their subtrees are reachable in the BFS (mirrors the yarn/npm root
	// optionalDependencies handling). Without this, a package that appears
	// ONLY under the root importer's optionalDependencies (and its whole
	// subtree) is dropped.
	seed(rootImporter.OptionalDependencies)

	// Seed each workspace member as a depth-1 anchor at [root, member].
	// Seeded AFTER the root directs so a concrete node shared between the
	// root and a member stays root-anchored (first-seen wins in the BFS),
	// preserving the root's direct classification.
	for _, member := range members {
		mid := nodeID(member)
		if _, seen := depthByNode[mid]; seen {
			continue
		}
		memberPath := []string{rootName, member.name}
		depthByNode[mid] = 1
		pathByNode[mid] = memberPath
		queue = append(queue, queueItem{n: member, path: memberPath, depth: 1})
	}

	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		for _, child := range adjacency[nodeID(head.n)] {
			id := nodeID(child)
			if _, seen := depthByNode[id]; seen {
				continue
			}
			childPath := append([]string{}, head.path...)
			childPath = append(childPath, child.name)
			depthByNode[id] = head.depth + 1
			pathByNode[id] = childPath
			queue = append(queue, queueItem{n: child, path: childPath, depth: head.depth + 1})
		}
	}

	var edges []DepEdge

	// Root edges (directs + devs).  Emitted at depth 1 with the resolved
	// concrete child version, one per declared dep map.
	addRoot := func(deps map[string]interface{}, edgeType string) {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			ch := resolveDirect(name, deps[name])
			edges = append(edges, DepEdge{
				ParentName:       rootName,
				ParentVersion:    rootVersion,
				ChildName:        name,
				ChildVersion:     ch.version,
				Ecosystem:        "npm",
				Type:             edgeType,
				Scope:            "",
				Depth:            1,
				IntroducedByPath: []string{rootName, name},
				Resolved:         true,
			})
		}
	}
	addRoot(rootImporter.Dependencies, "direct")
	addRoot(rootImporter.DevDependencies, "dev")
	addRoot(rootImporter.OptionalDependencies, "optional")

	// Transitive edges from each concrete node's children.  The
	// path/depth is computed PER EDGE from the emitting parent's BFS
	// resolution path (path = parentPath + [child], depth = len(path)-1),
	// so a child with several parents gets a distinct parent-anchored
	// path on every edge.  A parent unreachable from the root importer is
	// dropped rather than emitted with a fabricated depth-0 path.  The
	// dedup axis is the emitting PARENT node (never re-emit the root
	// importer's own directs), mirroring npm.go's parent-keyed
	// classification — the correct axis, not "is the child a root direct".
	parentIDs := make([]string, 0, len(adjacency))
	for pid := range adjacency {
		parentIDs = append(parentIDs, pid)
	}
	sort.Strings(parentIDs)
	for _, pid := range parentIDs {
		parent := nodesByID[pid]
		if parent.name == rootName {
			continue // never re-emit the synthetic root importer's directs
		}
		parentPath, reached := pathByNode[pid]
		if !reached {
			continue // parent unreachable from root importer — drop
		}
		for _, child := range adjacency[pid] {
			childPath := append(append([]string{}, parentPath...), child.name)
			edges = append(edges, DepEdge{
				ParentName:       parent.name,
				ParentVersion:    parent.version,
				ChildName:        child.name,
				ChildVersion:     child.version,
				Ecosystem:        "npm",
				Type:             "transitive",
				Scope:            "",
				Depth:            len(childPath) - 1,
				IntroducedByPath: childPath,
				Resolved:         true,
			})
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentName != edges[j].ParentName {
			return edges[i].ParentName < edges[j].ParentName
		}
		if edges[i].ParentVersion != edges[j].ParentVersion {
			return edges[i].ParentVersion < edges[j].ParentVersion
		}
		if edges[i].ChildName != edges[j].ChildName {
			return edges[i].ChildName < edges[j].ChildName
		}
		return edges[i].ChildVersion < edges[j].ChildVersion
	})
	return edges, nil
}

// pnpmKeyParts splits a pnpm package key into (name, version) across all
// lockfile-version key shapes:
//
//	pnpm 9+ (no leading slash):  "foo@1.0.0"          → ("foo", "1.0.0")
//	pnpm 6/8 (leading slash):    "/foo@1.0.0"         → ("foo", "1.0.0")
//	pnpm 6/8 scoped:             "/@scope/foo@1.0.0"  → ("@scope/foo", "1.0.0")
//	pnpm 8+ peer-decorated:      "/foo@1.0.0(peer@2)" → ("foo", "1.0.0")
//	pnpm 5.x:                    "/express/4.18.2"    → ("express", "4.18.2")
//	pnpm 5.x scoped:             "/@scope/foo/1.0.0"  → ("@scope/foo", "1.0.0")
//	pnpm 5.x peer-decorated:     "/react-dom/16.13.1_react@16.13.1"
//	                                                  → ("react-dom", "16.13.1")
//
// pnpm encodes a package's peer-resolution context INTO the key. pnpm 8+
// appends it as a parenthesised "(react@16.13.1)" suffix; pnpm 5.x instead
// appends it after an UNDERSCORE ("/react-dom/16.13.1_react@16.13.1"). Both
// decorations carry the peer's own '@version', and both must be stripped
// before the version is read. Stripping only the '(' form left the 5.x
// underscore form intact, so LastIndex('@') landed on the PEER version's
// '@' and returned name="react-dom/16.13.1_react", version="16.13.1" — a
// bogus name that matched no adjacency entry, silently dropping every
// peer-decorated 5.x transitive edge.
//
// The name↔version SEPARATOR is what distinguishes the lockfile shapes:
// pnpm 6+/9 separate with '@' (a scope's leading '@' is not a separator);
// pnpm 5.x separate with '/'. We locate the first '/' or '@' AFTER any
// leading "@scope/" — that byte is the separator:
//
//   - '@' → pnpm 6+/9: the version is the remainder (the '(' peer suffix,
//     if any, was already trimmed above). A scoped name whose package part
//     starts with a digit (e.g. "@scope/2fa@1.0.0") still splits correctly
//     because the separator search begins past "@scope/".
//   - '/' → pnpm 5.x: the version is the remainder up to the first '_' —
//     the underscore peer-context separator. '_' is not a legal semver
//     character, so cutting there is safe; any '_' inside the package NAME
//     sits BEFORE the separator (e.g. "lodash._baseassign/4.0.0") and is
//     preserved untouched.
func pnpmKeyParts(key string) (string, string) {
	k := strings.TrimPrefix(key, "/")
	// Strip any "(...)" peer-dep suffix that pnpm 8+ appends.
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	// Find where the package NAME ends. A scope's leading "@scope/" is part
	// of the name, so begin the separator search past it.
	searchFrom := 0
	if strings.HasPrefix(k, "@") {
		slash := strings.IndexByte(k, '/')
		if slash < 0 {
			// Malformed scoped key with no separator — treat it all as name.
			return k, ""
		}
		searchFrom = slash + 1
	}
	sep := -1
	for i := searchFrom; i < len(k); i++ {
		if k[i] == '@' || k[i] == '/' {
			sep = i
			break
		}
	}
	if sep < 0 {
		// No separator: a bare name (e.g. malformed key) — no version.
		return k, ""
	}
	name := k[:sep]
	rest := k[sep+1:]
	if k[sep] == '/' {
		// pnpm 5.x: "version[_peer]".  Strip the peer context at the first
		// '_' (never a semver character, so this can't truncate a real
		// version).
		if u := strings.IndexByte(rest, '_'); u >= 0 {
			rest = rest[:u]
		}
	}
	return name, rest
}

// pnpmDepVersion cleans a per-package dependency VALUE (the concrete
// resolved child version) — e.g. "6.11.0" or, when pnpm decorates it
// with a peer-resolution context, "6.11.0(react@18.0.0)".  Strip at the
// first '(' so the child version is clean semver.
func pnpmDepVersion(v string) string {
	if i := strings.Index(v, "("); i > 0 {
		v = v[:i]
	}
	return v
}

// pnpmEntryVersion extracts the version from an importer dep value,
// which can be either a string "1.0.0" or an object {version: "1.0.0", specifier: "^1.0.0"}.
//
// pnpm >= 9 suffixes the resolved importer version with a peer-resolution
// context, e.g. "1.2.3(react@18.0.0)".  Strip it at the first '(' — the
// same rule pnpmKeyParts applies to package keys — so direct-dep
// child_version is clean semver, not a peer-decorated string.
func pnpmEntryVersion(v interface{}) string {
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case map[string]interface{}:
		vs, ok := t["version"].(string)
		if !ok {
			return ""
		}
		s = vs
	default:
		return ""
	}
	if i := strings.Index(s, "("); i > 0 {
		s = s[:i]
	}
	return s
}

type pnpmLock struct {
	LockfileVersion interface{}                 `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter     `yaml:"importers"`
	Packages        map[string]pnpmPackageEntry `yaml:"packages"`
	// pnpm >= 9 moved per-package dependency lists out of `packages:`
	// (which now carries only resolution/engines metadata) into a new
	// top-level `snapshots:` block keyed by name@version(peerctx).
	Snapshots map[string]pnpmPackageEntry `yaml:"snapshots"`
	// older v5 fields (when importers absent):
	Dependencies         map[string]interface{} `yaml:"dependencies"`
	DevDependencies      map[string]interface{} `yaml:"devDependencies"`
	OptionalDependencies map[string]interface{} `yaml:"optionalDependencies"`
}

type pnpmImporter struct {
	Dependencies         map[string]interface{} `yaml:"dependencies"`
	DevDependencies      map[string]interface{} `yaml:"devDependencies"`
	OptionalDependencies map[string]interface{} `yaml:"optionalDependencies"`
}

type pnpmPackageEntry struct {
	Dependencies    map[string]string `yaml:"dependencies"`
	DevDependencies map[string]string `yaml:"devDependencies"`
	// pnpm records a package's OPTIONAL transitive deps under
	// optionalDependencies in the snapshot (v9) / packages (v5-6) entry —
	// e.g. a package optionally pulling fsevents. Without reading this
	// field those optional-transitive edges (and their subtrees) are
	// dropped from the graph. The adjacency builder folds it into the
	// child list alongside Dependencies.
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}
