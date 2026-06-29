package deptree

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// ParseYarnLock reads yarn.lock v1 and a sibling package.json to emit
// dep-graph edges. The package.json supplies the "what's direct vs
// transitive" view that yarn.lock alone lacks.
//
// yarnLockPath: path to yarn.lock
// packageJsonPath: path to the project's package.json
//
// Returns (edges, nil) on success. If package.json is missing every
// edge is tagged "transitive" since direct/transitive can't be
// established.
func ParseYarnLock(yarnLockPath, packageJsonPath string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(yarnLockPath, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", yarnLockPath, err)
	}
	// Yarn v2+ ("berry") lockfiles open with a `__metadata:` block and
	// use a different schema the v1 parser below would misparse into
	// garbage edges.  Detect it (scan the first ~256 bytes) and bail
	// cleanly — berry dep-tree support is a separate piece of work.
	if isYarnBerry(raw) {
		return nil, nil
	}
	entries, err := parseYarnV1(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", yarnLockPath, err)
	}

	// Build a spec->version index keyed on the FULL yarn key
	// ("lodash@^4.17.21", "@types/node@^18.0.0") so a package that
	// appears at multiple versions resolves each dependency request to
	// the correct concrete version instead of collapsing to one
	// name-keyed node.  A single entry can carry several keys (multiple
	// requested ranges resolving to the same version), so every key maps
	// to that entry's resolved version.
	specToVersion := map[string]string{}
	// Fallback name->version for callers that only know a bare name
	// (e.g. package.json directs whose declared range we still match
	// against the full key below, but default to the last-seen version
	// if no key matches).
	nameToVersion := map[string]string{}
	for _, e := range entries {
		for _, k := range e.keys {
			name := yarnSpecName(k)
			if name == "" {
				continue
			}
			specToVersion[k] = e.version
			nameToVersion[name] = e.version
		}
	}

	// resolveSpec maps a (name, range) request to the concrete resolved
	// version by looking up the exact yarn key "name@range".  Falls back
	// to any version seen for that name when the precise key is absent
	// (defensive: a malformed lockfile may omit the exact requested key).
	resolveSpec := func(name, rng string) (string, bool) {
		if v, ok := specToVersion[name+"@"+rng]; ok {
			return v, true
		}
		if v, ok := nameToVersion[name]; ok {
			return v, true
		}
		return "", false
	}

	// Load package.json (optional). Missing → all edges transitive.
	var rootName, rootVersion string
	directDeps := map[string]string{}
	devDeps := map[string]string{}
	peerDeps := map[string]string{}
	optionalDeps := map[string]string{}
	if pjRaw, err := safeio.ReadFile(packageJsonPath, maxLockfileBytes); err == nil {
		var pj struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		}
		if err := json.Unmarshal(pjRaw, &pj); err == nil {
			rootName = pj.Name
			rootVersion = pj.Version
			directDeps = pj.Dependencies
			devDeps = pj.DevDependencies
			peerDeps = pj.PeerDependencies
			optionalDeps = pj.OptionalDependencies
		}
	}
	if rootName == "" {
		rootName = "(unknown)"
	}

	// Node identity is (name, version) — a package that appears at two
	// versions is two distinct nodes.  nodeID concatenates the two so the
	// BFS, depth, and path bookkeeping never collapse them.
	nodeID := func(name, version string) string { return name + "@" + version }

	// Build adjacency over concrete (name, version) nodes.  Each yarn
	// entry has ONE resolved version and a dependencies map of
	// (childName → range); resolve each range to a concrete child version
	// via the full yarn key so distinct versions stay distinct.
	type node struct{ name, version string }
	adjacency := map[string][]node{}
	for _, e := range entries {
		if len(e.keys) == 0 {
			continue
		}
		parent := node{name: yarnSpecName(e.keys[0]), version: e.version}
		if parent.name == "" {
			continue
		}
		pid := nodeID(parent.name, parent.version)
		for childName, childRange := range e.dependencies {
			cv, ok := resolveSpec(childName, childRange)
			if !ok {
				continue
			}
			adjacency[pid] = append(adjacency[pid], node{name: childName, version: cv})
		}
	}

	// BFS from the root over concrete nodes to compute depth +
	// introduced_by_path.  depthByNode / pathByNode are keyed on the
	// (name@version) node id so two versions of one package get separate
	// depths and paths.
	depthByNode := map[string]int{nodeID(rootName, rootVersion): 0}
	pathByNode := map[string][]string{nodeID(rootName, rootVersion): {rootName}}
	type queueItem struct {
		n     node
		path  []string
		depth int
	}
	queue := []queueItem{}

	// Resolve each root-declared dependency range to a concrete version.
	rootChildren := map[string]string{} // childName -> resolved version (for dedup vs transitive)
	seedRoot := func(name, rng string) (node, bool) {
		v, ok := resolveSpec(name, rng)
		if !ok {
			return node{}, false
		}
		return node{name: name, version: v}, true
	}
	for name, rng := range mergeMaps(directDeps, devDeps, peerDeps, optionalDeps) {
		ch, ok := seedRoot(name, rng)
		if !ok {
			continue
		}
		id := nodeID(ch.name, ch.version)
		if _, seen := depthByNode[id]; seen {
			continue
		}
		rootChildren[ch.name] = ch.version
		childPath := []string{rootName, ch.name}
		depthByNode[id] = 1
		pathByNode[id] = childPath
		queue = append(queue, queueItem{n: ch, path: childPath, depth: 1})
	}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		for _, child := range adjacency[nodeID(head.n.name, head.n.version)] {
			id := nodeID(child.name, child.version)
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

	// depthFor / pathFor look up a concrete node's BFS result, falling
	// back to depth 1 / [root,name] for nodes the BFS did not reach (an
	// orphan package not transitively reachable from the declared root).
	depthFor := func(name, version string) int {
		if d, ok := depthByNode[nodeID(name, version)]; ok {
			return d
		}
		return 1
	}
	pathFor := func(name, version string) []string {
		if p, ok := pathByNode[nodeID(name, version)]; ok {
			return p
		}
		return nil
	}

	var edges []DepEdge

	// Root edges, one per declared dep map, at the resolved version.
	addRoot := func(deps map[string]string, edgeType string) {
		for name, rng := range deps {
			v, ok := resolveSpec(name, rng)
			if !ok {
				continue
			}
			edges = append(edges, DepEdge{
				ParentName:       rootName,
				ParentVersion:    rootVersion,
				ChildName:        name,
				ChildVersion:     v,
				Ecosystem:        "npm",
				Type:             edgeType,
				Scope:            "",
				Depth:            depthFor(name, v),
				IntroducedByPath: SafePath(pathFor(name, v), rootName, name),
				Resolved:         true,
			})
		}
	}
	addRoot(directDeps, "direct")
	addRoot(devDeps, "dev")
	addRoot(peerDeps, "peer")
	addRoot(optionalDeps, "optional")

	// Transitive edges: every entry's dependencies map, resolved to
	// concrete child versions, EXCLUDING edges already emitted from the
	// root.  Keyed by (parent@version, child@version) so multi-version
	// packages keep every distinct edge.
	type edgeKey struct{ parent, child string }
	emitted := map[edgeKey]bool{}
	for _, e := range entries {
		if len(e.keys) == 0 {
			continue
		}
		parentName := yarnSpecName(e.keys[0])
		if parentName == "" || parentName == rootName {
			continue // root deps already covered above
		}
		parentVersion := e.version
		for childName, childRange := range e.dependencies {
			childVersion, ok := resolveSpec(childName, childRange)
			if !ok {
				continue
			}
			// Skip an edge identical to a depth-1 root direct (same child
			// AND same resolved version) to avoid double-counting.
			if rv, isRoot := rootChildren[childName]; isRoot && rv == childVersion && depthFor(childName, childVersion) == 1 {
				continue
			}
			ek := edgeKey{
				parent: nodeID(parentName, parentVersion),
				child:  nodeID(childName, childVersion),
			}
			if emitted[ek] {
				continue
			}
			emitted[ek] = true
			edges = append(edges, DepEdge{
				ParentName:       parentName,
				ParentVersion:    parentVersion,
				ChildName:        childName,
				ChildVersion:     childVersion,
				Ecosystem:        "npm",
				Type:             "transitive",
				Scope:            "",
				Depth:            depthFor(childName, childVersion),
				IntroducedByPath: SafePath(pathFor(childName, childVersion), parentName, childName),
				Resolved:         true,
			})
		}
	}

	// Sort for deterministic output: by parent, then child, then child
	// version (so two versions of one child order stably).
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentName != edges[j].ParentName {
			return edges[i].ParentName < edges[j].ParentName
		}
		if edges[i].ChildName != edges[j].ChildName {
			return edges[i].ChildName < edges[j].ChildName
		}
		return edges[i].ChildVersion < edges[j].ChildVersion
	})
	return edges, nil
}

// isYarnBerry reports whether raw is a yarn v2+ ("berry") lockfile,
// identified by a top-level `__metadata:` block within the first ~256
// bytes.  Classic v1 lockfiles never contain it.
func isYarnBerry(raw []byte) bool {
	head := raw
	if len(head) > 256 {
		head = head[:256]
	}
	for _, line := range strings.Split(string(head), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "__metadata:") {
			return true
		}
	}
	return false
}

// yarnSpecName extracts the package name from a yarn key like
// "lodash@^4.17.0" → "lodash", or "@types/node@^18.0.0" → "@types/node".
func yarnSpecName(key string) string {
	if strings.HasPrefix(key, "@") {
		idx := strings.Index(key[1:], "@")
		if idx < 0 {
			return ""
		}
		return key[:1+idx]
	}
	idx := strings.Index(key, "@")
	if idx < 0 {
		return key
	}
	return key[:idx]
}

func mergeMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

type yarnEntry struct {
	keys         []string
	version      string
	dependencies map[string]string
}

// parseYarnV1 is a small hand-rolled parser. Format reference:
// https://classic.yarnpkg.com/en/docs/yarn-lock
func parseYarnV1(content string) ([]yarnEntry, error) {
	var entries []yarnEntry
	var current *yarnEntry
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Section header: no leading whitespace and ends with ":".
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &yarnEntry{dependencies: map[string]string{}}
			inDeps = false
			header := strings.TrimSuffix(trimmed, ":")
			for _, part := range strings.Split(header, ",") {
				k := strings.TrimSpace(part)
				k = strings.Trim(k, "\"")
				if k != "" {
					current.keys = append(current.keys, k)
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent < 2 {
			continue
		}
		// "  version "1.2.3"" at indent 2.
		// "  dependencies:" at indent 2.
		// "    foo "1.0.0"" at indent 4 (inside dependencies).
		if indent == 2 {
			inDeps = false
			if strings.HasPrefix(trimmed, "version ") {
				current.version = strings.Trim(strings.TrimPrefix(trimmed, "version "), "\"")
			} else if trimmed == "dependencies:" {
				inDeps = true
			}
		} else if indent == 4 && inDeps {
			// "foo "1.0.0"" or "\"@scope/foo\" \"^1.0.0\""
			parts := strings.SplitN(trimmed, " ", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.Trim(parts[0], "\"")
			version := strings.Trim(parts[1], "\"")
			current.dependencies[name] = version
		}
	}
	if current != nil {
		entries = append(entries, *current)
	}
	return entries, scanner.Err()
}
