package deptree

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
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
	raw, err := os.ReadFile(yarnLockPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", yarnLockPath, err)
	}
	entries, err := parseYarnV1(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", yarnLockPath, err)
	}

	// Build name->version map (using the resolved version per entry).
	// Yarn keys can be like "lodash@^4.17.0" or "@types/node@^18.0.0".
	// One package can have multiple keys with the same resolved version.
	nameToVersion := map[string]string{}
	for _, e := range entries {
		for _, k := range e.keys {
			name := yarnSpecName(k)
			if name == "" {
				continue
			}
			nameToVersion[name] = e.version
		}
	}

	// Load package.json (optional). Missing → all edges transitive.
	var rootName, rootVersion string
	directDeps := map[string]string{}
	devDeps := map[string]string{}
	peerDeps := map[string]string{}
	optionalDeps := map[string]string{}
	if pjRaw, err := os.ReadFile(packageJsonPath); err == nil {
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

	// BFS from root to compute depth + introduced_by_path.
	// Build an adjacency from each yarn entry's dependencies map.
	depGraph := map[string]map[string]bool{}
	for _, e := range entries {
		for _, k := range e.keys {
			name := yarnSpecName(k)
			if name == "" {
				continue
			}
			if _, ok := depGraph[name]; !ok {
				depGraph[name] = map[string]bool{}
			}
			for childSpec := range e.dependencies {
				childName := childSpec // dependencies map keys are bare names
				depGraph[name][childName] = true
			}
		}
	}

	depthByName := map[string]int{rootName: 0}
	pathByName := map[string][]string{rootName: {rootName}}
	// Seed with root's directs + dev/peer/optional. All count for BFS distance.
	type queueItem struct {
		name  string
		path  []string
		depth int
	}
	queue := []queueItem{}
	for child := range mergeMaps(directDeps, devDeps, peerDeps, optionalDeps) {
		childPath := []string{rootName, child}
		depthByName[child] = 1
		pathByName[child] = childPath
		queue = append(queue, queueItem{name: child, path: childPath, depth: 1})
	}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		for child := range depGraph[head.name] {
			if _, seen := depthByName[child]; seen {
				continue
			}
			childPath := append([]string{}, head.path...)
			childPath = append(childPath, child)
			depthByName[child] = head.depth + 1
			pathByName[child] = childPath
			queue = append(queue, queueItem{name: child, path: childPath, depth: head.depth + 1})
		}
	}

	var edges []DepEdge

	// Root edges, one per declared dep map.
	addRoot := func(deps map[string]string, edgeType string) {
		for name := range deps {
			v, ok := nameToVersion[name]
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
				Depth:            depthByName[name],
				IntroducedByPath: pathByName[name],
				Resolved:         true,
			})
		}
	}
	addRoot(directDeps, "direct")
	addRoot(devDeps, "dev")
	addRoot(peerDeps, "peer")
	addRoot(optionalDeps, "optional")

	// Transitive edges: every entry's dependencies map, EXCLUDING edges
	// already emitted from the root.
	rootChildren := mergeMaps(directDeps, devDeps, peerDeps, optionalDeps)
	for _, e := range entries {
		// Use canonical parent name = the first key's bare name.
		if len(e.keys) == 0 {
			continue
		}
		parentName := yarnSpecName(e.keys[0])
		if parentName == "" {
			continue
		}
		parentVersion := e.version
		for childName := range e.dependencies {
			if parentName == rootName {
				continue // already covered by root section
			}
			if _, isRootDirect := rootChildren[childName]; isRootDirect && depthByName[childName] == 1 {
				// child is already a direct of root with depth 1 — skip to
				// avoid double-counting the same edge.
				continue
			}
			childVersion, ok := nameToVersion[childName]
			if !ok {
				continue
			}
			edges = append(edges, DepEdge{
				ParentName:       parentName,
				ParentVersion:    parentVersion,
				ChildName:        childName,
				ChildVersion:     childVersion,
				Ecosystem:        "npm",
				Type:             "transitive",
				Scope:            "",
				Depth:            depthByName[childName],
				IntroducedByPath: pathByName[childName],
				Resolved:         true,
			})
		}
	}

	// Sort for deterministic output.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentName != edges[j].ParentName {
			return edges[i].ParentName < edges[j].ParentName
		}
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
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
