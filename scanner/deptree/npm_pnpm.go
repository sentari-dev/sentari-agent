package deptree

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParsePnpmLock reads pnpm-lock.yaml (lockfileVersion 5.x/6.x/9.x) and
// emits dep-graph edges. Like yarn, pnpm-lock alone doesn't fully
// distinguish direct vs transitive without the workspace's
// package.json, but pnpm-lock DOES carry an `importers` map keyed by
// workspace path with declared deps. We use that to identify directs.
func ParsePnpmLock(lockPath string) ([]DepEdge, error) {
	raw, err := os.ReadFile(lockPath)
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
		if lock.Dependencies != nil || lock.DevDependencies != nil {
			rootImporter = pnpmImporter{
				Dependencies:    lock.Dependencies,
				DevDependencies: lock.DevDependencies,
			}
		}
	}

	// Build map: package key (e.g. "/foo@1.0.0") → (name, version, deps).
	type pkgInfo struct {
		name    string
		version string
		deps    map[string]string
	}
	pkgsByKey := map[string]pkgInfo{}
	for key, entry := range lock.Packages {
		name, version := pnpmKeyParts(key)
		if name == "" {
			continue
		}
		pkgsByKey[key] = pkgInfo{
			name:    name,
			version: version,
			deps:    entry.Dependencies,
		}
	}

	rootName := "(root)"
	rootVersion := ""

	// Build adjacency: name → set of child names.
	depGraph := map[string]map[string]bool{}
	versionByName := map[string]string{}
	for _, info := range pkgsByKey {
		versionByName[info.name] = info.version
		if _, ok := depGraph[info.name]; !ok {
			depGraph[info.name] = map[string]bool{}
		}
		for childName := range info.deps {
			depGraph[info.name][childName] = true
		}
	}

	// BFS from root.
	type queueItem struct {
		name  string
		path  []string
		depth int
	}
	depthByName := map[string]int{rootName: 0}
	pathByName := map[string][]string{rootName: {rootName}}

	// Direct deps from importer.
	allDirects := map[string]struct{}{}
	for n := range rootImporter.Dependencies {
		allDirects[n] = struct{}{}
	}
	for n := range rootImporter.DevDependencies {
		allDirects[n] = struct{}{}
	}
	queue := []queueItem{}
	for n := range allDirects {
		depthByName[n] = 1
		pathByName[n] = []string{rootName, n}
		queue = append(queue, queueItem{name: n, path: pathByName[n], depth: 1})
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

	// Root edges (directs).
	for name, info := range rootImporter.Dependencies {
		v := pnpmEntryVersion(info)
		if v == "" {
			v = versionByName[name]
		}
		edges = append(edges, DepEdge{
			ParentName:       rootName,
			ParentVersion:    rootVersion,
			ChildName:        name,
			ChildVersion:     v,
			Ecosystem:        "npm",
			Type:             "direct",
			Scope:            "",
			Depth:            1,
			IntroducedByPath: []string{rootName, name},
			Resolved:         true,
		})
	}
	for name, info := range rootImporter.DevDependencies {
		v := pnpmEntryVersion(info)
		if v == "" {
			v = versionByName[name]
		}
		edges = append(edges, DepEdge{
			ParentName:       rootName,
			ParentVersion:    rootVersion,
			ChildName:        name,
			ChildVersion:     v,
			Ecosystem:        "npm",
			Type:             "dev",
			Scope:            "",
			Depth:            1,
			IntroducedByPath: []string{rootName, name},
			Resolved:         true,
		})
	}

	// Transitive edges from each package's deps map.
	for _, info := range pkgsByKey {
		for childName := range info.deps {
			if _, isDirect := allDirects[childName]; isDirect && depthByName[childName] == 1 {
				// already a direct from root; don't double-count.
				continue
			}
			childVer := versionByName[childName]
			edges = append(edges, DepEdge{
				ParentName:       info.name,
				ParentVersion:    info.version,
				ChildName:        childName,
				ChildVersion:     childVer,
				Ecosystem:        "npm",
				Type:             "transitive",
				Scope:            "",
				Depth:            depthByName[childName],
				IntroducedByPath: pathByName[childName],
				Resolved:         true,
			})
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].ParentName != edges[j].ParentName {
			return edges[i].ParentName < edges[j].ParentName
		}
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
}

// pnpmKeyParts splits "/foo@1.0.0" → ("foo", "1.0.0") or
// "/@scope/foo@1.0.0" → ("@scope/foo", "1.0.0"). pnpm 9+ uses
// "foo@1.0.0" (no leading slash) — handle both.
func pnpmKeyParts(key string) (string, string) {
	k := strings.TrimPrefix(key, "/")
	// Strip any "(...)" peer-dep suffix that pnpm 8+ appends.
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	// Last "@" splits name from version.
	idx := strings.LastIndex(k, "@")
	if idx <= 0 {
		return k, ""
	}
	return k[:idx], k[idx+1:]
}

// pnpmEntryVersion extracts the version from an importer dep value,
// which can be either a string "1.0.0" or an object {version: "1.0.0", specifier: "^1.0.0"}.
func pnpmEntryVersion(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]interface{}:
		if s, ok := t["version"].(string); ok {
			return s
		}
	}
	return ""
}

type pnpmLock struct {
	LockfileVersion interface{}                 `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter     `yaml:"importers"`
	Packages        map[string]pnpmPackageEntry `yaml:"packages"`
	// older v5 fields (when importers absent):
	Dependencies    map[string]interface{} `yaml:"dependencies"`
	DevDependencies map[string]interface{} `yaml:"devDependencies"`
}

type pnpmImporter struct {
	Dependencies    map[string]interface{} `yaml:"dependencies"`
	DevDependencies map[string]interface{} `yaml:"devDependencies"`
}

type pnpmPackageEntry struct {
	Dependencies    map[string]string `yaml:"dependencies"`
	DevDependencies map[string]string `yaml:"devDependencies"`
}
