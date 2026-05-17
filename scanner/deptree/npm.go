package deptree

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

// ParseNpmPackageLock reads a package-lock.json (lockfileVersion 2 or 3)
// and emits dep-graph edges. v1 lockfiles return an error — they use a
// recursive shape this parser does not handle, and v7+ npm writes v2/v3.
//
// The dep type per edge follows the parent->child relationship encoded
// in the lockfile:
//   - dependencies         → "direct" when parent is root, else "transitive"
//   - devDependencies      → "dev"     (at root only; transitive devs are "transitive")
//   - peerDependencies     → "peer"
//   - optionalDependencies → "optional"
//
// IntroducedByPath is the full root→leaf chain inclusive of both
// endpoints (e.g. ["myapp", "express", "lodash"]).
func ParseNpmPackageLock(lockPath string) ([]DepEdge, error) {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", lockPath, err)
	}
	var lock npmPackageLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", lockPath, err)
	}
	if lock.LockfileVersion < 2 {
		return nil, fmt.Errorf("%s: lockfileVersion %d unsupported (need v2 or v3)", lockPath, lock.LockfileVersion)
	}
	if len(lock.Packages) == 0 {
		return nil, nil
	}

	// Root entry is always Packages[""].
	root, ok := lock.Packages[""]
	if !ok {
		return nil, fmt.Errorf("%s: missing root package entry", lockPath)
	}
	rootName := root.Name
	if rootName == "" {
		rootName = lock.Name
	}
	rootVersion := root.Version
	if rootVersion == "" {
		rootVersion = lock.Version
	}

	// Build a map from package-lock key (e.g. "node_modules/lodash" or
	// "node_modules/@scope/pkg") to the package name. Root key is "".
	keyToName := map[string]string{"": rootName}
	for key := range lock.Packages {
		if key == "" {
			continue
		}
		keyToName[key] = npmPackageNameFromKey(key)
	}

	// BFS from root to compute depth + introduced_by_path.
	type bfsItem struct {
		key   string
		path  []string
		depth int
	}
	depthByKey := map[string]int{"": 0}
	pathByKey := map[string][]string{"": {rootName}}
	queue := []bfsItem{{key: "", path: []string{rootName}, depth: 0}}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		entry := lock.Packages[head.key]
		for childSpec := range entry.Dependencies {
			childKey, childEntry, found := npmResolveChild(lock.Packages, head.key, childSpec)
			if !found {
				continue
			}
			if _, seen := depthByKey[childKey]; seen {
				continue
			}
			childPath := append([]string{}, head.path...)
			childPath = append(childPath, npmPackageNameFromKey(childKey))
			depthByKey[childKey] = head.depth + 1
			pathByKey[childKey] = childPath
			queue = append(queue, bfsItem{key: childKey, path: childPath, depth: head.depth + 1})
			_ = childEntry // marker to keep variable in scope for readability
		}
	}

	var edges []DepEdge
	for parentKey, parentEntry := range lock.Packages {
		parentName := keyToName[parentKey]
		parentVersion := parentEntry.Version
		if parentKey == "" {
			parentVersion = rootVersion
		}
		parentPath := pathByKey[parentKey]
		// Each of the 4 dependency maps becomes edges with the appropriate type.
		// At root, devDependencies → "dev", peerDeps → "peer", optionalDeps → "optional".
		// Below root, every edge is "transitive" regardless of how it was declared
		// (npm flattens; we lose the "was this dev?" semantics past depth 0).
		edges = appendEdges(edges, parentKey, parentName, parentVersion, parentPath, parentEntry.Dependencies, lock.Packages, keyToName, depthByKey, pathByKey, "direct")
		if parentKey == "" {
			edges = appendEdges(edges, parentKey, parentName, parentVersion, parentPath, parentEntry.DevDependencies, lock.Packages, keyToName, depthByKey, pathByKey, "dev")
			edges = appendEdges(edges, parentKey, parentName, parentVersion, parentPath, parentEntry.PeerDependencies, lock.Packages, keyToName, depthByKey, pathByKey, "peer")
			edges = appendEdges(edges, parentKey, parentName, parentVersion, parentPath, parentEntry.OptionalDependencies, lock.Packages, keyToName, depthByKey, pathByKey, "optional")
		}
	}
	return edges, nil
}

func appendEdges(
	edges []DepEdge,
	parentKey, parentName, parentVersion string,
	parentPath []string,
	deps map[string]string,
	packages map[string]npmPackageEntry,
	keyToName map[string]string,
	depthByKey map[string]int,
	pathByKey map[string][]string,
	atRootType string,
) []DepEdge {
	for childSpec := range deps {
		childKey, childEntry, found := npmResolveChild(packages, parentKey, childSpec)
		if !found {
			continue
		}
		childName := keyToName[childKey]
		childPath := pathByKey[childKey]
		if len(childPath) == 0 {
			// Shouldn't happen given BFS above, but defensively append.
			childPath = append([]string{}, parentPath...)
			childPath = append(childPath, childName)
		}
		edgeType := atRootType
		if parentKey != "" {
			edgeType = "transitive"
		}
		edges = append(edges, DepEdge{
			ParentName:       parentName,
			ParentVersion:    parentVersion,
			ChildName:        childName,
			ChildVersion:     childEntry.Version,
			Ecosystem:        "npm",
			Type:             edgeType,
			Scope:            "",
			Depth:            depthByKey[childKey],
			IntroducedByPath: childPath,
			Resolved:         true,
		})
	}
	return edges
}

// npmResolveChild walks the node_modules hoisting from a parent key
// upward until it finds a package entry for `name`. Returns the matched
// key+entry or (false) if no resolution exists in this lockfile.
//
// npm's hoisting model: when resolving "foo" from "node_modules/bar",
// npm checks "node_modules/bar/node_modules/foo" first, then walks up
// the ancestor chain. We replicate that walk against the packages map.
func npmResolveChild(packages map[string]npmPackageEntry, parentKey, childName string) (string, npmPackageEntry, bool) {
	// Search from the most-nested possible location to the root.
	base := parentKey
	for {
		candidate := joinNpmKey(base, childName)
		if entry, ok := packages[candidate]; ok {
			return candidate, entry, true
		}
		if base == "" {
			break
		}
		// Walk one ancestor up: strip the trailing "node_modules/<name>" segment.
		base = npmParentKey(base)
	}
	return "", npmPackageEntry{}, false
}

func joinNpmKey(parentKey, childName string) string {
	if parentKey == "" {
		return path.Join("node_modules", childName)
	}
	return path.Join(parentKey, "node_modules", childName)
}

// npmParentKey strips the trailing node_modules/<name> (or
// node_modules/@scope/name) segment from a packages-map key. Returns ""
// when there is no parent (key already at root nesting).
func npmParentKey(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx <= 0 {
		return ""
	}
	// Step back over the leading "node_modules/" plus the preceding "/".
	parent := strings.TrimSuffix(key[:idx], "/")
	return parent
}

// npmPackageNameFromKey extracts the package name from a key like
// "node_modules/lodash" → "lodash" or
// "node_modules/@types/node" → "@types/node" or
// "node_modules/express/node_modules/qs" → "qs".
func npmPackageNameFromKey(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return key
	}
	return key[idx+len("node_modules/"):]
}

type npmPackageLock struct {
	Name            string                     `json:"name"`
	Version         string                     `json:"version"`
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]npmPackageEntry `json:"packages"`
}

type npmPackageEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}
