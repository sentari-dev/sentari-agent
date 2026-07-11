package deptree

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
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
	raw, err := safeio.ReadFile(lockPath, maxLockfileBytes)
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
	// Workspace-member keys are local filesystem paths (e.g.
	// "packages/liba") that are NOT package names — for those the entry's
	// own "name" field is used (see npmEntryName), so a key like
	// "packages/liba" never leaks onto the wire as a parent/child name.
	keyToName := map[string]string{"": rootName}
	for key, entry := range lock.Packages {
		if key == "" {
			continue
		}
		keyToName[key] = npmEntryName(key, entry)
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

	// Seed the BFS with workspace-member entries as additional depth-1
	// roots. In an npm workspaces lockfile the members live under local
	// filesystem keys (e.g. "packages/liba") that carry their own "name"
	// field and are NOT reachable from the root "" via node_modules
	// resolution — their dependency subtrees would otherwise be
	// BFS-unreachable and (pre-fix) shipped as fabricated depth-0 edges
	// with a 2-element path, violating depth==len(path)-1 and the
	// root-anchored-path invariant. Anchoring each member at
	// [root, member] (depth 1) gives its whole subtree a real
	// root→member→… path. Members mirror Maven reactor modules; their own
	// direct deps then surface as transitive (depth>=2) like every other
	// sub-root npm edge.
	for key, entry := range lock.Packages {
		if key == "" || strings.Contains(key, "node_modules/") {
			continue
		}
		name := entry.Name
		if name == "" {
			continue
		}
		memberPath := []string{rootName, name}
		depthByKey[key] = 1
		pathByKey[key] = memberPath
		queue = append(queue, bfsItem{key: key, path: memberPath, depth: 1})
	}

	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		entry := lock.Packages[head.key]
		// Walk the same parent->child relationships appendEdges emits:
		// runtime deps everywhere, plus dev/peer/optional at root. Without
		// the root extras, the entire dev/peer/optional subtree would be
		// BFS-unreachable and its edges would fall back to sub-2-element
		// introduced_by_path values, violating the contract's minItems=2.
		depMaps := []map[string]string{entry.Dependencies}
		if head.key == "" {
			depMaps = append(depMaps, entry.DevDependencies, entry.PeerDependencies, entry.OptionalDependencies)
		}
		for _, deps := range depMaps {
			for childSpec := range deps {
				childKey, _, found := npmResolveChild(lock.Packages, head.key, childSpec)
				if !found {
					continue
				}
				if _, seen := depthByKey[childKey]; seen {
					continue
				}
				childPath := append([]string{}, head.path...)
				childPath = append(childPath, keyToName[childKey])
				depthByKey[childKey] = head.depth + 1
				pathByKey[childKey] = childPath
				queue = append(queue, bfsItem{key: childKey, path: childPath, depth: head.depth + 1})
			}
		}
	}

	var edges []DepEdge
	for parentKey, parentEntry := range lock.Packages {
		if _, reached := pathByKey[parentKey]; !reached {
			// Parent not reachable from the root project (extraneous
			// install, orphaned entry, a workspace member with no "name").
			// Drop all its edges — the same convention pypi/pnpm/nuget
			// follow — instead of fabricating a depth-0, 2-element path
			// that violates depth==len(path)-1 and the root-anchored-path
			// invariant.
			continue
		}
		parentName := keyToName[parentKey]
		parentVersion := parentEntry.Version
		if parentKey == "" {
			parentVersion = rootVersion
		}
		// Each of the 4 dependency maps becomes edges with the appropriate type.
		// At root, devDependencies → "dev", peerDeps → "peer", optionalDeps → "optional".
		// Below root, every edge is "transitive" regardless of how it was declared
		// (npm flattens; we lose the "was this dev?" semantics past depth 0).
		edges = appendEdges(edges, parentKey, parentName, parentVersion, parentEntry.Dependencies, lock.Packages, keyToName, depthByKey, pathByKey, "direct")
		if parentKey == "" {
			edges = appendEdges(edges, parentKey, parentName, parentVersion, parentEntry.DevDependencies, lock.Packages, keyToName, depthByKey, pathByKey, "dev")
			edges = appendEdges(edges, parentKey, parentName, parentVersion, parentEntry.PeerDependencies, lock.Packages, keyToName, depthByKey, pathByKey, "peer")
			edges = appendEdges(edges, parentKey, parentName, parentVersion, parentEntry.OptionalDependencies, lock.Packages, keyToName, depthByKey, pathByKey, "optional")
		}
	}
	return edges, nil
}

func appendEdges(
	edges []DepEdge,
	parentKey, parentName, parentVersion string,
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
		childPath, reached := pathByKey[childKey]
		if !reached {
			// Child not reachable from the root project — drop the edge
			// rather than fabricate a depth-0 path (mirrors the parent
			// drop in the emission loop above).
			continue
		}
		childName := keyToName[childKey]
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
			IntroducedByPath: SafePath(childPath, parentName, childName),
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

// npmEntryName resolves the package name for a packages-map key.
//
// For installed-dependency keys (those containing a node_modules/
// segment) the trailing segment after the last node_modules/ is the
// name. For workspace-member keys — local filesystem paths like
// "packages/liba" with no node_modules/ segment — the key is NOT a
// package name, so the entry's own "name" field is preferred; the raw
// key is only a last-resort fallback when the entry omits its name.
// This stops workspace lockfile keys ("packages/liba") from leaking
// onto the wire as parent_name/child_name/path entries.
func npmEntryName(key string, entry npmPackageEntry) string {
	if strings.Contains(key, "node_modules/") {
		return npmPackageNameFromKey(key)
	}
	if entry.Name != "" {
		return entry.Name
	}
	return npmPackageNameFromKey(key)
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
