package deptree

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// ParseNuGetProjectAssets reads a project.assets.json (always present
// after `dotnet restore`) and emits dep-graph edges per TFM. The TFM
// is recorded in the edge's Scope field (e.g. Scope="net6.0").
func ParseNuGetProjectAssets(path string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(path, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var assets nugetAssets
	if err := json.Unmarshal(raw, &assets); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	rootName := assets.Project.Restore.ProjectName
	if rootName == "" {
		rootName = "(unknown)"
	}
	rootVersion := assets.Project.Version

	var edges []DepEdge
	for targetKey, target := range assets.Targets {
		// `dotnet restore` keys `targets` by the LONG framework moniker
		// (".NETCoreApp,Version=v6.0", optionally with a "/<rid>" suffix)
		// while `project.frameworks` is keyed by the SHORT TFM ("net6.0").
		// Normalize before correlating so directs actually resolve — an
		// un-normalized lookup misses, leaving directs empty, which seeds
		// the BFS with nothing and drops every edge as unreachable.
		tfm := normalizeTFM(targetKey)

		// Build directs per TFM from project.frameworks[tfm].dependencies.
		directs := map[string]bool{}
		if fw, ok := assets.Project.Frameworks[tfm]; ok {
			for name := range fw.Dependencies {
				directs[strings.ToLower(name)] = true
			}
		}

		// Build a name→version map from target keys ("Name/Version").
		nameToVersion := map[string]string{}
		nameToOriginalCase := map[string]string{}
		for key, entry := range target {
			if entry.Type != "package" {
				continue
			}
			parts := strings.SplitN(key, "/", 2)
			if len(parts) != 2 {
				continue
			}
			origName := parts[0]
			lower := strings.ToLower(origName)
			nameToVersion[lower] = parts[1]
			nameToOriginalCase[lower] = origName
		}

		// Build adjacency: lowercased name → deps.
		depGraph := map[string]map[string]string{} // parent → {child → child version}
		for key, entry := range target {
			if entry.Type != "package" {
				continue
			}
			parts := strings.SplitN(key, "/", 2)
			if len(parts) != 2 {
				continue
			}
			parentLower := strings.ToLower(parts[0])
			children := map[string]string{}
			for childName := range entry.Dependencies {
				childLower := strings.ToLower(childName)
				if v, ok := nameToVersion[childLower]; ok {
					children[childLower] = v
				}
			}
			depGraph[parentLower] = children
		}

		// BFS from synthetic root to compute depth + introduced_by_path.
		type queueItem struct {
			name  string
			path  []string
			depth int
		}
		depthByName := map[string]int{strings.ToLower(rootName): 0}
		pathByName := map[string][]string{strings.ToLower(rootName): {rootName}}
		queue := []queueItem{}
		// Iterate directs in a deterministic order so BFS paths are stable.
		directKeys := make([]string, 0, len(directs))
		for d := range directs {
			directKeys = append(directKeys, d)
		}
		sort.Strings(directKeys)
		for _, direct := range directKeys {
			childPath := []string{rootName, nameToOriginalCase[direct]}
			depthByName[direct] = 1
			pathByName[direct] = childPath
			queue = append(queue, queueItem{name: direct, path: childPath, depth: 1})
		}
		for len(queue) > 0 {
			head := queue[0]
			queue = queue[1:]
			childKeys := make([]string, 0, len(depGraph[head.name]))
			for c := range depGraph[head.name] {
				childKeys = append(childKeys, c)
			}
			sort.Strings(childKeys)
			for _, child := range childKeys {
				if _, seen := depthByName[child]; seen {
					continue
				}
				childPath := append([]string{}, head.path...)
				childPath = append(childPath, nameToOriginalCase[child])
				depthByName[child] = head.depth + 1
				pathByName[child] = childPath
				queue = append(queue, queueItem{name: child, path: childPath, depth: head.depth + 1})
			}
		}

		// Emit direct edges.
		for _, direct := range directKeys {
			v, ok := nameToVersion[direct]
			if !ok {
				continue
			}
			edges = append(edges, DepEdge{
				ParentName:       rootName,
				ParentVersion:    rootVersion,
				ChildName:        nameToOriginalCase[direct],
				ChildVersion:     v,
				Ecosystem:        "nuget",
				Type:             "direct",
				Scope:            tfm,
				Depth:            1,
				IntroducedByPath: SafePath(pathByName[direct], rootName, nameToOriginalCase[direct]),
				Resolved:         true,
			})
		}
		// Emit transitive edges from the dep graph.  The path/depth is
		// computed PER EDGE from the emitting parent's BFS resolution path
		// (path = parentPath + [child], depth = len(path)-1), so a child
		// with several parents carries a distinct parent-anchored path on
		// each edge instead of the parent-agnostic per-child value the
		// earlier code reused.  A parent unreachable from the synthetic
		// root is dropped rather than emitted with a fabricated depth-0
		// path.  The old child-keyed skip ("child is a direct at depth 1")
		// wrongly dropped legitimate transitive edges into packages that
		// are also root directs; the synthetic root is never a parent in
		// depGraph, so no root→direct edge can be duplicated here and no
		// skip is needed.
		parents := make([]string, 0, len(depGraph))
		for p := range depGraph {
			parents = append(parents, p)
		}
		sort.Strings(parents)
		for _, parent := range parents {
			parentPath, reached := pathByName[parent]
			if !reached {
				continue // parent unreachable from root — drop its edges
			}
			children := depGraph[parent]
			childKeys := make([]string, 0, len(children))
			for c := range children {
				childKeys = append(childKeys, c)
			}
			sort.Strings(childKeys)
			for _, child := range childKeys {
				childVer := children[child]
				childPath := append(append([]string{}, parentPath...), nameToOriginalCase[child])
				edges = append(edges, DepEdge{
					ParentName:       nameToOriginalCase[parent],
					ParentVersion:    nameToVersion[parent],
					ChildName:        nameToOriginalCase[child],
					ChildVersion:     childVer,
					Ecosystem:        "nuget",
					Type:             "transitive",
					Scope:            tfm,
					Depth:            len(childPath) - 1,
					IntroducedByPath: childPath,
					Resolved:         true,
				})
			}
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Scope != edges[j].Scope {
			return edges[i].Scope < edges[j].Scope
		}
		if edges[i].Depth != edges[j].Depth {
			return edges[i].Depth < edges[j].Depth
		}
		if edges[i].ParentName != edges[j].ParentName {
			return edges[i].ParentName < edges[j].ParentName
		}
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
}

// normalizeTFM converts a project.assets.json `targets` key into the
// short target-framework moniker used as keys in `project.frameworks`.
// `dotnet restore` writes `targets` keyed by the LONG framework moniker
// (".NETCoreApp,Version=v6.0", ".NETFramework,Version=v4.7.2",
// ".NETStandard,Version=v2.0"), optionally with a "/<rid>" runtime
// identifier suffix (".NETCoreApp,Version=v6.0/win-x64"), whereas
// `project.frameworks` is keyed by the short TFM ("net6.0", "net472",
// "netstandard2.0"). Correlating targets→frameworks requires this
// normalization or the direct-dependency lookup silently misses.
//
// Mapping:
//   - ".NETCoreApp,Version=vX.Y"          -> "netX.Y"        (net6.0, net8.0)
//   - ".NETFramework,Version=vX.Y[.Z]"    -> "netXY[Z]"      (net472, net48)
//   - ".NETStandard,Version=vX.Y"         -> "netstandardX.Y"
//
// A key already in short form (or otherwise unrecognized) is returned
// unchanged, so short-keyed assets files keep working.
func normalizeTFM(targetKey string) string {
	// Strip any "/<rid>" runtime-identifier suffix first.
	if i := strings.IndexByte(targetKey, '/'); i >= 0 {
		targetKey = targetKey[:i]
	}
	const (
		coreAppPrefix   = ".NETCoreApp,Version=v"
		frameworkPrefix = ".NETFramework,Version=v"
		standardPrefix  = ".NETStandard,Version=v"
	)
	switch {
	case strings.HasPrefix(targetKey, coreAppPrefix):
		return "net" + strings.TrimPrefix(targetKey, coreAppPrefix)
	case strings.HasPrefix(targetKey, standardPrefix):
		return "netstandard" + strings.TrimPrefix(targetKey, standardPrefix)
	case strings.HasPrefix(targetKey, frameworkPrefix):
		v := strings.TrimPrefix(targetKey, frameworkPrefix)
		return "net" + strings.ReplaceAll(v, ".", "")
	default:
		return targetKey
	}
}

// ParseNuGetPackagesLock is the fallback for projects that have
// packages.lock.json but no project.assets.json. The shape is simpler:
// per-framework "dependencies" map with explicit type=Direct|Transitive.
func ParseNuGetPackagesLock(path string) ([]DepEdge, error) {
	raw, err := safeio.ReadFile(path, maxLockfileBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock nugetPackagesLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	rootName := "(unknown)"
	rootVersion := ""
	var edges []DepEdge
	for tfm, deps := range lock.Dependencies {
		// Iterate deterministically.
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			entry := deps[name]
			depth := 1
			edgeType := "transitive"
			parent := rootName
			parentVer := rootVersion
			if strings.EqualFold(entry.Type, "Direct") {
				edgeType = "direct"
			} else {
				// packages.lock.json doesn't carry per-dep parent info, so
				// the real depth is unknown.  We model transitives as
				// children of the synthetic "(unknown)" root with a
				// 2-element introduced_by_path; that path length implies
				// depth 1, so keep depth==len(path)-1==1 (self-consistent
				// rather than the previous depth=2 with a length-2 path).
				parent = "(unknown)"
			}
			edges = append(edges, DepEdge{
				ParentName:       parent,
				ParentVersion:    parentVer,
				ChildName:        name,
				ChildVersion:     entry.Resolved,
				Ecosystem:        "nuget",
				Type:             edgeType,
				Scope:            tfm,
				Depth:            depth,
				IntroducedByPath: []string{rootName, name},
				Resolved:         true,
			})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Scope != edges[j].Scope {
			return edges[i].Scope < edges[j].Scope
		}
		if edges[i].Depth != edges[j].Depth {
			return edges[i].Depth < edges[j].Depth
		}
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
}

type nugetAssets struct {
	Version int                                    `json:"version"`
	Targets map[string]map[string]nugetTargetEntry `json:"targets"`
	Project nugetProjectBlock                      `json:"project"`
}

type nugetTargetEntry struct {
	Type         string            `json:"type"`
	Dependencies map[string]string `json:"dependencies"`
}

type nugetProjectBlock struct {
	Version    string                         `json:"version"`
	Frameworks map[string]nugetFrameworkBlock `json:"frameworks"`
	Restore    nugetRestoreBlock              `json:"restore"`
}

type nugetFrameworkBlock struct {
	Dependencies map[string]nugetFrameworkDep `json:"dependencies"`
}

type nugetFrameworkDep struct {
	Version string `json:"version"`
}

type nugetRestoreBlock struct {
	ProjectName string `json:"projectName"`
}

type nugetPackagesLock struct {
	Version      int                                  `json:"version"`
	Dependencies map[string]map[string]nugetLockEntry `json:"dependencies"`
}

type nugetLockEntry struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}
