package deptree

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ParseNuGetProjectAssets reads a project.assets.json (always present
// after `dotnet restore`) and emits dep-graph edges per TFM. The TFM
// is recorded in the edge's Scope field (e.g. Scope="net6.0").
func ParseNuGetProjectAssets(path string) ([]DepEdge, error) {
	raw, err := os.ReadFile(path)
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
	for tfm, target := range assets.Targets {
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
				IntroducedByPath: pathByName[direct],
				Resolved:         true,
			})
		}
		// Emit transitive edges from the dep graph.
		parents := make([]string, 0, len(depGraph))
		for p := range depGraph {
			parents = append(parents, p)
		}
		sort.Strings(parents)
		for _, parent := range parents {
			children := depGraph[parent]
			childKeys := make([]string, 0, len(children))
			for c := range children {
				childKeys = append(childKeys, c)
			}
			sort.Strings(childKeys)
			for _, child := range childKeys {
				childVer := children[child]
				if _, isDirect := directs[child]; isDirect && depthByName[child] == 1 {
					continue
				}
				edges = append(edges, DepEdge{
					ParentName:       nameToOriginalCase[parent],
					ParentVersion:    nameToVersion[parent],
					ChildName:        nameToOriginalCase[child],
					ChildVersion:     childVer,
					Ecosystem:        "nuget",
					Type:             "transitive",
					Scope:            tfm,
					Depth:            depthByName[child],
					IntroducedByPath: pathByName[child],
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

// ParseNuGetPackagesLock is the fallback for projects that have
// packages.lock.json but no project.assets.json. The shape is simpler:
// per-framework "dependencies" map with explicit type=Direct|Transitive.
func ParseNuGetPackagesLock(path string) ([]DepEdge, error) {
	raw, err := os.ReadFile(path)
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
				// packages.lock.json doesn't carry per-dep parent info; we emit
				// transitives with parent="(unknown)" and depth=2.
				depth = 2
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
