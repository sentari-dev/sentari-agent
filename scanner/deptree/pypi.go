package deptree

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// pypiPkgInfo is the per-package summary used internally by the PyPI
// graph builders. Names in the map keys are lowercased.
type pypiPkgInfo struct {
	version string
	deps    []string
}

// ParseUvLock reads uv.lock (TOML) and emits dep-graph edges.
// The file has [[package]] entries each with name, version, and an
// optional "dependencies" array of { name = "...", marker = "..." } tables.
//
// Root inference: anything not appearing in another package's
// dependencies is a root candidate. uv.lock typically has exactly one
// root (the project itself).
func ParseUvLock(path string) ([]DepEdge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock uvLock
	if _, err := toml.Decode(string(raw), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	pkgs := map[string]pypiPkgInfo{}
	for _, p := range lock.Packages {
		name := strings.ToLower(p.Name)
		var deps []string
		for _, d := range p.Dependencies {
			if d.Name != "" {
				deps = append(deps, strings.ToLower(d.Name))
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
	rootName := roots[0]
	rootVersion := pkgs[rootName].version

	return buildPypiEdges(pkgs, rootName, rootVersion), nil
}

// ParsePoetryLock reads poetry.lock (TOML, similar to uv.lock).
// [[package]] entries have name, version, and dependencies (a table
// mapping dep-name → version-spec OR an inline table with version + extras).
func ParsePoetryLock(path string) ([]DepEdge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock poetryLock
	if _, err := toml.Decode(string(raw), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	pkgs := map[string]pypiPkgInfo{}
	for _, p := range lock.Packages {
		name := strings.ToLower(p.Name)
		var deps []string
		for depName := range p.Dependencies {
			deps = append(deps, strings.ToLower(depName))
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
		// poetry.lock typically does NOT contain the project itself.
		// Fall back to all-direct emission with an unknown synthetic root.
		return buildPypiAllDirect(pkgs, "(unknown)", ""), nil
	}
	rootName := roots[0]
	rootVersion := pkgs[rootName].version
	return buildPypiEdges(pkgs, rootName, rootVersion), nil
}

// ParsePipfileLock reads Pipfile.lock (JSON). All packages are treated
// as depth-1 edges from a synthetic root since Pipfile.lock doesn't
// carry per-dep parent info. "default" packages become Type="direct",
// "develop" packages become Type="dev".
func ParsePipfileLock(path string) ([]DepEdge, error) {
	raw, err := os.ReadFile(path)
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

// ParseRequirementsTxt reads a requirements.txt and emits direct edges
// only. Hash pins (--hash=...) and includes (-r other.txt) are ignored.
func ParseRequirementsTxt(path string) ([]DepEdge, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	rootName := "(unknown)"
	rootVersion := ""
	specRe := regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)`)
	var edges []DepEdge
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Drop inline " #" comments.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		m := specRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		edges = append(edges, DepEdge{
			ParentName:       rootName,
			ParentVersion:    rootVersion,
			ChildName:        m[1],
			ChildVersion:     m[2],
			Ecosystem:        "pypi",
			Type:             "direct",
			Scope:            "",
			Depth:            1,
			IntroducedByPath: []string{rootName, m[1]},
			Resolved:         true,
		})
	}
	if err := scanner.Err(); err != nil {
		return edges, err
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ChildName < edges[j].ChildName
	})
	return edges, nil
}

// buildPypiEdges runs BFS from rootName through the (name → deps) graph
// and emits edges per the standard direct/transitive convention.
func buildPypiEdges(pkgs map[string]pypiPkgInfo, rootName, rootVersion string) []DepEdge {
	_ = rootVersion // parent_version for non-root parents comes from pkgs map
	type queueItem struct {
		name  string
		path  []string
		depth int
	}
	depthByName := map[string]int{rootName: 0}
	pathByName := map[string][]string{rootName: {rootName}}
	queue := []queueItem{}

	// Direct deps from root, sorted for determinism.
	rootDeps := append([]string{}, pkgs[rootName].deps...)
	sort.Strings(rootDeps)
	for _, child := range rootDeps {
		if _, seen := depthByName[child]; seen {
			continue
		}
		depthByName[child] = 1
		pathByName[child] = []string{rootName, child}
		queue = append(queue, queueItem{name: child, path: pathByName[child], depth: 1})
	}
	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		children := append([]string{}, pkgs[head.name].deps...)
		sort.Strings(children)
		for _, child := range children {
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

	// Emit edges deterministically by iterating sorted parent keys.
	parents := make([]string, 0, len(pkgs))
	for p := range pkgs {
		parents = append(parents, p)
	}
	sort.Strings(parents)
	var edges []DepEdge
	for _, parent := range parents {
		info := pkgs[parent]
		children := append([]string{}, info.deps...)
		sort.Strings(children)
		for _, child := range children {
			edgeType := "transitive"
			if parent == rootName {
				edgeType = "direct"
			}
			edges = append(edges, DepEdge{
				ParentName:       parent,
				ParentVersion:    info.version,
				ChildName:        child,
				ChildVersion:     pkgs[child].version,
				Ecosystem:        "pypi",
				Type:             edgeType,
				Scope:            "",
				Depth:            depthByName[child],
				IntroducedByPath: pathByName[child],
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
