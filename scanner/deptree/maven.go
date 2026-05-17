// Package deptree (Maven flavor).
//
// Best-effort 90% dep-tree resolver for Maven projects. Reads pom.xml
// for the project's directs, then walks ~/.m2/repository to recurse
// transitively. Out-of-scope (Phase 4):
//   - BOM imports via <dependencyManagement> with <scope>import</scope>;
//     these are emitted with Resolved=false.
//   - <parent> POM resolution and property interpolation beyond simple
//     ${project.version} → root version.
//   - Profiles, activation conditions.
//   - Version range resolution.
package deptree

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ParseMavenPom reads a pom.xml + recurses through ~/.m2 to emit dep
// edges. m2Dir is the absolute path to a Maven local repository root
// (typically ~/.m2/repository).
func ParseMavenPom(pomPath, m2Dir string) ([]DepEdge, error) {
	raw, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pomPath, err)
	}
	var root mavenPom
	if err := xml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", pomPath, err)
	}

	rootGA := mavenGA{groupId: root.GroupID, artifactId: root.ArtifactID}
	rootVersion := root.Version

	// Interpolate ${project.version} → rootVersion in declared deps.
	interpolate := func(v string) string {
		if v == "${project.version}" {
			return rootVersion
		}
		return v
	}

	// Track edges + path metadata.
	type pendingDep struct {
		parent     mavenGA
		parentVer  string
		parentPath []string
		dep        mavenDep
	}
	// Resolved version per (groupId,artifactId), populated as BFS proceeds.
	// Nearest-wins mediation: the FIRST time we resolve a GA wins.
	resolved := map[mavenGA]string{}
	// Path to each resolved GA for introduced_by_path computation.
	pathByGA := map[mavenGA][]string{}
	depthByGA := map[mavenGA]int{}

	var edges []DepEdge

	// Helper to emit an edge.
	emit := func(parentName, parentVersion, childName, childVersion, scope, edgeType string, depth int, path []string, resolvedFlag bool) {
		edges = append(edges, DepEdge{
			ParentName:       parentName,
			ParentVersion:    parentVersion,
			ChildName:        childName,
			ChildVersion:     childVersion,
			Ecosystem:        "maven",
			Type:             edgeType,
			Scope:            scope,
			Depth:            depth,
			IntroducedByPath: path,
			Resolved:         resolvedFlag,
		})
	}

	// Convert root's name to "groupId:artifactId" for use as the path
	// root identifier.
	rootCoord := mavenCoord(rootGA)

	// Direct deps from <dependencies> block (NOT <dependencyManagement>).
	queue := []pendingDep{}
	for _, d := range root.Dependencies {
		queue = append(queue, pendingDep{
			parent:     rootGA,
			parentVer:  rootVersion,
			parentPath: []string{rootCoord},
			dep:        d,
		})
	}

	// BOM imports emit Resolved=false at depth 1 — but no transitive recursion.
	for _, d := range root.DependencyManagement.Dependencies {
		if strings.EqualFold(d.Scope, "import") {
			depGA := mavenGA{groupId: d.GroupID, artifactId: d.ArtifactID}
			depVersion := interpolate(d.Version)
			coord := mavenCoord(depGA)
			emit(
				rootCoord, rootVersion,
				coord, depVersion,
				"import", "direct", 1,
				[]string{rootCoord, coord},
				false,
			)
		}
	}

	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]
		ga := mavenGA{groupId: head.dep.GroupID, artifactId: head.dep.ArtifactID}
		version := interpolate(head.dep.Version)
		if version == "" {
			continue
		}
		if _, seen := resolved[ga]; seen {
			// Nearest-wins: first resolution wins; skip later occurrences.
			continue
		}
		resolved[ga] = version
		coord := mavenCoord(ga)
		path := append([]string{}, head.parentPath...)
		path = append(path, coord)
		pathByGA[ga] = path
		depthByGA[ga] = len(path) - 1

		parentName := mavenCoord(head.parent)

		edgeType := "transitive"
		if head.parent == rootGA {
			edgeType = "direct"
		}
		emit(
			parentName, head.parentVer,
			coord, version,
			head.dep.Scope, edgeType,
			depthByGA[ga], path, true,
		)

		// Recurse: read the dep's POM from ~/.m2 and queue its deps.
		childPomPath := mavenPomLocation(m2Dir, ga.groupId, ga.artifactId, version)
		childRaw, err := os.ReadFile(childPomPath)
		if err != nil {
			// Pom missing in local repo — agent has no network, no further
			// recursion possible. Leaf node in our graph.
			continue
		}
		var child mavenPom
		if err := xml.Unmarshal(childRaw, &child); err != nil {
			continue
		}
		childInterpolate := func(v string) string {
			if v == "${project.version}" {
				return version
			}
			return v
		}
		for _, gd := range child.Dependencies {
			// Skip test/provided scope by default — these aren't part of
			// the runtime dep tree from a top-level consumer's POV.
			if strings.EqualFold(gd.Scope, "test") || strings.EqualFold(gd.Scope, "provided") {
				continue
			}
			// Apply child's interpolation to its dep versions.
			gd.Version = childInterpolate(gd.Version)
			queue = append(queue, pendingDep{
				parent:     ga,
				parentVer:  version,
				parentPath: path,
				dep:        gd,
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
	return edges, nil
}

func mavenPomLocation(m2Dir, groupId, artifactId, version string) string {
	groupPath := strings.ReplaceAll(groupId, ".", string(filepath.Separator))
	return filepath.Join(m2Dir, groupPath, artifactId, version, fmt.Sprintf("%s-%s.pom", artifactId, version))
}

func mavenCoord(ga mavenGA) string {
	return ga.groupId + ":" + ga.artifactId
}

type mavenGA struct {
	groupId    string
	artifactId string
}

type mavenPom struct {
	XMLName              xml.Name            `xml:"project"`
	GroupID              string              `xml:"groupId"`
	ArtifactID           string              `xml:"artifactId"`
	Version              string              `xml:"version"`
	Dependencies         []mavenDep          `xml:"dependencies>dependency"`
	DependencyManagement mavenDependencyMgmt `xml:"dependencyManagement"`
}

type mavenDependencyMgmt struct {
	Dependencies []mavenDep `xml:"dependencies>dependency"`
}

type mavenDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
	Type       string `xml:"type"`
}
