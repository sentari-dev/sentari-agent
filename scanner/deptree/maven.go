// Package deptree (Maven flavor).
//
// Best-effort 90% dep-tree resolver for Maven projects. Reads pom.xml
// for the project's directs, then walks ~/.m2/repository to recurse
// transitively. Out-of-scope:
//   - non-activeByDefault profile activation (OS/JDK/property conditions)
//   - a full Maven version-range solver (range strings kept verbatim when
//     no matching artifact found on disk)
//   - online POM fetch (server side completes unresolved refs via
//     maven_pom_metadata cache)
package deptree

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPomBytes caps a child POM read from ~/.m2 — POMs are tiny
// declarative XML, so 1 MiB is well above any realistic size.
const maxPomBytes = 1 << 20 // 1 MiB

// maxReactorDepth bounds <modules> recursion so a cyclic or pathological
// reactor layout cannot drive the walker into a runaway loop.  In
// practice reactor trees are flat (2 levels) — a cap of 8 leaves
// plenty of headroom for nested multi-module Spring layouts while
// still terminating on malice.
const maxReactorDepth = 8

// maxParentChainDepth bounds <parent> chain traversal.  Legitimate Maven
// parent hierarchies rarely exceed 3 levels; a depth cap of 8 matches
// the reactor cap and guards against circular parent declarations.
const maxParentChainDepth = 8

// pendingDep is a BFS queue item shared between ParseMavenPom (the BFS
// driver) and collectReactorModules (the <modules> walker that feeds
// the queue with each child module's <dependencies>).
//
// fromReactorModule marks deps declared by a reactor child module.
// Such deps are logically direct from the project's POV even though
// their IntroducedByPath has two elements ([reactor-root, module])
// before the dep coord is appended.
type pendingDep struct {
	parent            mavenGA
	parentVer         string
	parentPath        []string
	dep               mavenDep
	fromReactorModule bool
}

// isUnresolvedPlaceholder reports whether v still contains a ${...}
// expression that was not resolved by interpolateProps — indicating that
// the edge's version is not locally known and the edge should be flagged
// Resolved=false.
func isUnresolvedPlaceholder(v string) bool {
	return strings.Contains(v, "${") && strings.Contains(v, "}")
}

// interpolateProps resolves ${...} placeholders in v against props and
// ${project.version} → projectVersion.  Iterates up to 10 times to handle
// chained substitutions (e.g., ${x} where x=${y} where y=1.0). If a
// placeholder remains after the iteration cap it is returned verbatim — the
// caller is responsible for flagging the edge as unresolved.
func interpolateProps(v, projectVersion string, props map[string]string) string {
	const maxIter = 10
	for i := 0; i < maxIter; i++ {
		start := strings.Index(v, "${")
		if start == -1 {
			break
		}
		end := strings.Index(v[start:], "}")
		if end == -1 {
			break
		}
		key := v[start+2 : start+end]
		var replacement string
		if key == "project.version" || key == "version" {
			replacement = projectVersion
		} else if val, ok := props[key]; ok {
			replacement = val
		} else {
			// Unknown placeholder — return verbatim to signal unresolved.
			break
		}
		v = v[:start] + replacement + v[start+end+1:]
	}
	return v
}

// resolveParentChain walks the <parent> chain starting from pom up to
// maxParentChainDepth levels.  It returns merged property and managed-version
// maps: child values take precedence over parent values (child overrides
// parent), and the parent chain is applied from closest to furthest ancestor.
//
// Parent POMs are resolved from ~/.m2 via their GAV coordinate.
// If a parent POM is absent from the local cache the chain terminates
// at that point — the agent never fetches from the network.
func resolveParentChain(pom mavenPom, m2Dir string) (props map[string]string, managed map[mavenGA]string) {
	props = map[string]string{}
	managed = map[mavenGA]string{}

	// Walk the parent chain up to maxParentChainDepth.  We accumulate
	// ancestor data into temporary slices (closest-first) then merge in
	// reverse (furthest-first) so child overrides parent.
	type ancestorData struct {
		props   map[string]string
		managed map[mavenGA]string
	}
	var ancestors []ancestorData

	cur := pom
	seen := map[string]bool{}
	for depth := 0; depth < maxParentChainDepth; depth++ {
		p := cur.Parent
		if p.GroupID == "" || p.ArtifactID == "" || p.Version == "" {
			break
		}
		coord := p.GroupID + ":" + p.ArtifactID + ":" + p.Version
		if seen[coord] {
			break // cycle guard
		}
		seen[coord] = true

		pomPath := mavenPomLocation(m2Dir, p.GroupID, p.ArtifactID, p.Version)
		raw, err := safeio.ReadFile(pomPath, maxPomBytes)
		if err != nil {
			// Parent not in local cache — chain terminates here.
			break
		}
		var parentPom mavenPom
		if err := xml.Unmarshal(raw, &parentPom); err != nil {
			break
		}

		// Collect this ancestor's properties.
		aProps := map[string]string{}
		for k, v := range parentPom.Properties.entries {
			aProps[k] = v
		}
		// Collect this ancestor's managed versions (non-import only).
		aManaged := map[mavenGA]string{}
		for _, d := range parentPom.DependencyManagement.Dependencies {
			if strings.EqualFold(d.Scope, "import") {
				continue
			}
			ga := mavenGA{groupId: d.GroupID, artifactId: d.ArtifactID}
			if d.Version != "" {
				aManaged[ga] = d.Version
			}
		}
		ancestors = append(ancestors, ancestorData{props: aProps, managed: aManaged})

		// Continue up the chain.
		cur = parentPom
	}

	// Merge furthest-first so closest ancestor wins.
	for i := len(ancestors) - 1; i >= 0; i-- {
		for k, v := range ancestors[i].props {
			props[k] = v
		}
		for ga, v := range ancestors[i].managed {
			managed[ga] = v
		}
	}
	return props, managed
}

// ParseMavenPom reads a pom.xml + recurses through ~/.m2 to emit dep
// edges. m2Dir is the absolute path to a Maven local repository root
// (typically ~/.m2/repository).
//
// When the root pom is a reactor parent (it declares <modules>), the
// walker recursively reads each child module's pom.xml and treats their
// <dependencies> as if they were declared in the same project.  This
// lets multi-module Spring Boot / Quarkus / Camel projects (where the
// top-level pom has no <dependencies>) surface their full dep graph
// instead of silently emitting zero edges.
func ParseMavenPom(pomPath, m2Dir string) ([]DepEdge, error) {
	// POMs are bounded XML manifests; the 1 MiB cap covers every
	// real-world reactor parent we've encountered and refuses to load
	// a hostile/oversized file before it reaches the XML decoder.
	raw, err := safeio.ReadFile(pomPath, maxPomBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pomPath, err)
	}
	var root mavenPom
	if err := xml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", pomPath, err)
	}

	rootGA := mavenGA{groupId: root.GroupID, artifactId: root.ArtifactID}
	rootVersion := root.Version

	// Resolve the <parent> chain to inherit properties and managed versions.
	// Child overrides parent: we start with inherited values then apply the
	// child's own declarations on top.
	inheritedProps, inheritedManaged := resolveParentChain(root, m2Dir)

	// Merge root's own <properties> on top of inherited ones.
	// Build the effective property map: inherited (parent chain) then child.
	effectiveProps := inheritedProps
	for k, v := range root.Properties.entries {
		effectiveProps[k] = v
	}

	// interpolate resolves ${...} placeholders against the effective property
	// map plus ${project.version} → rootVersion.  Unresolvable placeholders
	// are returned verbatim (handled by the caller as unresolved).
	interpolate := func(v string) string {
		return interpolateProps(v, rootVersion, effectiveProps)
	}

	// Managed versions from <dependencyManagement> (excluding BOM
	// <scope>import</scope> entries, which are handled separately below).
	// A <dependencies> entry that omits <version> inherits its version
	// from here — without this lookup such managed-version deps resolve
	// to an empty version and get silently dropped by the BFS.
	//
	// Start from inherited managed versions (parent chain), then overlay
	// child's own declarations (child wins on conflict).
	managedVersions := map[mavenGA]string{}
	for ga, v := range inheritedManaged {
		if iv := interpolate(v); iv != "" {
			managedVersions[ga] = iv
		}
	}
	// Flatten import-scoped BOM entries from local cache.
	// BOM imports have lower priority than explicit managedVersions from the
	// root POM (Maven spec: direct declarations override BOM declarations).
	// We populate BOM-managed versions first so explicit entries override below.
	for _, d := range root.DependencyManagement.Dependencies {
		if !strings.EqualFold(d.Scope, "import") {
			continue
		}
		bomVersion := interpolate(d.Version)
		if bomVersion == "" {
			continue
		}
		bomPomPath := mavenPomLocation(m2Dir, d.GroupID, d.ArtifactID, bomVersion)
		bomRaw, err := safeio.ReadFile(bomPomPath, maxPomBytes)
		if err != nil {
			// BOM not in local cache — leave any deps that rely on it unresolved.
			continue
		}
		var bomPom mavenPom
		if err := xml.Unmarshal(bomRaw, &bomPom); err != nil {
			continue
		}
		// Resolve BOM's own properties so its managed version strings
		// can reference ${...} (e.g., Spring BOM uses ${spring-framework.version}).
		bomProps := map[string]string{}
		for k, v := range bomPom.Properties.entries {
			bomProps[k] = v
		}
		bomVersion2 := bomPom.Version
		bomInterpolate := func(v string) string {
			return interpolateProps(v, bomVersion2, bomProps)
		}
		for _, bd := range bomPom.DependencyManagement.Dependencies {
			if strings.EqualFold(bd.Scope, "import") {
				// Nested BOM import — out of scope for this pass; leave unresolved.
				continue
			}
			ga := mavenGA{groupId: bd.GroupID, artifactId: bd.ArtifactID}
			// Only set if not already managed (BOM entries are lower priority).
			if _, alreadySet := managedVersions[ga]; !alreadySet {
				if v := bomInterpolate(bd.Version); v != "" {
					managedVersions[ga] = v
				}
			}
		}
	}
	// Apply root POM's explicit managedVersions last so they override BOM entries.
	for _, d := range root.DependencyManagement.Dependencies {
		if strings.EqualFold(d.Scope, "import") {
			continue
		}
		ga := mavenGA{groupId: d.GroupID, artifactId: d.ArtifactID}
		if v := interpolate(d.Version); v != "" {
			managedVersions[ga] = v
		}
	}

	// Resolved version per (groupId,artifactId), populated as BFS proceeds.
	// Nearest-wins mediation: the FIRST time we resolve a GA wins, and only
	// that first resolution recurses into the artifact's own POM.  Later
	// occurrences of the same GA under a DIFFERENT parent still emit their
	// own distinct edge (one entry per dependency edge per the v3
	// contract) — they just reuse the already-mediated version and do not
	// re-recurse.
	resolved := map[mavenGA]string{}
	// Path to each resolved GA for introduced_by_path computation.
	pathByGA := map[mavenGA][]string{}
	depthByGA := map[mavenGA]int{}
	// Edge dedup keyed on (parent, child) so the SAME shared artifact
	// reached through two parents keeps both distinct edges.
	type edgeKey struct{ parent, child mavenGA }
	emittedEdges := map[edgeKey]bool{}

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

	// Walk reactor child modules (depth-bounded).  Each child's
	// <dependencies> are appended to the same BFS queue using the
	// child module's GA as the parent — that way edges retain the
	// "this dep was introduced by module X" attribution and the
	// existing nearest-wins map dedupes across modules.
	if len(root.Modules) > 0 {
		visited := map[string]bool{pomPath: true}
		collectReactorModules(filepath.Dir(pomPath), root, rootVersion, rootCoord, &queue, visited, 1)
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
		// Managed-version deps omit <version> in <dependencies> and inherit
		// it from <dependencyManagement>; recover it here so they are not
		// dropped as empty-version.
		if version == "" {
			if mv, ok := managedVersions[ga]; ok {
				version = mv
			}
		}

		// Nearest-wins version mediation: the FIRST resolution of a GA
		// fixes its version, depth, and path; later occurrences reuse it.
		firstResolution := false
		if mediated, seen := resolved[ga]; seen {
			version = mediated
		} else {
			if version == "" {
				// No explicit, managed, or previously-mediated version —
				// nothing to resolve; cannot recurse.
				continue
			}
			firstResolution = true
			resolved[ga] = version
			coord := mavenCoord(ga)
			path := append([]string{}, head.parentPath...)
			path = append(path, coord)
			pathByGA[ga] = path
			depthByGA[ga] = len(path) - 1
		}

		coord := mavenCoord(ga)

		// Emit one edge per distinct (parent, child) pair so a shared
		// artifact reached via multiple parents keeps every edge.  Depth
		// and introduced_by_path follow the nearest-wins resolution.
		ek := edgeKey{parent: head.parent, child: ga}
		if !emittedEdges[ek] {
			emittedEdges[ek] = true
			parentName := mavenCoord(head.parent)
			edgePath := append([]string{}, head.parentPath...)
			edgePath = append(edgePath, coord)

			// Direct iff declared by the reactor root OR by any reactor
			// module (logically direct from the project's POV; the path
			// still traces back through the module so attribution survives).
			edgeType := "transitive"
			if head.parent == rootGA || head.fromReactorModule {
				edgeType = "direct"
			}
			// A version that still contains a ${...} placeholder could not
			// be resolved locally — emit the verbatim string and mark the
			// edge unresolved so the server can complete it fleet-wide.
			edgeResolved := !isUnresolvedPlaceholder(version)
			emit(
				parentName, head.parentVer,
				coord, version,
				head.dep.Scope, edgeType,
				len(edgePath)-1, edgePath, edgeResolved,
			)
		}

		// Only the first resolution of a GA recurses into its POM; later
		// occurrences reuse the already-walked subtree.
		if !firstResolution {
			continue
		}

		// Recurse: read the dep's POM from ~/.m2 and queue its deps.
		path := pathByGA[ga]
		childPomPath := mavenPomLocation(m2Dir, ga.groupId, ga.artifactId, version)
		childRaw, err := safeio.ReadFile(childPomPath, maxPomBytes)
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
			// Transitive recursion never sets fromReactorModule — by
			// definition it's no longer logically-direct.
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

// collectReactorModules walks <modules> entries beneath a reactor parent
// pom and appends every reachable child module's <dependencies> to the
// shared queue.  Each child contributes deps under its OWN GA as the
// parent (so edge attribution survives), but the IntroducedByPath
// traces back to the reactor root so depth-1 edges still report
// reactor-root → module → dep.
//
// The walk is depth-bounded by maxReactorDepth and refuses to revisit
// a pom path more than once, so cyclic <modules> declarations cannot
// drive a runaway loop.
func collectReactorModules(parentDir string, parent mavenPom, reactorRootVersion, reactorRootCoord string, queue *[]pendingDep, visited map[string]bool, depth int) {
	if depth > maxReactorDepth {
		return
	}
	for _, mod := range parent.Modules {
		mod = strings.TrimSpace(mod)
		if mod == "" {
			continue
		}
		childPomPath := filepath.Join(parentDir, mod, "pom.xml")
		if visited[childPomPath] {
			continue
		}
		visited[childPomPath] = true

		// Same 1 MiB POM cap as the reactor root above — child
		// module POMs are no more permissive than the parent.
		raw, err := safeio.ReadFile(childPomPath, maxPomBytes)
		if err != nil {
			continue // module dir or pom missing — skip silently
		}
		var child mavenPom
		if err := xml.Unmarshal(raw, &child); err != nil {
			continue
		}

		// Inherit groupId/version from the reactor parent when the child
		// pom omits them — Maven inheritance, simplified.
		childGroupId := child.GroupID
		if childGroupId == "" {
			childGroupId = parent.GroupID
		}
		childArtifactId := child.ArtifactID
		// artifactId is REQUIRED by the POM spec, so we don't synthesise
		// one — if it's empty the module is malformed; skip.
		if childArtifactId == "" {
			continue
		}
		childVersion := child.Version
		if childVersion == "" {
			childVersion = parent.Version
			if childVersion == "" {
				childVersion = reactorRootVersion
			}
		}

		childGA := mavenGA{groupId: childGroupId, artifactId: childArtifactId}
		childCoord := mavenCoord(childGA)

		// Child's path traces back to the reactor root: [root, child].
		childPath := []string{reactorRootCoord, childCoord}

		childInterpolate := func(v string) string {
			if v == "${project.version}" {
				return childVersion
			}
			return v
		}
		for _, d := range child.Dependencies {
			d.Version = childInterpolate(d.Version)
			*queue = append(*queue, pendingDep{
				parent:            childGA,
				parentVer:         childVersion,
				parentPath:        childPath,
				dep:               d,
				fromReactorModule: true,
			})
		}

		// Recurse into this child's own <modules> (nested reactor).
		if len(child.Modules) > 0 {
			collectReactorModules(filepath.Dir(childPomPath), child, reactorRootVersion, reactorRootCoord, queue, visited, depth+1)
		}
	}
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
	Parent               mavenParentRef      `xml:"parent"`
	Properties           mavenProperties     `xml:"properties"`
	Modules              []string            `xml:"modules>module"`
	Dependencies         []mavenDep          `xml:"dependencies>dependency"`
	DependencyManagement mavenDependencyMgmt `xml:"dependencyManagement"`
	Profiles             []mavenProfile      `xml:"profiles>profile"`
}

// mavenParentRef is the <parent> block that may appear in a POM to declare
// its parent artifact.  relativePath is optional; when absent Maven
// defaults to "../pom.xml" but the agent resolves from ~/.m2 first.
type mavenParentRef struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

// mavenProperties holds the raw key-value pairs from <properties>.
// Because property keys are arbitrary element names, we decode them
// as a slice of xml.Token via a custom UnmarshalXML.
type mavenProperties struct {
	entries map[string]string
}

func (p *mavenProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.entries = map[string]string{}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &t); err != nil {
				return err
			}
			p.entries[t.Name.Local] = val
		case xml.EndElement:
			return nil
		}
	}
}

// mavenProfile is an abbreviated <profile> sufficient for activeByDefault
// activation detection and merging of deps / dependencyManagement /
// properties declared inside the profile.
type mavenProfile struct {
	Activation           mavenProfileActivation `xml:"activation"`
	Properties           mavenProperties        `xml:"properties"`
	Dependencies         []mavenDep             `xml:"dependencies>dependency"`
	DependencyManagement mavenDependencyMgmt    `xml:"dependencyManagement"`
}

// mavenProfileActivation captures the <activation> block.  Only
// <activeByDefault> is used for now — OS/JDK/property conditions are
// out of scope.
type mavenProfileActivation struct {
	ActiveByDefault string `xml:"activeByDefault"`
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
