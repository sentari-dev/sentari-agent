package deptree

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The v3 dep-graph contract defines `depth` as the number of nodes in
// `introduced_by_path` minus one — i.e. the count of edges traversed
// from the root project to the child. A direct (root-child) edge has a
// two-element path (`[root, child]`) and therefore `depth=1`; the first
// transitive edge has a three-element path and `depth=2`; and so on.
//
// This is the convention encoded by the JSON example in
// docs/contracts/agent-scan-payload-v3.md (`["myapp","express","lodash"]`
// → `depth=2`), by the shared JSON Schema, and by both the npm and pypi
// parsers. These tests pin that convention so the prose can never again
// silently drift away from the example and the emitted payloads.

// depthMatchesPath asserts the structural invariant the contract relies
// on: depth is always exactly len(introduced_by_path)-1.
func depthMatchesPath(t *testing.T, edges []DepEdge, label string) {
	t.Helper()
	for _, e := range edges {
		want := len(e.IntroducedByPath) - 1
		if e.Depth != want {
			t.Errorf("%s: edge %s->%s has depth=%d but introduced_by_path has %d nodes (want depth=%d)",
				label, e.ParentName, e.ChildName, e.Depth, len(e.IntroducedByPath), want)
		}
		if e.Type == "direct" && e.Depth != 1 {
			t.Errorf("%s: direct edge %s->%s must have depth=1 per contract, got %d",
				label, e.ParentName, e.ChildName, e.Depth)
		}
		if e.Type == "transitive" && e.Depth < 2 {
			t.Errorf("%s: transitive edge %s->%s must have depth>=2 per contract, got %d",
				label, e.ParentName, e.ChildName, e.Depth)
		}
	}
}

func TestDepthConvention_npmDirectAndTransitive(t *testing.T) {
	edges, err := ParseNpmPackageLock(filepath.Join("testdata", "npm", "v2-simple", "package-lock.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) == 0 {
		t.Fatal("expected at least one edge")
	}
	depthMatchesPath(t, edges, "npm")

	var sawDirect, sawTransitive bool
	for _, e := range edges {
		switch e.Type {
		case "direct":
			sawDirect = true
			if e.Depth != 1 {
				t.Errorf("npm direct edge %s->%s: want depth=1, got %d", e.ParentName, e.ChildName, e.Depth)
			}
		case "transitive":
			sawTransitive = true
			if e.Depth != 2 {
				t.Errorf("npm transitive edge %s->%s: want depth=2, got %d", e.ParentName, e.ChildName, e.Depth)
			}
		}
	}
	if !sawDirect || !sawTransitive {
		t.Fatalf("fixture must exercise both a direct and a transitive edge (direct=%v transitive=%v)", sawDirect, sawTransitive)
	}
}

func TestDepthConvention_pypiDirectAndTransitive(t *testing.T) {
	pkgs := map[string]pypiPkgInfo{
		"root": {version: "1.0.0", deps: []string{"a"}},
		"a":    {version: "2.0.0", deps: []string{"b"}},
		"b":    {version: "3.0.0"},
	}
	edges := buildPypiEdges(pkgs, "root", "1.0.0")
	if len(edges) == 0 {
		t.Fatal("expected at least one edge")
	}
	depthMatchesPath(t, edges, "pypi")

	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	if e, ok := byChild["a"]; !ok || e.Type != "direct" || e.Depth != 1 {
		t.Errorf("pypi 'a' must be a direct edge at depth 1, got %+v", e)
	}
	if e, ok := byChild["b"]; !ok || e.Type != "transitive" || e.Depth != 2 {
		t.Errorf("pypi 'b' must be a transitive edge at depth 2, got %+v", e)
	}
}

// assertEdgeContractInvariants checks the full per-edge v3 contract on
// every emitted edge:
//
//   - depth == len(introduced_by_path)-1
//   - the path is at least [parent, child] (minItems=2)
//   - path[len-1] == child and path[len-2] == parent (the chain ends
//     root→…→parent→child)
//   - type=="direct"     ⟹ depth==1  (direct⟺depth-1 in the
//     direct/transitive partition — dev/peer/optional root edges are
//     also depth-1 but are not "direct")
//   - type=="transitive" ⟹ depth>=2
//
// It is the machine-checkable form of the P0-6 acceptance criteria and
// is run over every fixture below.
func assertEdgeContractInvariants(t *testing.T, edges []DepEdge, label string) {
	t.Helper()
	for _, e := range edges {
		n := len(e.IntroducedByPath)
		if n < 2 {
			t.Errorf("%s: edge %s->%s has introduced_by_path with <2 nodes: %v",
				label, e.ParentName, e.ChildName, e.IntroducedByPath)
			continue
		}
		if want := n - 1; e.Depth != want {
			t.Errorf("%s: edge %s->%s has depth=%d but path has %d nodes (want depth=%d): %v",
				label, e.ParentName, e.ChildName, e.Depth, n, want, e.IntroducedByPath)
		}
		if e.IntroducedByPath[n-1] != e.ChildName {
			t.Errorf("%s: edge %s->%s path must end at child, got %v",
				label, e.ParentName, e.ChildName, e.IntroducedByPath)
		}
		if e.IntroducedByPath[n-2] != e.ParentName {
			t.Errorf("%s: edge %s->%s path[len-2] must be the parent, got %v",
				label, e.ParentName, e.ChildName, e.IntroducedByPath)
		}
		if e.Type == "direct" && e.Depth != 1 {
			t.Errorf("%s: direct edge %s->%s must have depth=1, got %d",
				label, e.ParentName, e.ChildName, e.Depth)
		}
		if e.Type == "transitive" && e.Depth < 2 {
			t.Errorf("%s: transitive edge %s->%s must have depth>=2, got %d",
				label, e.ParentName, e.ChildName, e.Depth)
		}
	}
}

// assertMavenEdgeContractInvariants is the Maven-reactor-aware form of
// assertEdgeContractInvariants. Maven reactor-module dependencies are
// intentionally emitted as type="direct" at depth>1 (the path traces
// root → module → dependency), so the blanket direct⟺depth1 rule the
// other-ecosystem helper enforces does NOT apply here. Instead it pins
// the documented contract for reactor graphs:
//
//   - depth == len(introduced_by_path)-1 (always)
//   - the path is root-anchored: path[0] == the reactor root coordinate
//   - path ends root→…→parent→child
//   - type=="transitive" ⟹ depth>=2
//   - type=="direct"     ⟹ depth in {1,2}: 1 for the root project's own
//     deps / BOM imports, 2 for a reactor module's deps (root→module→dep)
func assertMavenEdgeContractInvariants(t *testing.T, edges []DepEdge, rootCoord, label string) {
	t.Helper()
	for _, e := range edges {
		n := len(e.IntroducedByPath)
		if n < 2 {
			t.Errorf("%s: edge %s->%s has introduced_by_path with <2 nodes: %v",
				label, e.ParentName, e.ChildName, e.IntroducedByPath)
			continue
		}
		if want := n - 1; e.Depth != want {
			t.Errorf("%s: edge %s->%s has depth=%d but path has %d nodes (want depth=%d): %v",
				label, e.ParentName, e.ChildName, e.Depth, n, want, e.IntroducedByPath)
		}
		if e.IntroducedByPath[0] != rootCoord {
			t.Errorf("%s: edge %s->%s path must start at the reactor root %q, got %v",
				label, e.ParentName, e.ChildName, rootCoord, e.IntroducedByPath)
		}
		if e.IntroducedByPath[n-1] != e.ChildName {
			t.Errorf("%s: edge %s->%s path must end at child, got %v",
				label, e.ParentName, e.ChildName, e.IntroducedByPath)
		}
		if e.IntroducedByPath[n-2] != e.ParentName {
			t.Errorf("%s: edge %s->%s path[len-2] must be the parent, got %v",
				label, e.ParentName, e.ChildName, e.IntroducedByPath)
		}
		if e.Type == "transitive" && e.Depth < 2 {
			t.Errorf("%s: transitive edge %s->%s must have depth>=2, got %d",
				label, e.ParentName, e.ChildName, e.Depth)
		}
		if e.Type == "direct" && (e.Depth < 1 || e.Depth > 2) {
			t.Errorf("%s: direct edge %s->%s must have depth 1 (root dep) or 2 (reactor-module dep), got %d",
				label, e.ParentName, e.ChildName, e.Depth)
		}
	}
}

// TestDepthConvention_pypiMultiParentChild pins the P0-6 multi-parent
// fix: a child reachable through two different parents must carry a
// DISTINCT, parent-anchored introduced_by_path (and matching depth) on
// each of its edges — not one shared per-child value reused on every
// edge (the pre-fix bug that produced tens of thousands of contract
// violations on the real-scan walkthrough).
func TestDepthConvention_pypiMultiParentChild(t *testing.T) {
	pkgs := map[string]pypiPkgInfo{
		"root":   {version: "1.0.0", deps: []string{"a", "c"}},
		"a":      {version: "2.0.0", deps: []string{"shared"}},
		"c":      {version: "3.0.0", deps: []string{"shared"}},
		"shared": {version: "9.0.0"},
	}
	edges := buildPypiEdges(pkgs, "root", "1.0.0")
	assertEdgeContractInvariants(t, edges, "pypi-multiparent")

	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	aShared, ok := byEdge[key{"a", "shared"}]
	if !ok {
		t.Fatalf("a->shared edge missing; edges=%+v", edges)
	}
	if aShared.Depth != 2 || !equalPath(aShared.IntroducedByPath, []string{"root", "a", "shared"}) {
		t.Errorf("a->shared must be depth 2 via [root a shared], got depth=%d path=%v", aShared.Depth, aShared.IntroducedByPath)
	}
	cShared, ok := byEdge[key{"c", "shared"}]
	if !ok {
		t.Fatalf("c->shared edge missing; edges=%+v", edges)
	}
	if cShared.Depth != 2 || !equalPath(cShared.IntroducedByPath, []string{"root", "c", "shared"}) {
		t.Errorf("c->shared must be depth 2 via [root c shared], got depth=%d path=%v", cShared.Depth, cShared.IntroducedByPath)
	}
}

// TestDepthConvention_pypiUnreachableGroup pins the "no fabricated
// depth-0 edge" half of P0-6: nodes in a subgraph that is not reachable
// from the chosen root (e.g. a dev/optional group or orphan) are DROPPED
// rather than emitted with depth 0 and a fabricated 2-element path.
func TestDepthConvention_pypiUnreachableGroup(t *testing.T) {
	pkgs := map[string]pypiPkgInfo{
		"app":       {version: "1.0", deps: []string{"reachable"}},
		"reachable": {version: "2.0"},
		// Unreachable dev/optional subgraph: never referenced from "app".
		"devtool": {version: "9.0", deps: []string{"devdep"}},
		"devdep":  {version: "0.1"},
	}
	edges := buildPypiEdges(pkgs, "app", "1.0")
	assertEdgeContractInvariants(t, edges, "pypi-unreachable")

	for _, e := range edges {
		if e.Depth == 0 {
			t.Errorf("no edge may have depth 0 (fabricated); got %+v", e)
		}
		if e.ParentName == "devtool" || e.ChildName == "devdep" {
			t.Errorf("unreachable dev-group edge must be dropped, got %+v", e)
		}
	}
	// The single reachable edge must still be present and correct.
	if len(edges) != 1 || edges[0].ParentName != "app" || edges[0].ChildName != "reachable" || edges[0].Depth != 1 {
		t.Fatalf("expected exactly [app->reachable @depth1], got %+v", edges)
	}
}

// TestDepthConvention_pnpmPeerSuffixCleanVersion pins P0-6 item 2: a
// pnpm v9 importer version decorated with a peer-resolution context
// ("4.18.2(react@18.0.0)") must yield a clean semver child_version on
// the emitted direct edge, and every edge must satisfy the invariants.
func TestDepthConvention_pnpmPeerSuffixCleanVersion(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "pnpm-lock.yaml")
	body := `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2(react@18.0.0)

packages:

  express@4.18.2:
    resolution: {integrity: sha512-express}

  qs@6.11.0:
    resolution: {integrity: sha512-qs}

snapshots:

  express@4.18.2(react@18.0.0):
    dependencies:
      qs: 6.11.0

  qs@6.11.0: {}
`
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParsePnpmLock(lockPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	assertEdgeContractInvariants(t, edges, "pnpm-peer")

	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	express, ok := byChild["express"]
	if !ok || express.Type != "direct" {
		t.Fatalf("expected direct express edge, got %+v", express)
	}
	if express.ChildVersion != "4.18.2" {
		t.Errorf("direct express child_version must be clean semver 4.18.2, got %q", express.ChildVersion)
	}
	qs, ok := byChild["qs"]
	if !ok || qs.Type != "transitive" || qs.ParentName != "express" || qs.Depth != 2 {
		t.Errorf("expected express->qs transitive at depth 2, got %+v", qs)
	}
}

// TestDepthConvention_yarnOptionalDependencies pins P0-6 item 4: a
// yarn.lock entry with an `optionalDependencies:` block must produce the
// corresponding edge (previously silently dropped because the parser
// only folded `dependencies:` blocks).
func TestDepthConvention_yarnOptionalDependencies(t *testing.T) {
	dir := t.TempDir()
	yarnPath := filepath.Join(dir, "yarn.lock")
	pjPath := filepath.Join(dir, "package.json")
	yarnBody := `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  integrity sha512-test
  optionalDependencies:
    fsevents "2.3.2"

fsevents@2.3.2:
  version "2.3.2"
  resolved "https://registry.yarnpkg.com/fsevents/-/fsevents-2.3.2.tgz"
  integrity sha512-test
`
	if err := os.WriteFile(yarnPath, []byte(yarnBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pjPath, []byte(`{"name":"optdep-fixture","version":"1.0.0","dependencies":{"express":"^4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseYarnLock(yarnPath, pjPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	assertEdgeContractInvariants(t, edges, "yarn-optional")

	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}
	fs, ok := byEdge[key{"express", "fsevents"}]
	if !ok {
		t.Fatalf("express->fsevents edge from optionalDependencies must be emitted; edges=%+v", edges)
	}
	if fs.Type != "transitive" || fs.Depth != 2 || fs.ChildVersion != "2.3.2" {
		t.Errorf("express->fsevents wrong: %+v", fs)
	}
}

func equalPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDepthConvention_contractProseMatchesExample guards the prose in the
// shared contract doc against drifting away from the JSON example and the
// emitted payloads. The earlier prose claimed direct edges had `depth=0`,
// which contradicts the `depth=2` example three-node path printed in the
// same section (and every parser). This test fails if that contradiction
// is reintroduced.
func TestDepthConvention_contractProseMatchesExample(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "contracts", "agent-scan-payload-v3.md")
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read contract doc: %v", err)
	}
	doc := string(raw)

	if strings.Contains(doc, "`depth=0`") {
		t.Errorf("contract prose still claims a `depth=0` edge, contradicting the depth=2 JSON example and the parsers")
	}
	// The direct-edge depth must be stated as 1 to match the example/code.
	if !strings.Contains(doc, "`depth=1`") {
		t.Errorf("contract prose must state direct edges have `depth=1` to match the JSON example and parsers")
	}
}
