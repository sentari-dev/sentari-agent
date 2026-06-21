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
