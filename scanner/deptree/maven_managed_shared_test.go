package deptree

import (
	"path/filepath"
	"testing"
)

// TestParseMavenPom_managedVersionAndSharedArtifact covers two related
// dep-graph defects:
//
//  1. Managed-version deps (declared in <dependencies> WITHOUT a
//     <version> because the version lives in <dependencyManagement>)
//     were silently dropped — the parser saw version=="" and skipped
//     the dep entirely.
//  2. A shared artifact reached through two different parents
//     (lib-a → shared AND lib-b → shared) was collapsed to a single
//     edge because dedup keyed on the artifact GA alone, not the
//     (parent, child) edge.  The v3 contract requires one entry per
//     dependency edge, so both edges must survive.
func TestParseMavenPom_managedVersionAndSharedArtifact(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "maven", "managed-shared")
	m2Dir := filepath.Join(fixtureDir, ".m2", "repository")
	edges, err := ParseMavenPom(filepath.Join(fixtureDir, "pom.xml"), m2Dir)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	// (1) Managed-version dep lib-a must NOT be dropped; its version is
	// resolved from <dependencyManagement>.
	libA, ok := byEdge[key{"com.example.app:my-app", "com.example:lib-a"}]
	if !ok {
		t.Fatalf("managed-version dep lib-a was dropped; edges=%+v", edges)
	}
	if libA.ChildVersion != "1.0.0" {
		t.Errorf("lib-a version=%q want 1.0.0 (resolved from dependencyManagement)", libA.ChildVersion)
	}
	if libA.Type != "direct" || libA.Depth != 1 || !libA.Resolved {
		t.Errorf("lib-a edge attrs wrong: %+v", libA)
	}

	// lib-b is a normal explicit-version direct dep.
	libB, ok := byEdge[key{"com.example.app:my-app", "com.example:lib-b"}]
	if !ok || libB.ChildVersion != "1.0.0" || libB.Type != "direct" {
		t.Errorf("lib-b edge wrong: %+v", libB)
	}

	// (2) Both shared edges must be present and distinct.
	sharedViaA, okA := byEdge[key{"com.example:lib-a", "com.example:shared"}]
	sharedViaB, okB := byEdge[key{"com.example:lib-b", "com.example:shared"}]
	if !okA || !okB {
		t.Fatalf("shared artifact collapsed: lib-a->shared present=%v lib-b->shared present=%v; edges=%+v", okA, okB, edges)
	}
	if sharedViaA.ChildVersion != "3.0.0" || sharedViaB.ChildVersion != "3.0.0" {
		t.Errorf("shared version wrong: viaA=%q viaB=%q", sharedViaA.ChildVersion, sharedViaB.ChildVersion)
	}
	if sharedViaA.Type != "transitive" || sharedViaB.Type != "transitive" {
		t.Errorf("shared edges should be transitive: viaA=%s viaB=%s", sharedViaA.Type, sharedViaB.Type)
	}
	if sharedViaA.Depth != 2 || sharedViaB.Depth != 2 {
		t.Errorf("shared depth wrong: viaA=%d viaB=%d", sharedViaA.Depth, sharedViaB.Depth)
	}

	// Exactly the 4 expected edges, no extras.
	if len(edges) != 4 {
		t.Errorf("expected 4 edges (lib-a, lib-b, lib-a->shared, lib-b->shared), got %d: %+v", len(edges), edges)
	}
}
