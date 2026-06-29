package deptree

import (
	"path/filepath"
	"testing"
)

func TestParsePnpmLock_directAndTransitive(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-simple", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d: %+v", len(edges), edges)
	}
	var direct, transitive *DepEdge
	for i := range edges {
		if edges[i].Type == "direct" {
			direct = &edges[i]
		} else if edges[i].Type == "transitive" {
			transitive = &edges[i]
		}
	}
	if direct == nil || direct.ChildName != "express" || direct.ChildVersion != "4.18.2" {
		t.Errorf("direct edge wrong: %+v", direct)
	}
	if transitive == nil || transitive.ParentName != "express" || transitive.ChildName != "qs" || transitive.Depth != 2 {
		t.Errorf("transitive edge wrong: %+v", transitive)
	}
}

// TestParsePnpmLock_v9_snapshotsTransitive proves the pnpm >=9 layout
// is parsed: dependency lists live under top-level `snapshots:` (the
// `packages:` block holds only resolution metadata).  Before the fix
// this yielded 0 transitive edges because pnpmLock only read
// `packages:`.
func TestParsePnpmLock_v9_snapshotsTransitive(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v9", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	var transitives int
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
		if e.Type == "transitive" {
			transitives++
		}
	}
	if transitives == 0 {
		t.Fatalf("expected transitive edges from pnpm v9 snapshots, got 0: %+v", edges)
	}
	// express -> qs (depth 2) and qs -> side-channel (depth 3).
	qs, ok := byChild["qs"]
	if !ok || qs.ParentName != "express" || qs.Type != "transitive" || qs.Depth != 2 {
		t.Errorf("expected express->qs transitive at depth 2, got %+v", qs)
	}
	sc, ok := byChild["side-channel"]
	if !ok || sc.ParentName != "qs" || sc.Type != "transitive" || sc.Depth != 3 {
		t.Errorf("expected qs->side-channel transitive at depth 3, got %+v", sc)
	}
}

// TestParsePnpmLock_v6_legacyPackagesBlock keeps the old v5/v6 layout
// (deps inline under `packages:`) working after the v9 fix.
func TestParsePnpmLock_v6_legacyPackagesBlock(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v6", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d: %+v", len(edges), edges)
	}
	var transitive *DepEdge
	for i := range edges {
		if edges[i].Type == "transitive" {
			transitive = &edges[i]
		}
	}
	if transitive == nil || transitive.ParentName != "express" || transitive.ChildName != "qs" || transitive.Depth != 2 {
		t.Errorf("legacy v6 transitive edge wrong: %+v", transitive)
	}
}

func TestPnpmKeyParts(t *testing.T) {
	cases := map[string][2]string{
		"/foo@1.0.0":             {"foo", "1.0.0"},
		"/@scope/foo@1.0.0":      {"@scope/foo", "1.0.0"},
		"foo@2.3.4":              {"foo", "2.3.4"},
		"/foo@1.0.0(peer@2.0.0)": {"foo", "1.0.0"},
	}
	for in, want := range cases {
		name, ver := pnpmKeyParts(in)
		if name != want[0] || ver != want[1] {
			t.Errorf("pnpmKeyParts(%q) = (%q, %q), want (%q, %q)", in, name, ver, want[0], want[1])
		}
	}
}
