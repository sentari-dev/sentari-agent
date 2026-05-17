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
