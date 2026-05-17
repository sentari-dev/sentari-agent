package deptree

import (
	"path/filepath"
	"testing"
)

func TestParseYarnLock_direct_and_transitive(t *testing.T) {
	dir := filepath.Join("testdata", "npm", "yarn-v1")
	edges, err := ParseYarnLock(filepath.Join(dir, "yarn.lock"), filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 3 {
		t.Fatalf("expected 3 edges (2 direct + 1 transitive), got %d: %+v", len(edges), edges)
	}

	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}

	expressEdge, ok := byChild["express"]
	if !ok || expressEdge.Type != "direct" || expressEdge.ChildVersion != "4.18.2" || expressEdge.ParentName != "yarn-v1-fixture" {
		t.Errorf("express edge wrong: %+v", expressEdge)
	}
	if expressEdge.Depth != 1 || len(expressEdge.IntroducedByPath) != 2 {
		t.Errorf("express depth/path wrong: depth=%d path=%v", expressEdge.Depth, expressEdge.IntroducedByPath)
	}

	lodashEdge, ok := byChild["lodash"]
	if !ok || lodashEdge.Type != "direct" {
		t.Errorf("lodash edge wrong: %+v", lodashEdge)
	}

	qsEdge, ok := byChild["qs"]
	if !ok || qsEdge.Type != "transitive" || qsEdge.ChildVersion != "6.11.0" || qsEdge.ParentName != "express" || qsEdge.Depth != 2 {
		t.Errorf("qs edge wrong: %+v", qsEdge)
	}
}

func TestYarnSpecName(t *testing.T) {
	cases := map[string]string{
		"lodash@^4.17.0":    "lodash",
		"@types/node@^18.0": "@types/node",
		"foo@1.0.0":         "foo",
	}
	for in, want := range cases {
		if got := yarnSpecName(in); got != want {
			t.Errorf("yarnSpecName(%q) = %q, want %q", in, got, want)
		}
	}
}
