package deptree

import (
	"path/filepath"
	"testing"
)

func TestParseNuGetProjectAssets(t *testing.T) {
	edges, err := ParseNuGetProjectAssets(filepath.Join("testdata", "nuget", "with-assets", "project.assets.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (1 direct + 1 transitive), got %d: %+v", len(edges), edges)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	d, ok := byChild["Newtonsoft.Json"]
	if !ok || d.Type != "direct" || d.ChildVersion != "13.0.3" || d.Scope != "net6.0" {
		t.Errorf("direct edge wrong: %+v", d)
	}
	tr, ok := byChild["Microsoft.CSharp"]
	if !ok || tr.Type != "transitive" || tr.ParentName != "Newtonsoft.Json" || tr.Depth != 2 || tr.Scope != "net6.0" {
		t.Errorf("transitive edge wrong: %+v", tr)
	}
}

func TestParseNuGetPackagesLock(t *testing.T) {
	edges, err := ParseNuGetPackagesLock(filepath.Join("testdata", "nuget", "lock-only", "packages.lock.json"))
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
		} else {
			transitive = &edges[i]
		}
	}
	if direct == nil || direct.ChildName != "Newtonsoft.Json" || direct.ChildVersion != "13.0.3" {
		t.Errorf("direct edge wrong: %+v", direct)
	}
	if transitive == nil || transitive.ChildName != "Microsoft.CSharp" || transitive.ChildVersion != "4.7.0" {
		t.Errorf("transitive edge wrong: %+v", transitive)
	}
}
