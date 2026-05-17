package deptree

import (
	"path/filepath"
	"testing"
)

func TestParseUvLock_directAndTransitive(t *testing.T) {
	edges, err := ParseUvLock(filepath.Join("testdata", "pypi", "uv", "uv.lock"))
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
	if direct == nil || direct.ChildName != "requests" || direct.ChildVersion != "2.31.0" {
		t.Errorf("direct edge wrong: %+v", direct)
	}
	if transitive == nil || transitive.ChildName != "urllib3" || transitive.ParentName != "requests" {
		t.Errorf("transitive edge wrong: %+v", transitive)
	}
}

func TestParsePoetryLock_inferRootFromDepGraph(t *testing.T) {
	edges, err := ParsePoetryLock(filepath.Join("testdata", "pypi", "poetry", "poetry.lock"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) == 0 {
		t.Fatal("expected at least 1 edge")
	}
	hasUrllib3 := false
	for _, e := range edges {
		if e.ChildName == "urllib3" {
			hasUrllib3 = true
		}
	}
	if !hasUrllib3 {
		t.Errorf("expected urllib3 to appear in edges, got %+v", edges)
	}
}

func TestParsePipfileLock_defaultAndDevelop(t *testing.T) {
	edges, err := ParsePipfileLock(filepath.Join("testdata", "pypi", "pipfile", "Pipfile.lock"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d: %+v", len(edges), edges)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	r, ok := byChild["requests"]
	if !ok || r.Type != "direct" || r.ChildVersion != "2.31.0" {
		t.Errorf("requests edge wrong: %+v", r)
	}
	p, ok := byChild["pytest"]
	if !ok || p.Type != "dev" || p.ChildVersion != "7.4.0" {
		t.Errorf("pytest edge wrong: %+v", p)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	edges, err := ParseRequirementsTxt(filepath.Join("testdata", "pypi", "requirements", "requirements.txt"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (skip -r and comments), got %d: %+v", len(edges), edges)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	if e, ok := byChild["requests"]; !ok || e.ChildVersion != "2.31.0" {
		t.Errorf("requests edge wrong: %+v", e)
	}
	if e, ok := byChild["urllib3"]; !ok || e.ChildVersion != "2.0.7" {
		t.Errorf("urllib3 edge wrong: %+v", e)
	}
}
