package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNpmPackageLock_v3Simple(t *testing.T) {
	edges, err := ParseNpmPackageLock(filepath.Join("testdata", "npm", "v3-simple", "package-lock.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.ParentName != "v3-simple" || e.ChildName != "lodash" {
		t.Errorf("wrong parent/child: %s -> %s", e.ParentName, e.ChildName)
	}
	if e.ChildVersion != "4.17.21" {
		t.Errorf("wrong child version: %s", e.ChildVersion)
	}
	if e.Type != "direct" {
		t.Errorf("expected direct, got %s", e.Type)
	}
	if e.Depth != 1 {
		t.Errorf("expected depth 1, got %d", e.Depth)
	}
	if len(e.IntroducedByPath) != 2 || e.IntroducedByPath[0] != "v3-simple" || e.IntroducedByPath[1] != "lodash" {
		t.Errorf("wrong path: %v", e.IntroducedByPath)
	}
	if !e.Resolved {
		t.Error("expected resolved=true")
	}
}

func TestParseNpmPackageLock_v2WithTransitive(t *testing.T) {
	edges, err := ParseNpmPackageLock(filepath.Join("testdata", "npm", "v2-simple", "package-lock.json"))
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
			break
		}
	}
	if transitive == nil {
		t.Fatal("expected one transitive edge")
	}
	if transitive.ParentName != "express" || transitive.ChildName != "qs" {
		t.Errorf("wrong transitive: %s -> %s", transitive.ParentName, transitive.ChildName)
	}
	if transitive.Depth != 2 {
		t.Errorf("expected depth 2 for transitive, got %d", transitive.Depth)
	}
	if len(transitive.IntroducedByPath) != 3 {
		t.Errorf("expected 3-element path, got %v", transitive.IntroducedByPath)
	}
}

func TestParseNpmPackageLock_devAndPeerDeps(t *testing.T) {
	edges, err := ParseNpmPackageLock(filepath.Join("testdata", "npm", "v3-with-dev", "package-lock.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 3 {
		t.Fatalf("expected 3 edges (1 direct + 1 dev + 1 peer), got %d: %+v", len(edges), edges)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	if e, ok := byChild["react"]; !ok || e.Type != "direct" {
		t.Errorf("react should be direct, got %+v", e)
	}
	if e, ok := byChild["jest"]; !ok || e.Type != "dev" {
		t.Errorf("jest should be dev, got %+v", e)
	}
	if e, ok := byChild["@types/react"]; !ok || e.Type != "peer" {
		t.Errorf("@types/react should be peer, got %+v", e)
	}
}

func TestParseNpmPackageLock_returnsErrorForV1(t *testing.T) {
	dir := t.TempDir()
	v1Path := filepath.Join(dir, "package-lock.json")
	if err := writeFile(v1Path, `{"name":"v1","lockfileVersion":1,"packages":{}}`); err != nil {
		t.Fatal(err)
	}
	_, err := ParseNpmPackageLock(v1Path)
	if err == nil {
		t.Fatal("expected error for v1 lockfile")
	}
}

func TestParseNpmPackageLock_emptyPackagesYieldsNoEdges(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "package-lock.json")
	if err := writeFile(p, `{"name":"empty","lockfileVersion":3,"packages":{}}`); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseNpmPackageLock(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("expected no edges, got %d", len(edges))
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
