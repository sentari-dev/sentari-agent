package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseUvLock_rootTieBreakByDirName covers a multi-root uv.lock
// where the alphabetically-first root candidate ("aaa-lib") is NOT the
// real project; the real project ("myapp") matches the lockfile's
// directory name and must be chosen as the root.
func TestParseUvLock_rootTieBreakByDirName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myapp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "uv.lock")
	// Two roots (neither appears in another package's deps): "aaa-lib"
	// (alphabetically first) and "myapp" (the real project, depends on
	// requests). requests is a child of myapp.
	body := `
[[package]]
name = "aaa-lib"
version = "0.0.1"

[[package]]
name = "myapp"
version = "1.0.0"
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
`
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseUvLock(lockPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	// The direct edge must originate from "myapp", not "aaa-lib".
	var directParent string
	for _, e := range edges {
		if e.Type == "direct" {
			directParent = e.ParentName
		}
	}
	if directParent != "myapp" {
		t.Fatalf("expected root 'myapp' (dir-name tie-break), got direct parent %q; edges=%+v", directParent, edges)
	}
}

// TestParsePoetryLock_rootTieBreakByDirName is the poetry.lock analogue
// of the uv tie-break test.
func TestParsePoetryLock_rootTieBreakByDirName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myapp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "poetry.lock")
	body := `
[[package]]
name = "aaa-lib"
version = "0.0.1"

[[package]]
name = "myapp"
version = "1.0.0"

[package.dependencies]
requests = "^2.31.0"

[[package]]
name = "requests"
version = "2.31.0"
`
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParsePoetryLock(lockPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	var directParent string
	for _, e := range edges {
		if e.Type == "direct" {
			directParent = e.ParentName
		}
	}
	if directParent != "myapp" {
		t.Fatalf("expected root 'myapp' (dir-name tie-break), got direct parent %q; edges=%+v", directParent, edges)
	}
}

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

// TestParseRequirementsTxt_stripsBOM proves a leading UTF-8 BOM
// (\xef\xbb\xbf) does not swallow the first package line.
func TestParseRequirementsTxt_stripsBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	content := "\xef\xbb\xbfrequests==2.31.0\nurllib3==2.0.7\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	if e, ok := byChild["requests"]; !ok || e.ChildVersion != "2.31.0" {
		t.Fatalf("first line (BOM-prefixed) should parse as requests==2.31.0, got %+v (all: %+v)", e, edges)
	}
	if _, ok := byChild["urllib3"]; !ok {
		t.Errorf("urllib3 missing: %+v", edges)
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
