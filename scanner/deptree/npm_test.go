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

// TestParseNpmPackageLock_devTransitives covers dev/optional dependencies
// that have their own transitive dependencies: the BFS must walk those
// subtrees so every emitted edge carries a fully rooted
// introduced_by_path (contract requires minItems=2).
func TestParseNpmPackageLock_devTransitives(t *testing.T) {
	edges, err := ParseNpmPackageLock(filepath.Join("testdata", "npm", "v3-dev-transitive", "package-lock.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 6 {
		t.Fatalf("expected 6 edges, got %d: %+v", len(edges), edges)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}

	// Root-level edges keep their declared types.
	if e := byChild["react"]; e.Type != "direct" || e.Depth != 1 {
		t.Errorf("react should be direct depth 1, got %+v", e)
	}
	if e := byChild["jest"]; e.Type != "dev" || e.Depth != 1 {
		t.Errorf("jest should be dev depth 1, got %+v", e)
	}
	if e := byChild["fsevents"]; e.Type != "optional" || e.Depth != 1 {
		t.Errorf("fsevents should be optional depth 1, got %+v", e)
	}

	// Transitive of the dev dep: jest -> chalk.
	chalk := byChild["chalk"]
	if chalk.ParentName != "jest" || chalk.Type != "transitive" {
		t.Errorf("chalk should be transitive under jest, got %+v", chalk)
	}
	if chalk.Depth != 2 {
		t.Errorf("chalk should have depth 2, got %d", chalk.Depth)
	}
	wantChalkPath := []string{"v3-dev-transitive", "jest", "chalk"}
	if len(chalk.IntroducedByPath) != 3 ||
		chalk.IntroducedByPath[0] != wantChalkPath[0] ||
		chalk.IntroducedByPath[1] != wantChalkPath[1] ||
		chalk.IntroducedByPath[2] != wantChalkPath[2] {
		t.Errorf("chalk path should be %v, got %v", wantChalkPath, chalk.IntroducedByPath)
	}

	// Second-level transitive of the dev subtree: chalk -> ansi-styles.
	ansi := byChild["ansi-styles"]
	if ansi.ParentName != "chalk" || ansi.Depth != 3 || len(ansi.IntroducedByPath) != 4 {
		t.Errorf("ansi-styles should be depth 3 with 4-element path, got %+v", ansi)
	}

	// Transitive of the optional dep: fsevents -> nan.
	nan := byChild["nan"]
	if nan.ParentName != "fsevents" || nan.Depth != 2 || len(nan.IntroducedByPath) != 3 {
		t.Errorf("nan should be depth 2 with 3-element path, got %+v", nan)
	}
}

// TestParseNpmPackageLock_orphanParentFallsBackToSafePath pins the
// orphan-edge convention: a packages-map entry not reachable from root
// still emits a schema-valid 2-element [parent, child] path via SafePath.
func TestParseNpmPackageLock_orphanParentFallsBackToSafePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "package-lock.json")
	lock := `{
  "name": "orphan-root",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "orphan-root", "version": "1.0.0"},
    "node_modules/ghost": {"version": "0.0.1", "dependencies": {"react": "^18.0.0"}},
    "node_modules/react": {"version": "18.2.0"}
  }
}`
	if err := writeFile(p, lock); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseNpmPackageLock(p)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.ParentName != "ghost" || e.ChildName != "react" {
		t.Errorf("wrong edge: %s -> %s", e.ParentName, e.ChildName)
	}
	if len(e.IntroducedByPath) != 2 || e.IntroducedByPath[0] != "ghost" || e.IntroducedByPath[1] != "react" {
		t.Errorf("orphan edge should fall back to [ghost react], got %v", e.IntroducedByPath)
	}
}

// TestParseNpmPackageLock_allPathsSatisfyMinItems2 is the parser-level
// contract invariant: every edge emitted from every package-lock fixture
// must have an introduced_by_path of at least 2 elements (v3 schema
// minItems=2; the server 422-rejects shorter paths).
func TestParseNpmPackageLock_allPathsSatisfyMinItems2(t *testing.T) {
	locks, err := filepath.Glob(filepath.Join("testdata", "npm", "*", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) == 0 {
		t.Fatal("no package-lock.json fixtures found")
	}
	for _, lock := range locks {
		t.Run(filepath.Base(filepath.Dir(lock)), func(t *testing.T) {
			edges, err := ParseNpmPackageLock(lock)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			for _, e := range edges {
				if len(e.IntroducedByPath) < 2 {
					t.Errorf("edge %s -> %s has introduced_by_path %v (len %d), violates minItems=2",
						e.ParentName, e.ChildName, e.IntroducedByPath, len(e.IntroducedByPath))
				}
			}
		})
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
