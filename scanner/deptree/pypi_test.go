package deptree

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestNormalizePyPIName pins the PEP 503 name key: lowercase and collapse
// any run of -, _, . into a single hyphen. Plain strings.ToLower left the
// separator mismatch in place and broke dep-edge joins.
func TestNormalizePyPIName(t *testing.T) {
	cases := map[string]string{
		"Typing_Extensions": "typing-extensions",
		"typing-extensions": "typing-extensions",
		"typing.extensions": "typing-extensions",
		"Flask":             "flask",
		"zope__interface":   "zope-interface",
		"a.-_b":             "a-b",
	}
	for in, want := range cases {
		if got := normalizePyPIName(in); got != want {
			t.Errorf("normalizePyPIName(%q)=%q want %q", in, got, want)
		}
	}
}

// TestParseUvLock_pep503NameJoin proves a dependency referenced with a
// non-normalized name ("Typing_Extensions") joins against the package
// entry declared as "typing-extensions" — pre-fix (case-only lowercasing)
// the underscore/hyphen mismatch dropped the child version, leaving the
// edge child_version empty and the transitive subtree unreachable.
func TestParseUvLock_pep503NameJoin(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "myproj")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "uv.lock")
	body := `
[[package]]
name = "myproj"
version = "1.0.0"
dependencies = [
    { name = "Typing_Extensions" },
]

[[package]]
name = "typing-extensions"
version = "4.9.0"
`
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseUvLock(lockPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.ParentName != "myproj" || e.ChildName != "typing-extensions" {
		t.Errorf("wrong edge parent/child: %s -> %s", e.ParentName, e.ChildName)
	}
	if e.ChildVersion != "4.9.0" {
		t.Errorf("child_version = %q; want 4.9.0 (join must succeed after PEP 503 normalization)", e.ChildVersion)
	}
	if e.Type != "direct" || e.Depth != 1 {
		t.Errorf("expected direct edge at depth 1, got %+v", e)
	}
}

// TestParsePoetryLock_multipleTopLevelDeps proves the root-synthesis fix:
// a poetry.lock (which never contains the project package) with TWO
// unrelated top-level deps — requests (→urllib3) and click — must emit
// BOTH as depth-1 directs under the synthetic "(unknown)" root, and keep
// urllib3 as a depth-2 transitive under requests. The pre-fix code elected
// a single root (click, alphabetically first, dep-less) and dropped
// requests and its urllib3 subtree entirely, emitting 0 edges.
func TestParsePoetryLock_multipleTopLevelDeps(t *testing.T) {
	// Directory name "app" matches no package, so the dir-name tie-break
	// does not fire and the synthesis path is exercised.
	dir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "poetry.lock")
	body := `
[[package]]
name = "click"
version = "8.1.7"

[[package]]
name = "requests"
version = "2.31.0"

[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "urllib3"
version = "2.0.7"
`
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParsePoetryLock(lockPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	assertEdgeContractInvariants(t, edges, "poetry-multi-toplevel")

	type key struct{ parent, child string }
	got := map[key]DepEdge{}
	for _, e := range edges {
		got[key{e.ParentName, e.ChildName}] = e
	}
	if e, ok := got[key{"(unknown)", "requests"}]; !ok || e.Type != "direct" || e.Depth != 1 {
		t.Errorf("want (unknown)->requests direct depth1, got %+v (all: %+v)", e, edges)
	}
	if e, ok := got[key{"(unknown)", "click"}]; !ok || e.Type != "direct" || e.Depth != 1 {
		t.Errorf("want (unknown)->click direct depth1, got %+v (all: %+v)", e, edges)
	}
	if e, ok := got[key{"requests", "urllib3"}]; !ok || e.Type != "transitive" || e.Depth != 2 {
		t.Errorf("want requests->urllib3 transitive depth2, got %+v (all: %+v)", e, edges)
	}
	if len(edges) != 3 {
		t.Errorf("expected exactly 3 edges, got %d: %+v", len(edges), edges)
	}
}

// TestParsePoetryLock_fullCycleAllDirect exercises buildPypiAllDirect (the
// true-cycle fallback that fires only when NO no-incoming-edge candidate
// exists). Package A deps B and B deps A, so every node has an incoming
// edge and no root is derivable → all packages are emitted as depth-1
// directs from the synthetic "(unknown)" root.
func TestParsePoetryLock_fullCycleAllDirect(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cyc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "poetry.lock")
	body := `
[[package]]
name = "a"
version = "1.0.0"

[package.dependencies]
b = "*"

[[package]]
name = "b"
version = "2.0.0"

[package.dependencies]
a = "*"
`
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParsePoetryLock(lockPath)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	assertEdgeContractInvariants(t, edges, "poetry-full-cycle")

	if len(edges) != 2 {
		t.Fatalf("expected 2 all-direct edges, got %d: %+v", len(edges), edges)
	}
	for _, e := range edges {
		if e.ParentName != "(unknown)" {
			t.Errorf("all-direct edge parent must be (unknown), got %q: %+v", e.ParentName, e)
		}
		if e.Type != "direct" || e.Depth != 1 {
			t.Errorf("all-direct edge must be direct depth1, got %+v", e)
		}
		wantPath := []string{"(unknown)", e.ChildName}
		if len(e.IntroducedByPath) != 2 ||
			e.IntroducedByPath[0] != wantPath[0] ||
			e.IntroducedByPath[1] != wantPath[1] {
			t.Errorf("all-direct edge path must be %v, got %v", wantPath, e.IntroducedByPath)
		}
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

// TestParseRequirementsTxt_skipsURLAndVCS proves direct URL and VCS lines
// no longer emit phantom "git" / "https" packages: only the real pinned
// requirement (flask==2.0) survives.
func TestParseRequirementsTxt_skipsURLAndVCS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	content := "git+https://github.com/psf/requests.git\n" +
		"https://files.pythonhosted.org/packages/foo-1.0.tar.gz\n" +
		"flask==2.0\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	edges, err := ParseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected exactly 1 edge (only flask), got %d: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.ChildName != "flask" || e.ChildVersion != "2.0" {
		t.Errorf("expected flask==2.0, got %+v", e)
	}
	for _, bad := range []string{"git", "https", "http"} {
		for _, e := range edges {
			if e.ChildName == bad {
				t.Errorf("phantom package %q emitted from URL/VCS line: %+v", bad, edges)
			}
		}
	}
}

// TestParseRequirementsTxt_followsIncludes proves an `-r nested.txt`
// include is followed: the nested file's edges are merged in alongside
// the including file's own direct dep.
func TestParseRequirementsTxt_followsIncludes(t *testing.T) {
	edges, err := ParseRequirementsTxt(filepath.Join("testdata", "pypi", "requirements", "with-include.txt"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}
	// flask is declared directly in with-include.txt.
	if e, ok := byChild["flask"]; !ok || e.ChildVersion != "3.0.0" {
		t.Errorf("flask (direct) edge wrong: %+v (all: %+v)", e, edges)
	}
	// requests + urllib3 come from the included nested.txt.
	if e, ok := byChild["requests"]; !ok || e.ChildVersion != "2.31.0" {
		t.Errorf("requests (from -r nested.txt) missing/wrong: %+v (all: %+v)", e, edges)
	}
	if e, ok := byChild["urllib3"]; !ok || e.ChildVersion != "" {
		t.Errorf("urllib3 (from -r nested.txt, unpinned) missing/wrong: %+v (all: %+v)", e, edges)
	}
	if len(edges) != 3 {
		t.Fatalf("expected 3 edges (flask + nested requests/urllib3), got %d: %+v", len(edges), edges)
	}
}

// TestParseRequirementsTxt_includeCycleBounded proves a self-referential
// include chain (a -> b -> a) terminates via the visited-set instead of
// looping forever, and that each file's real deps are emitted exactly
// once.
func TestParseRequirementsTxt_includeCycleBounded(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(a, []byte("-r b.txt\nalpha==1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("-r a.txt\nbeta==2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var edges []DepEdge
	var perr error
	go func() {
		edges, perr = ParseRequirementsTxt(a)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ParseRequirementsTxt did not terminate on a self-referential -r cycle")
	}
	if perr != nil {
		t.Fatalf("parse failed: %v", perr)
	}

	counts := map[string]int{}
	for _, e := range edges {
		counts[e.ChildName]++
	}
	if counts["alpha"] != 1 || counts["beta"] != 1 {
		t.Fatalf("expected alpha and beta exactly once each, got %+v (edges: %+v)", counts, edges)
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
