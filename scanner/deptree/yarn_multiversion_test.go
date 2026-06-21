package deptree

import (
	"path/filepath"
	"testing"
)

// TestParseYarnLock_multipleVersionsRetained proves the yarn v1 parser
// keeps DISTINCT versions of the same package instead of collapsing
// them to a single name-keyed node.
//
// Fixture: the root depends on lodash@^4.17.21 (→ 4.17.21) while a
// transitive dep (legacy-pkg) depends on lodash@^3.10.0 (→ 3.10.1).
// A correct dep graph carries BOTH lodash versions; the buggy parser
// kept only one (whichever yarn key it saw last), so the transitive
// edge silently pointed at the wrong version.
func TestParseYarnLock_multipleVersionsRetained(t *testing.T) {
	dir := filepath.Join("testdata", "npm", "yarn-multiversion")
	edges, err := ParseYarnLock(filepath.Join(dir, "yarn.lock"), filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	root := "yarn-multiversion-fixture"

	// Root → lodash resolves the modern 4.17.21.
	rootLodash, ok := byEdge[key{root, "lodash"}]
	if !ok {
		t.Fatalf("root->lodash edge missing; edges=%+v", edges)
	}
	if rootLodash.ChildVersion != "4.17.21" {
		t.Errorf("root->lodash version=%q want 4.17.21", rootLodash.ChildVersion)
	}
	if rootLodash.Type != "direct" || rootLodash.Depth != 1 {
		t.Errorf("root->lodash attrs wrong: %+v", rootLodash)
	}

	// legacy-pkg → lodash resolves the legacy 3.10.1 — a DISTINCT version.
	legacyLodash, ok := byEdge[key{"legacy-pkg", "lodash"}]
	if !ok {
		t.Fatalf("legacy-pkg->lodash edge missing (multi-version collapse); edges=%+v", edges)
	}
	if legacyLodash.ChildVersion != "3.10.1" {
		t.Errorf("legacy-pkg->lodash version=%q want 3.10.1 (distinct from root's 4.17.21)", legacyLodash.ChildVersion)
	}
	if legacyLodash.Type != "transitive" || legacyLodash.Depth != 2 {
		t.Errorf("legacy-pkg->lodash attrs wrong: %+v", legacyLodash)
	}

	// Both distinct versions must appear across all lodash edges.
	versions := map[string]bool{}
	for _, e := range edges {
		if e.ChildName == "lodash" {
			versions[e.ChildVersion] = true
		}
	}
	if !versions["3.10.1"] || !versions["4.17.21"] {
		t.Errorf("expected both lodash versions retained, got %v", versions)
	}

	// root->legacy-pkg sanity.
	legacy, ok := byEdge[key{root, "legacy-pkg"}]
	if !ok || legacy.ChildVersion != "1.0.0" || legacy.Type != "direct" {
		t.Errorf("root->legacy-pkg edge wrong: %+v", legacy)
	}
}
