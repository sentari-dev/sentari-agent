package deptree

import (
	"path/filepath"
	"sort"
	"testing"
)

// TestParseMavenPom_reactorWalksChildModules covers the multi-module
// Spring Boot / Quarkus / Camel layout: a reactor parent POM that
// declares only <modules> (no top-level <dependencies>) plus N child
// modules that each declare their own <dependencies>.
//
// Pre-fix this returned zero edges (the parent had no <dependencies>).
// Post-fix all child-module direct deps must surface, attributed to
// the module that declared them.  The intentionally-missing "missing"
// module must be skipped silently with no error and no edge.
func TestParseMavenPom_reactorWalksChildModules(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "maven", "multimodule")
	// Empty m2 dir — we only care about direct (depth-1) edges from
	// each child module's pom; transitive recursion needs no .m2 here.
	emptyM2 := filepath.Join(fixtureDir, "nonexistent-m2")

	edges, err := ParseMavenPom(filepath.Join(fixtureDir, "pom.xml"), emptyM2)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Expected child-module deps:
	//   api      → com.example:http-client      4.5.13
	//   core     → com.example:logging-api      2.17.1
	//   core     → com.example:cache-lib        3.0.0
	// All three must be present.  The "missing" module dir is absent
	// on disk and must NOT produce an edge or an error.
	wantChildren := map[string]string{
		"com.example:http-client": "4.5.13",
		"com.example:logging-api": "2.17.1",
		"com.example:cache-lib":   "3.0.0",
	}

	gotChildren := map[string]string{}
	for _, e := range edges {
		gotChildren[e.ChildName] = e.ChildVersion
	}
	for want, wantVer := range wantChildren {
		gotVer, ok := gotChildren[want]
		if !ok {
			t.Errorf("missing reactor edge: child %q (want version %q); all edges=%+v", want, wantVer, edges)
			continue
		}
		if gotVer != wantVer {
			t.Errorf("reactor edge %q: version=%q want %q", want, gotVer, wantVer)
		}
	}

	// Edge attribution: api → http-client must list api as the parent
	// module, not the reactor root.  This proves the walker preserves
	// which module introduced the dep.
	wantParents := map[string]string{
		"com.example:http-client": "com.example.reactor:api",
		"com.example:logging-api": "com.example.reactor:core",
		"com.example:cache-lib":   "com.example.reactor:core",
	}
	for child, wantParent := range wantParents {
		for _, e := range edges {
			if e.ChildName != child {
				continue
			}
			if e.ParentName != wantParent {
				t.Errorf("reactor edge %q: parent=%q want %q (full edge: %+v)", child, e.ParentName, wantParent, e)
			}
			if e.Type != "direct" {
				t.Errorf("reactor edge %q: type=%q want %q (reactor module deps surface as direct edges)", child, e.Type, "direct")
			}
			if !e.Resolved {
				t.Errorf("reactor edge %q: Resolved=false; child-module direct deps with explicit versions should resolve", child)
			}
		}
	}

	// IntroducedByPath must trace [reactor-root, module] for each
	// child-module edge — operators rely on this path to see "which
	// module brought this dep in?"
	wantPaths := map[string][]string{
		"com.example:http-client": {"com.example.reactor:my-reactor", "com.example.reactor:api"},
		"com.example:logging-api": {"com.example.reactor:my-reactor", "com.example.reactor:core"},
		"com.example:cache-lib":   {"com.example.reactor:my-reactor", "com.example.reactor:core"},
	}
	for child, wantPath := range wantPaths {
		for _, e := range edges {
			if e.ChildName != child {
				continue
			}
			gotPath := append([]string{}, e.IntroducedByPath...)
			// Last element is the child itself; assert the prefix.
			if len(gotPath) < 2 {
				t.Errorf("reactor edge %q: IntroducedByPath too short %v", child, gotPath)
				continue
			}
			prefix := gotPath[:2]
			if !equalStrings(prefix, wantPath) {
				t.Errorf("reactor edge %q: IntroducedByPath prefix=%v want %v", child, prefix, wantPath)
			}
		}
	}

	// The missing module ("missing") must not appear anywhere — it has
	// no pom on disk so the walker must skip it silently.
	for _, e := range edges {
		if e.ParentName == "com.example.reactor:missing" {
			t.Errorf("missing-module edge leaked into output: %+v", e)
		}
	}
}

// TestParseMavenPom_reactorEmptyModuleListIsNoOp guards against a
// regression where a reactor with no actual modules entries still tries
// to walk the filesystem.  The simple fixture has no <modules>, so the
// walker should behave exactly as before (no extra edges, no errors).
func TestParseMavenPom_reactorEmptyModuleListIsNoOp(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "maven", "simple")
	m2Dir := filepath.Join(fixtureDir, ".m2", "repository")
	edges, err := ParseMavenPom(filepath.Join(fixtureDir, "pom.xml"), m2Dir)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Errorf("expected 2 edges (1 direct + 1 transitive) for non-reactor simple pom, got %d: %+v", len(edges), edges)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortStrings is used internally to compare unordered slices in error msgs.
//
//nolint:unused // kept for clearer assertions if more comparisons are added.
func sortStrings(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}
