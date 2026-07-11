package deptree

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParsePnpmLock_negativeInputs feeds malformed, truncated, wrong-typed, and
// deeply-nested pnpm-lock.yaml bytes to the parser and asserts it degrades
// gracefully — no panic, and either a returned error or a contract-valid
// (possibly empty) edge slice. A pnpm-lock.yaml is attacker-influenceable (it
// sits in a scanned project tree), so a crash here is a fleet-wide scan DoS.
func TestParsePnpmLock_negativeInputs(t *testing.T) {
	// Deeply-nested flow sequence under an ignored key — must not blow the
	// stack; yaml.v3 handles this iteratively and returns cleanly.
	const depth = 2000
	deepNested := "importers:\n  x: " + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "\n"

	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t\n"},
		{"truncated yaml mapping", "importers:\n  .:\n    dependencies:\n      express:"},
		{"truncated mid-key", "lockfileVersion: '6.0'\nimporters:\n  ."},
		{"wrong-typed importers (list)", "importers:\n  - a\n  - b\n"},
		{"wrong-typed dependencies (scalar)", "importers:\n  .:\n    dependencies: notamap\n"},
		{"wrong-typed packages (scalar)", "packages: 12345\n"},
		{"missing importers and packages", "lockfileVersion: '9.0'\n"},
		{"empty object", "{}\n"},
		{"garbage tokens", ":::\n\t@@@\n- - -\n"},
		{"control bytes", "\x00\x01\x02importers:\x00\n"},
		{"tab-indented (yaml-illegal)", "importers:\n\t.:\n\t\tdependencies: {}\n"},
		{"deeply nested", deepNested},
		{"unterminated flow", "importers:\n  .: [dependencies\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pnpm-lock.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			// The bare call must not panic. If it returns edges, they must
			// still satisfy the structural per-edge contract.
			edges, err := ParsePnpmLock(path)
			if err != nil {
				return // a clean error is an acceptable outcome
			}
			assertEdgeStructInvariants(t, edges, "pnpm-negative/"+tc.name)
		})
	}
}

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

// TestParsePnpmLock_v9_snapshotsTransitive proves the pnpm >=9 layout
// is parsed: dependency lists live under top-level `snapshots:` (the
// `packages:` block holds only resolution metadata).  Before the fix
// this yielded 0 transitive edges because pnpmLock only read
// `packages:`.
func TestParsePnpmLock_v9_snapshotsTransitive(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v9", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	var transitives int
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
		if e.Type == "transitive" {
			transitives++
		}
	}
	if transitives == 0 {
		t.Fatalf("expected transitive edges from pnpm v9 snapshots, got 0: %+v", edges)
	}
	// express -> qs (depth 2) and qs -> side-channel (depth 3).
	qs, ok := byChild["qs"]
	if !ok || qs.ParentName != "express" || qs.Type != "transitive" || qs.Depth != 2 {
		t.Errorf("expected express->qs transitive at depth 2, got %+v", qs)
	}
	sc, ok := byChild["side-channel"]
	if !ok || sc.ParentName != "qs" || sc.Type != "transitive" || sc.Depth != 3 {
		t.Errorf("expected qs->side-channel transitive at depth 3, got %+v", sc)
	}
}

// TestParsePnpmLock_v6_legacyPackagesBlock keeps the old v5/v6 layout
// (deps inline under `packages:`) working after the v9 fix.
func TestParsePnpmLock_v6_legacyPackagesBlock(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v6", "pnpm-lock.yaml"))
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
		}
	}
	if transitive == nil || transitive.ParentName != "express" || transitive.ChildName != "qs" || transitive.Depth != 2 {
		t.Errorf("legacy v6 transitive edge wrong: %+v", transitive)
	}
}

// TestParsePnpmLock_v5_slashKeys proves lockfileVersion 5.x keys — which
// separate name from version with '/' ("/express/4.18.2") rather than
// '@' — are parsed and their transitive edges emitted.  Before the fix
// pnpmKeyParts split only on '@', so a 5.x key parsed to name
// "express/4.18.2" with an empty version, matched no adjacency entry,
// and EVERY 5.x transitive edge silently vanished.
func TestParsePnpmLock_v5_slashKeys(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v5", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (express direct + express->qs transitive), got %d: %+v", len(edges), edges)
	}
	var direct, transitive *DepEdge
	for i := range edges {
		switch edges[i].Type {
		case "direct":
			direct = &edges[i]
		case "transitive":
			transitive = &edges[i]
		}
	}
	if direct == nil || direct.ChildName != "express" || direct.ChildVersion != "4.18.2" {
		t.Errorf("direct edge wrong: %+v", direct)
	}
	if transitive == nil {
		t.Fatalf("no transitive edge emitted from v5 lockfile — 5.x edges vanished")
	}
	if transitive.ParentName != "express" || transitive.ParentVersion != "4.18.2" ||
		transitive.ChildName != "qs" || transitive.ChildVersion != "6.11.0" || transitive.Depth != 2 {
		t.Errorf("v5 transitive edge wrong: %+v", transitive)
	}
}

// TestParsePnpmLock_multiVersionRetained proves the graph keeps DISTINCT
// versions of the same package instead of collapsing them to one
// name-keyed node.  Fixture: alpha->lodash@4.17.20 and beta->lodash@4.17.21.
// The buggy parser keyed depGraph/versionByName on the bare name, so both
// edges emitted whichever version won the non-deterministic map-iteration
// race.  A correct graph carries BOTH versions on their respective edges.
func TestParsePnpmLock_multiVersionRetained(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-multiversion", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	alphaLodash, ok := byEdge[key{"alpha", "lodash"}]
	if !ok {
		t.Fatalf("alpha->lodash edge missing; edges=%+v", edges)
	}
	if alphaLodash.ChildVersion != "4.17.20" || alphaLodash.Type != "transitive" || alphaLodash.Depth != 2 {
		t.Errorf("alpha->lodash wrong (want 4.17.20 transitive depth 2): %+v", alphaLodash)
	}

	betaLodash, ok := byEdge[key{"beta", "lodash"}]
	if !ok {
		t.Fatalf("beta->lodash edge missing (multi-version collapse); edges=%+v", edges)
	}
	if betaLodash.ChildVersion != "4.17.21" || betaLodash.Type != "transitive" || betaLodash.Depth != 2 {
		t.Errorf("beta->lodash wrong (want 4.17.21 transitive depth 2): %+v", betaLodash)
	}

	// Both distinct versions must appear across all lodash edges.
	versions := map[string]bool{}
	for _, e := range edges {
		if e.ChildName == "lodash" {
			versions[e.ChildVersion] = true
		}
	}
	if !versions["4.17.20"] || !versions["4.17.21"] {
		t.Errorf("expected both lodash versions retained, got %v", versions)
	}

	// Determinism: re-parsing must yield byte-identical edge ordering.
	for i := 0; i < 5; i++ {
		again, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-multiversion", "pnpm-lock.yaml"))
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		if len(again) != len(edges) {
			t.Fatalf("edge count non-deterministic: %d vs %d", len(again), len(edges))
		}
		for j := range again {
			if again[j].ParentName != edges[j].ParentName ||
				again[j].ParentVersion != edges[j].ParentVersion ||
				again[j].ChildName != edges[j].ChildName ||
				again[j].ChildVersion != edges[j].ChildVersion {
				t.Fatalf("edge order non-deterministic at %d: %+v vs %+v", j, again[j], edges[j])
			}
		}
	}
}

// TestParsePnpmLock_rootOptionalDependencies proves the ROOT importer's
// optionalDependencies are seeded as declared directs alongside
// dependencies/devDependencies — so a package reachable ONLY through the
// root's optionalDependencies (and its whole subtree) is not dropped.
// Fixture: root deps=express, root optionalDependencies=sharp;
// sharp -> detect-libc. Before the fix the sharp subtree vanished because
// only Dependencies/DevDependencies were seeded into the BFS.
func TestParsePnpmLock_rootOptionalDependencies(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v9-optional", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	// Root optionalDependencies emitted as an "optional" direct at depth 1.
	optEdge, ok := byEdge[key{"(root)", "sharp"}]
	if !ok {
		t.Fatalf("root->sharp optional direct edge missing; edges=%+v", edges)
	}
	if optEdge.Type != "optional" || optEdge.ChildVersion != "0.32.6" || optEdge.Depth != 1 {
		t.Errorf("root->sharp wrong (want optional 0.32.6 depth 1): %+v", optEdge)
	}

	// The subtree under the optional dep must be reachable in the BFS.
	subEdge, ok := byEdge[key{"sharp", "detect-libc"}]
	if !ok {
		t.Fatalf("sharp->detect-libc subtree edge missing — root optionalDependencies subtree dropped; edges=%+v", edges)
	}
	if subEdge.Type != "transitive" || subEdge.ChildVersion != "2.0.2" || subEdge.Depth != 2 {
		t.Errorf("sharp->detect-libc wrong (want transitive 2.0.2 depth 2): %+v", subEdge)
	}
}

// TestParsePnpmLock_workspaceMembers proves that a pnpm workspace
// monorepo seeds the BFS from EVERY importer, not just ".".  Before the
// fix only lock.Importers["."] was seeded, so non-root members
// (packages/api, packages/web) and their whole transitive closure were
// dropped.  Fixture: root "." devDependencies=typescript;
// packages/api->express->qs; packages/web->react->loose-envify.  Members
// are anchored at [root, member] (depth 1), so their declared deps
// surface at depth 2 (transitive) and deeper deps at depth 3.
func TestParsePnpmLock_workspaceMembers(t *testing.T) {
	const root = "(root)"
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-workspace", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	// Contract invariants on EVERY emitted edge.
	for _, e := range edges {
		if e.Depth != len(e.IntroducedByPath)-1 {
			t.Errorf("depth != len(path)-1: %+v", e)
		}
		if len(e.IntroducedByPath) < 2 || e.IntroducedByPath[0] != root {
			t.Errorf("path not root-anchored: %+v", e)
		}
		if e.IntroducedByPath[len(e.IntroducedByPath)-1] != e.ChildName {
			t.Errorf("path does not end at child: %+v", e)
		}
		if e.Depth == 1 && e.Type == "transitive" {
			t.Errorf("depth-1 edge must not be transitive: %+v", e)
		}
		if e.Depth >= 2 && e.Type != "transitive" {
			t.Errorf("depth>=2 edge must be transitive: %+v", e)
		}
	}

	// Root "." direct (dev) still emitted at depth 1 — root semantics kept.
	if ts, ok := byEdge[key{root, "typescript"}]; !ok {
		t.Errorf("root->typescript dev direct missing; edges=%+v", edges)
	} else if ts.Type != "dev" || ts.ChildVersion != "5.4.5" || ts.Depth != 1 {
		t.Errorf("root->typescript wrong (want dev 5.4.5 depth 1): %+v", ts)
	}

	// Member packages/api: its declared dep express at depth 2, and
	// express's transitive qs at depth 3.
	api, ok := byEdge[key{"packages/api", "express"}]
	if !ok {
		t.Fatalf("packages/api->express edge missing — non-root member dropped; edges=%+v", edges)
	}
	if api.Type != "transitive" || api.ChildVersion != "4.18.2" || api.Depth != 2 {
		t.Errorf("packages/api->express wrong (want transitive 4.18.2 depth 2): %+v", api)
	}
	if got, want := api.IntroducedByPath, []string{root, "packages/api", "express"}; !pathEqual(got, want) {
		t.Errorf("packages/api->express path = %v, want %v", got, want)
	}
	qs, ok := byEdge[key{"express", "qs"}]
	if !ok {
		t.Fatalf("express->qs edge missing — member transitive closure dropped; edges=%+v", edges)
	}
	if qs.Depth != 3 || qs.Type != "transitive" {
		t.Errorf("express->qs wrong (want transitive depth 3): %+v", qs)
	}
	if got, want := qs.IntroducedByPath, []string{root, "packages/api", "express", "qs"}; !pathEqual(got, want) {
		t.Errorf("express->qs path = %v, want %v", got, want)
	}

	// Member packages/web: react at depth 2, loose-envify at depth 3.
	web, ok := byEdge[key{"packages/web", "react"}]
	if !ok {
		t.Fatalf("packages/web->react edge missing; edges=%+v", edges)
	}
	if web.Type != "transitive" || web.ChildVersion != "18.2.0" || web.Depth != 2 {
		t.Errorf("packages/web->react wrong (want transitive 18.2.0 depth 2): %+v", web)
	}
	le, ok := byEdge[key{"react", "loose-envify"}]
	if !ok {
		t.Fatalf("react->loose-envify edge missing; edges=%+v", edges)
	}
	if le.Depth != 3 || le.Type != "transitive" {
		t.Errorf("react->loose-envify wrong (want transitive depth 3): %+v", le)
	}
}

// TestParsePnpmLock_transitiveOptionalDependencies proves a TRANSITIVE
// package's optionalDependencies (recorded under optionalDependencies in
// the snapshot/packages entry) are folded into the graph.  Before the fix
// pnpmPackageEntry read only Dependencies, so an optional transitive dep
// (e.g. express optionally pulling fsevents) and its subtree vanished.
func TestParsePnpmLock_transitiveOptionalDependencies(t *testing.T) {
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", "pnpm-v9-transitive-optional", "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	type key struct{ parent, child string }
	byEdge := map[key]DepEdge{}
	for _, e := range edges {
		byEdge[key{e.ParentName, e.ChildName}] = e
	}

	// express is a root direct at depth 1.
	if ex, ok := byEdge[key{"(root)", "express"}]; !ok {
		t.Fatalf("root->express direct missing; edges=%+v", edges)
	} else if ex.Type != "direct" || ex.Depth != 1 {
		t.Errorf("root->express wrong (want direct depth 1): %+v", ex)
	}

	// express's OPTIONAL transitive dep fsevents must be emitted.
	fse, ok := byEdge[key{"express", "fsevents"}]
	if !ok {
		t.Fatalf("express->fsevents edge missing — transitive optionalDependencies dropped; edges=%+v", edges)
	}
	if fse.Type != "transitive" || fse.ChildVersion != "2.3.3" || fse.Depth != 2 {
		t.Errorf("express->fsevents wrong (want transitive 2.3.3 depth 2): %+v", fse)
	}

	// And fsevents's own subtree is reachable through the optional edge.
	ngb, ok := byEdge[key{"fsevents", "node-gyp-build"}]
	if !ok {
		t.Fatalf("fsevents->node-gyp-build edge missing — optional subtree dropped; edges=%+v", edges)
	}
	if ngb.Type != "transitive" || ngb.Depth != 3 {
		t.Errorf("fsevents->node-gyp-build wrong (want transitive depth 3): %+v", ngb)
	}
}

// TestParsePnpmLock_v9PeerContextUnion proves that when pnpm >= 9 records the
// SAME concrete package (foo@1.0.0) under multiple snapshot keys that differ
// only by peer context — foo@1.0.0(react@17.0.0) vs foo@1.0.0(react@18.0.0),
// each with a DIFFERENT resolved child set — the peer-stripped node's adjacency
// is the deterministic UNION of every context's children, and the emitted edges
// are byte-identical across repeated parses.  Before the fix the adjacency was
// overwritten by whichever snapshot key won Go's non-deterministic map
// iteration, so the same lockfile yielded different edges across runs.
func TestParsePnpmLock_v9PeerContextUnion(t *testing.T) {
	const fixture = "pnpm-v9-peer-context"
	edges, err := ParsePnpmLock(filepath.Join("testdata", "npm", fixture, "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Collect foo's children (name@version) across all emitted edges.
	fooChildren := map[string]bool{}
	for _, e := range edges {
		if e.ParentName == "foo" && e.ParentVersion == "1.0.0" {
			if e.Type != "transitive" {
				t.Errorf("foo->%s must be transitive, got %q: %+v", e.ChildName, e.Type, e)
			}
			fooChildren[e.ChildName+"@"+e.ChildVersion] = true
		}
	}

	// The union of both peer contexts: bar (17-only), baz (18-only), common
	// (shared, deduped to one), and BOTH react versions (lossless — a child
	// resolved to different versions under each context keeps both nodes).
	wantChildren := []string{
		"bar@1.0.0",
		"baz@2.0.0",
		"common@3.0.0",
		"react@17.0.0",
		"react@18.0.0",
	}
	for _, w := range wantChildren {
		if !fooChildren[w] {
			t.Errorf("union missing foo child %q; got %v; edges=%+v", w, fooChildren, edges)
		}
	}
	if len(fooChildren) != len(wantChildren) {
		t.Errorf("foo children = %v, want exactly %v", fooChildren, wantChildren)
	}

	// Determinism: re-parse N times and assert byte-identical edge ordering,
	// the exact reproducibility guarantee the concrete-node keying promises.
	for i := 0; i < 20; i++ {
		again, err := ParsePnpmLock(filepath.Join("testdata", "npm", fixture, "pnpm-lock.yaml"))
		if err != nil {
			t.Fatalf("re-parse %d failed: %v", i, err)
		}
		if len(again) != len(edges) {
			t.Fatalf("edge count non-deterministic on run %d: %d vs %d", i, len(again), len(edges))
		}
		for j := range again {
			a, b := again[j], edges[j]
			if a.ParentName != b.ParentName || a.ParentVersion != b.ParentVersion ||
				a.ChildName != b.ChildName || a.ChildVersion != b.ChildVersion ||
				a.Type != b.Type || a.Depth != b.Depth || !pathEqual(a.IntroducedByPath, b.IntroducedByPath) {
				t.Fatalf("edge non-deterministic on run %d at index %d:\n got  %+v\n want %+v",
					i, j, a, b)
			}
		}
	}
}

func pathEqual(a, b []string) bool {
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

func TestPnpmKeyParts(t *testing.T) {
	cases := map[string][2]string{
		"/foo@1.0.0":             {"foo", "1.0.0"},
		"/@scope/foo@1.0.0":      {"@scope/foo", "1.0.0"},
		"foo@2.3.4":              {"foo", "2.3.4"},
		"/foo@1.0.0(peer@2.0.0)": {"foo", "1.0.0"},
		// pnpm 5.x '/'-separated keys.
		"/express/4.18.2":   {"express", "4.18.2"},
		"/@scope/foo/1.0.0": {"@scope/foo", "1.0.0"},
		// pnpm 5.x UNDERSCORE peer-context suffix ("name/version_peer@x").
		// The peer's own '@version' must not hijack the split; the version
		// is cut at the first '_' after the name/version '/' separator.
		"/react-dom/16.13.1_react@16.13.1":         {"react-dom", "16.13.1"},
		"/@scope/pkg/1.0.0_peer@2.0.0":             {"@scope/pkg", "1.0.0"},
		"/@scope/pkg/1.0.0_@peerscope/peer@2.0.0":  {"@scope/pkg", "1.0.0"},
		"/react-dom/16.13.1_react@16.13.1_vue@3.0": {"react-dom", "16.13.1"},
		// An underscore inside the package NAME (a real npm shape,
		// e.g. lodash._baseassign) sits before the separator and must be
		// preserved — both in v5 '/'-separated and v9 '@'-separated keys.
		"/lodash._baseassign/4.0.0": {"lodash._baseassign", "4.0.0"},
		"lodash._baseassign@4.0.0":  {"lodash._baseassign", "4.0.0"},
		// A scoped package whose name part starts with a digit must still
		// split on the version '@', not on the intra-name '/'.
		"/@scope/2fa@1.0.0": {"@scope/2fa", "1.0.0"},
	}
	for in, want := range cases {
		name, ver := pnpmKeyParts(in)
		if name != want[0] || ver != want[1] {
			t.Errorf("pnpmKeyParts(%q) = (%q, %q), want (%q, %q)", in, name, ver, want[0], want[1])
		}
	}
}
