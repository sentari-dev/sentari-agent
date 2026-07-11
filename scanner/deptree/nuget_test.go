package deptree

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseNuGetProjectAssets_negativeInputs feeds malformed, truncated,
// wrong-typed, and deeply-nested project.assets.json bytes to the parser and
// asserts graceful degradation — no panic, and either a returned error or a
// contract-valid (possibly empty) edge slice. project.assets.json is
// attacker-influenceable (it sits in a scanned project tree after `dotnet
// restore`), so a crash here is a fleet-wide scan DoS.
func TestParseNuGetProjectAssets_negativeInputs(t *testing.T) {
	// Deeply-nested array under an ignored key — must not blow the stack;
	// encoding/json handles nesting iteratively and errors past its guard.
	const depth = 2000
	deepNested := `{"x":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`

	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t"},
		{"truncated object", `{"targets":`},
		{"truncated mid-string", `{"project":{"restore":{"projectName":"foo`},
		{"wrong-typed targets (string)", `{"targets":"nope"}`},
		{"wrong-typed targets (array)", `{"targets":[1,2,3]}`},
		{"wrong-typed target entry", `{"targets":{"net6.0":{"A/1.0":"scalar"}}}`},
		{"wrong-typed dependencies", `{"targets":{"net6.0":{"A/1.0":{"type":"package","dependencies":"x"}}}}`},
		{"missing targets and project", `{}`},
		{"null targets", `{"targets":null,"project":null}`},
		{"target key missing slash", `{"targets":{"net6.0":{"NoSlashKey":{"type":"package"}}}}`},
		{"json array top-level", `[1,2,3]`},
		{"json scalar top-level", `"just a string"`},
		{"garbage bytes", "\x00\x01not json{{{"},
		{"deeply nested", deepNested},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "project.assets.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			edges, err := ParseNuGetProjectAssets(path)
			if err != nil {
				return // a clean error is an acceptable outcome
			}
			assertEdgeStructInvariants(t, edges, "nuget-negative/"+tc.name)
		})
	}
}

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

// TestParseNuGetProjectAssets_realMonikers exercises the real shape a
// `dotnet restore` produces: `targets` keyed by the LONG framework
// moniker (".NETCoreApp,Version=v6.0/win-x64", RID suffix included)
// while `project.frameworks` is keyed by the SHORT TFM ("net6.0").
// Before normalizeTFM, the targets→frameworks correlation missed, directs
// resolved to empty, the BFS was seeded with nothing, and every edge was
// dropped as unreachable — an empty graph for essentially every real
// .NET project. This asserts a populated graph with correct direct /
// transitive depths, root-anchored paths, and a normalized Scope.
func TestParseNuGetProjectAssets_realMonikers(t *testing.T) {
	edges, err := ParseNuGetProjectAssets(filepath.Join("testdata", "nuget", "real-monikers", "project.assets.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 4 {
		t.Fatalf("expected 4 edges (2 direct + 2 transitive), got %d: %+v", len(edges), edges)
	}

	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
		if e.Scope != "net6.0" {
			t.Errorf("edge %s: Scope=%q, want normalized %q", e.ChildName, e.Scope, "net6.0")
		}
		if e.Ecosystem != "nuget" || !e.Resolved {
			t.Errorf("edge %s: unexpected ecosystem/resolved: %+v", e.ChildName, e)
		}
		// Per-edge path/depth contract: node at depth N has an
		// (N+1)-element root-anchored path.
		if e.Depth != len(e.IntroducedByPath)-1 {
			t.Errorf("edge %s->%s: Depth=%d but len(path)=%d: %+v",
				e.ParentName, e.ChildName, e.Depth, len(e.IntroducedByPath), e)
		}
		if len(e.IntroducedByPath) < 2 || e.IntroducedByPath[0] != "RealNetApp" {
			t.Errorf("edge %s: path not root-anchored: %+v", e.ChildName, e.IntroducedByPath)
		}
	}

	// Directs at depth 1, anchored directly under the root.
	for _, name := range []string{"Serilog", "Newtonsoft.Json"} {
		d, ok := byChild[name]
		if !ok || d.Type != "direct" || d.Depth != 1 || d.ParentName != "RealNetApp" {
			t.Errorf("direct edge %s wrong: %+v", name, d)
		}
	}

	// Transitives at depth 2, each anchored via its introducing direct.
	sc, ok := byChild["Serilog.Sinks.Console"]
	if !ok || sc.Type != "transitive" || sc.ParentName != "Serilog" || sc.Depth != 2 ||
		sc.ChildVersion != "5.0.1" ||
		!pathEqual(sc.IntroducedByPath, []string{"RealNetApp", "Serilog", "Serilog.Sinks.Console"}) {
		t.Errorf("transitive edge Serilog.Sinks.Console wrong: %+v", sc)
	}
	cs, ok := byChild["Microsoft.CSharp"]
	if !ok || cs.Type != "transitive" || cs.ParentName != "Newtonsoft.Json" || cs.Depth != 2 ||
		cs.ChildVersion != "4.7.0" ||
		!pathEqual(cs.IntroducedByPath, []string{"RealNetApp", "Newtonsoft.Json", "Microsoft.CSharp"}) {
		t.Errorf("transitive edge Microsoft.CSharp wrong: %+v", cs)
	}
}

func TestNormalizeTFM(t *testing.T) {
	cases := map[string]string{
		".NETCoreApp,Version=v6.0":         "net6.0",
		".NETCoreApp,Version=v8.0":         "net8.0",
		".NETCoreApp,Version=v6.0/win-x64": "net6.0",
		".NETFramework,Version=v4.7.2":     "net472",
		".NETFramework,Version=v4.8":       "net48",
		".NETStandard,Version=v2.0":        "netstandard2.0",
		".NETStandard,Version=v2.1/linux":  "netstandard2.1",
		"net6.0":                           "net6.0",
	}
	for in, want := range cases {
		if got := normalizeTFM(in); got != want {
			t.Errorf("normalizeTFM(%q) = %q, want %q", in, got, want)
		}
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

// TestParseNuGetPackagesLock_depthPathConsistency guards against the
// packages.lock.json transitive branch emitting a Depth that disagrees
// with len(IntroducedByPath).  By convention a node at depth N has a
// path of N+1 entries (root..node).  packages.lock.json carries no
// parent info, so transitives are modelled as depth-1 children of the
// synthetic "(unknown)" root → a 2-element path.
func TestParseNuGetPackagesLock_depthPathConsistency(t *testing.T) {
	edges, err := ParseNuGetPackagesLock(filepath.Join("testdata", "nuget", "lock-only", "packages.lock.json"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	for _, e := range edges {
		if e.Depth != len(e.IntroducedByPath)-1 {
			t.Errorf("edge %s->%s: Depth=%d but len(IntroducedByPath)=%d (want Depth == len(path)-1): %+v",
				e.ParentName, e.ChildName, e.Depth, len(e.IntroducedByPath), e)
		}
	}
}
