package deptree

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestSafePath_returnsPathWhenLongEnough(t *testing.T) {
	got := SafePath([]string{"root", "mid", "leaf"}, "p", "c")
	if len(got) != 3 || got[0] != "root" {
		t.Fatalf("SafePath should return precomputed path unchanged; got %v", got)
	}
}

func TestSafePath_fallsBackOnNilOrShortPath(t *testing.T) {
	cases := []struct {
		name string
		in   []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"single", []string{"only"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SafePath(c.in, "myparent", "mychild")
			if len(got) != 2 || got[0] != "myparent" || got[1] != "mychild" {
				t.Fatalf("expected [myparent, mychild] fallback; got %v", got)
			}
		})
	}
}

// TestContractV3_nilIntroducedByPath_failsSchemaValidation is the
// regression guard for the 2026-05-20 walkthrough finding: an agent
// emitted ``introduced_by_path: null`` for orphaned dep_edges and the
// server rejected the whole payload with HTTP 422.  After SafePath, no
// emitter can produce a nil/empty path; this test exists so the schema
// itself stays the hard contract.  If anyone relaxes ``minItems: 2``
// or adds an emitter that bypasses SafePath, this test goes red.
func TestContractV3_nilIntroducedByPath_failsSchemaValidation(t *testing.T) {
	schemaPath := mustResolveSchemaPath(t)
	schema, err := jsonschema.NewCompiler().Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	// Construct an edge whose IntroducedByPath is nil — the exact shape
	// the orphan emitters used to produce.  json.Marshal turns nil
	// slices into ``null``, so this exercises both the JSON encoding
	// behaviour and the schema's strictness in one go.
	payload := map[string]any{
		"dep_edges": []DepEdge{
			{
				ParentName:       "myapp",
				ParentVersion:    "1.0.0",
				ChildName:        "orphan",
				ChildVersion:     "0.1.0",
				Ecosystem:        "pypi",
				Type:             "transitive",
				Scope:            "",
				Depth:            2,
				IntroducedByPath: nil,
				Resolved:         true,
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal for validation: %v", err)
	}
	if err := schema.Validate(doc); err == nil {
		t.Fatalf("schema accepted nil introduced_by_path — regression: "+
			"either minItems was relaxed or DepEdge no longer marshals nil as null. payload: %s", body)
	}
}

// TestContractV3_safePathOutput_validatesAgainstSchema covers the
// positive case: an edge whose IntroducedByPath went through SafePath
// (so falls back to the minimal 2-element chain) MUST pass schema
// validation.  Pairs with the nil-rejection test above.
func TestContractV3_safePathOutput_validatesAgainstSchema(t *testing.T) {
	schemaPath := mustResolveSchemaPath(t)
	schema, err := jsonschema.NewCompiler().Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	payload := map[string]any{
		"dep_edges": []DepEdge{
			{
				ParentName:       "myapp",
				ParentVersion:    "1.0.0",
				ChildName:        "orphan",
				ChildVersion:     "0.1.0",
				Ecosystem:        "pypi",
				Type:             "transitive",
				Scope:            "",
				Depth:            2,
				IntroducedByPath: SafePath(nil, "myapp", "orphan"),
				Resolved:         true,
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal for validation: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("schema rejected SafePath fallback (expected to pass): %v\npayload: %s", err, body)
	}
}

// TestBuildPypiEdges_orphanParent_emitsValidPath exercises the BFS
// path-lookup site that produced the 2,749 nil paths on the
// walkthrough Mac: a parent in ``pkgs`` whose dependency chain never
// originates from the rootName.  Before the SafePath fix this
// returned an edge with IntroducedByPath=nil.
func TestBuildPypiEdges_orphanParent_emitsValidPath(t *testing.T) {
	pkgs := map[string]pypiPkgInfo{
		"app":    {version: "1.0", deps: []string{"reachable"}},
		"reachable":  {version: "2.0", deps: nil},
		// Orphan: not reachable from "app" via BFS, but listed as a parent.
		"orphan-parent": {version: "9.9", deps: []string{"orphan-child"}},
		"orphan-child":  {version: "0.1", deps: nil},
	}
	edges := buildPypiEdges(pkgs, "app", "1.0")
	for _, e := range edges {
		if len(e.IntroducedByPath) < 2 {
			t.Fatalf(
				"edge %s->%s emitted introduced_by_path with <2 entries: %v",
				e.ParentName, e.ChildName, e.IntroducedByPath,
			)
		}
	}
}

func mustResolveSchemaPath(t *testing.T) string {
	t.Helper()
	// Walk up from the test file to find docs/contracts/.  The test
	// runs from scanner/deptree, so two levels up is the repo root.
	candidate := strings.Join([]string{"..", "..", "docs", "contracts", "agent-scan-payload-v3.json"}, "/")
	return candidate
}
