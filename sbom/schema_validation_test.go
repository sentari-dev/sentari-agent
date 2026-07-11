package sbom

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Why a hand-authored SUBSET schema rather than the upstream CycloneDX / SPDX
// JSON Schemas: the official schemas pull EXTERNAL $ref meta-schemas
// (CycloneDX -> spdx.schema.json + jsf-0.82.schema.json; SPDX -> its own
// referenced defs) that a validator must fetch over the network to resolve.
// That is incompatible with the agent's CGO_ENABLED=0 / air-gap charter, so a
// prior review round evaluated and rejected upstream-schema validation. The
// subset schemas under testdata/schema/ inline no external refs, so
// compilation and validation are fully hermetic (santhosh-tekuri/jsonschema/v5
// serves the draft-07 meta-schema from memory — no network). They assert the
// STRUCTURE the agent emits — a real JSON-Schema gate on the document shape,
// complementing the golden byte-compare (which catches any additive drift).

// compileSubsetSchema compiles a hermetic subset schema from testdata/schema
// with no network access. Draft is pinned to draft-07 so the $schema keyword
// resolves against the validator's built-in meta-schema.
func compileSubsetSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("testdata", "schema", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", name, err)
	}
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	if err := c.AddResource(name, bytes.NewReader(raw)); err != nil {
		t.Fatalf("add schema resource %s: %v", name, err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile schema %s: %v", name, err)
	}
	return sch
}

// validate unmarshals data into the generic form jsonschema expects and runs
// the schema over it, failing the test on any validation error.
func validate(t *testing.T, sch *jsonschema.Schema, data []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal document for validation: %v", err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("document failed schema validation: %v", err)
	}
}

// TestCycloneDXValidatesAgainstSubsetSchema checks the freshly-generated
// CycloneDX document and the checked-in golden fixture both satisfy the
// hermetic CycloneDX 1.6 subset schema.
func TestCycloneDXValidatesAgainstSubsetSchema(t *testing.T) {
	sch := compileSubsetSchema(t, "cyclonedx-1.6-subset.schema.json")

	data, err := GenerateCycloneDX(goldenScanResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	validate(t, sch, data)

	golden, err := os.ReadFile(filepath.Join("testdata", "golden", "cyclonedx_full.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	validate(t, sch, golden)
}

// TestSPDXValidatesAgainstSubsetSchema checks the freshly-generated SPDX
// document and the checked-in golden fixture both satisfy the hermetic SPDX 2.3
// subset schema.
func TestSPDXValidatesAgainstSubsetSchema(t *testing.T) {
	sch := compileSubsetSchema(t, "spdx-2.3-subset.schema.json")

	data, err := GenerateSPDX(goldenScanResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}
	validate(t, sch, data)

	golden, err := os.ReadFile(filepath.Join("testdata", "golden", "spdx_full.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	validate(t, sch, golden)
}

// TestSubsetSchemaRejectsSpecShapeRegressions proves the schema is a real gate,
// not a rubber stamp: documents with a dropped/renamed required field or a
// wrong spec version must FAIL validation. Without these, a subset schema could
// silently pass anything.
func TestSubsetSchemaRejectsSpecShapeRegressions(t *testing.T) {
	cdxSchema := compileSubsetSchema(t, "cyclonedx-1.6-subset.schema.json")
	spdxSchema := compileSubsetSchema(t, "spdx-2.3-subset.schema.json")

	mutate := func(t *testing.T, data []byte, fn func(m map[string]any)) []byte {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("unmarshal for mutation: %v", err)
		}
		fn(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("remarshal mutated doc: %v", err)
		}
		return out
	}

	expectInvalid := func(t *testing.T, sch *jsonschema.Schema, data []byte, label string) {
		t.Helper()
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("unmarshal mutated doc: %v", err)
		}
		if err := sch.Validate(v); err == nil {
			t.Fatalf("%s: mutated document unexpectedly PASSED schema validation", label)
		}
	}

	cdx, err := GenerateCycloneDX(goldenScanResult())
	if err != nil {
		t.Fatalf("GenerateCycloneDX: %v", err)
	}
	spdx, err := GenerateSPDX(goldenScanResult())
	if err != nil {
		t.Fatalf("GenerateSPDX: %v", err)
	}

	// CycloneDX: dropped required top-level field.
	expectInvalid(t, cdxSchema, mutate(t, cdx, func(m map[string]any) {
		delete(m, "components")
	}), "cyclonedx missing components")

	// CycloneDX: wrong spec version (const mismatch).
	expectInvalid(t, cdxSchema, mutate(t, cdx, func(m map[string]any) {
		m["specVersion"] = "1.5"
	}), "cyclonedx wrong specVersion")

	// CycloneDX: a component missing its required "name".
	expectInvalid(t, cdxSchema, mutate(t, cdx, func(m map[string]any) {
		comps, _ := m["components"].([]any)
		if len(comps) == 0 {
			t.Fatal("golden has no components to mutate")
		}
		first, _ := comps[0].(map[string]any)
		delete(first, "name")
	}), "cyclonedx component missing name")

	// SPDX: dropped required top-level field.
	expectInvalid(t, spdxSchema, mutate(t, spdx, func(m map[string]any) {
		delete(m, "packages")
	}), "spdx missing packages")

	// SPDX: wrong spec version (const mismatch).
	expectInvalid(t, spdxSchema, mutate(t, spdx, func(m map[string]any) {
		m["spdxVersion"] = "SPDX-2.2"
	}), "spdx wrong spdxVersion")

	// SPDX: a package missing its required "downloadLocation".
	expectInvalid(t, spdxSchema, mutate(t, spdx, func(m map[string]any) {
		pkgs, _ := m["packages"].([]any)
		if len(pkgs) == 0 {
			t.Fatal("golden has no packages to mutate")
		}
		first, _ := pkgs[0].(map[string]any)
		delete(first, "downloadLocation")
	}), "spdx package missing downloadLocation")
}
