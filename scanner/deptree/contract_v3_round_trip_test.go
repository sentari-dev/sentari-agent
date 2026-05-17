package deptree

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// TestContractV3_payloadValidatesAgainstSharedSchema is the contract
// drift guard for the v3 agent scan payload.
//
// It constructs one instance of each new field type (DepEdge,
// LockfileMeta, SupplyChainSignal, LicenseEvidence), marshals to
// JSON via the same struct tags the agent uses on the wire, and
// validates the resulting document against
// docs/contracts/agent-scan-payload-v3.json.
//
// If a struct tag in scanner/deptree/types.go is ever renamed,
// dropped, or has its JSON shape diverge from the shared schema,
// this test fails immediately rather than producing payloads that
// the server's v3 ingest path quietly rejects.
func TestContractV3_payloadValidatesAgainstSharedSchema(t *testing.T) {
	// Test runs from scanner/deptree → go up two levels to repo root,
	// then into docs/contracts.
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "docs", "contracts", "agent-scan-payload-v3.json"))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}

	payload := map[string]interface{}{
		"dep_edges": []DepEdge{
			{
				ParentName:       "myapp",
				ParentVersion:    "1.0.0",
				ChildName:        "express",
				ChildVersion:     "4.18.2",
				Ecosystem:        "npm",
				Type:             "direct",
				Scope:            "runtime",
				Depth:            1,
				IntroducedByPath: []string{"myapp", "express"},
				Resolved:         true,
			},
		},
		"lockfiles": []LockfileMeta{
			{
				Path:                  "/srv/app/package-lock.json",
				Format:                "package_lock_v3",
				Ecosystem:             "npm",
				SHA256:                "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4",
				LastModified:          mustParseTime("2026-05-15T10:00:00Z"),
				DeclaredPackagesCount: 247,
				DriftStatus:           "unknown",
			},
		},
		"supply_chain_signals": []SupplyChainSignal{
			{
				PackageName:    "express",
				PackageVersion: "4.18.2",
				Ecosystem:      "npm",
				SignalType:     "postinstall_script",
				Severity:       "info",
				Source:         "agent-npm-scripts",
				Raw: map[string]interface{}{
					"script_body": "node prepare.js",
				},
			},
		},
		"license_evidence": []LicenseEvidence{
			{
				PackageName:    "express",
				PackageVersion: "4.18.2",
				Ecosystem:      "npm",
				SpdxID:         "MIT",
				Source:         "spdx_pkg",
				Confidence:     0.95,
				RawText:        "MIT",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal for validation: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("payload failed schema validation: %v\npayload: %s", err, string(body))
	}
}

func mustParseTime(s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return tm
}
