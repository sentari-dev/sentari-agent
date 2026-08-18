package deptree

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/sentari-dev/sentari-agent/scanner/runtimeversions"
)

// agentEmittedRuntimeNames returns every value the agent can place in
// InstalledRuntime.Name, DERIVED from the producing code rather than a
// hand-maintained literal list:
//   - language runtimes (python, node, jdk) from
//     runtimeversions.LanguageRuntimeNames() — the same constants the
//     python.go/python_system.go/node.go/jdk.go detectors emit.
//   - JVM application servers from runtimeversions.AppServerRuntimeNames() —
//     the keys of the appServers map classify() (appserver.go) draws from.
//   - web servers from runtimeversions.WebServerRuntimeNames() — the keys
//     of the webServers map.
//   - message brokers from runtimeversions.BrokerRuntimeNames() — the keys
//     of the brokers map.
//
// Auto-derivation is deliberate: a new runtime name added to the producing
// code automatically enters the schema cross-check below, so a future value
// (as "glassfish" once was) cannot ship unlisted in the shared schema enum
// without failing TestInstalledRuntimeNames_coveredBySchemaEnum.
func agentEmittedRuntimeNames() []string {
	names := append([]string{}, runtimeversions.LanguageRuntimeNames()...)
	names = append(names, runtimeversions.AppServerRuntimeNames()...)
	names = append(names, runtimeversions.WebServerRuntimeNames()...)
	return append(names, runtimeversions.BrokerRuntimeNames()...)
}

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
		// Built from real runtimeversions.InstalledRuntime values (one per
		// name the agent can emit), marshalled through the same struct tags
		// the wire uses — not hand-rolled maps. This guards the struct's
		// JSON shape (name/version/cycle/distro/install_path tags + the
		// distro,omitempty behaviour) against the shared schema.
		"installed_runtimes": realInstalledRuntimes(),
		// os_release + container_targets are declared on scanner.ScanResult
		// (scanner/types.go), but the scanner package imports this package
		// (deptree) so we cannot import scanner here without a cycle. The
		// maps below mirror scanner.OsRelease and
		// scanner.ContainerTargetSummary field-for-field (exact JSON tags),
		// exercising the OsRelease and ContainerTargetSummary schema
		// definitions with a fully-populated instance of each.
		"os_release": map[string]interface{}{
			"id":         "debian",
			"version_id": "12",
		},
		"container_targets": []map[string]interface{}{
			{
				"runtime":        "docker",
				"image_id":       "sha256:abc123",
				"image_tags":     []string{"myapp:1.0.0", "myapp:latest"},
				"container_id":   "c0ffee",
				"container_name": "myapp-web",
				"layer_count":    12,
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

// realInstalledRuntimes builds one fully-populated
// runtimeversions.InstalledRuntime per name the agent can emit, using the
// real Cycle derivation (CycleFor). Language runtimes carry an empty
// Distro (omitted on the wire via omitempty); app servers carry their
// vendor distro. Returned as []runtimeversions.InstalledRuntime so the
// contract test marshals the actual struct, not a stand-in map.
func realInstalledRuntimes() []runtimeversions.InstalledRuntime {
	sample := map[string]struct {
		version string
		distro  string
	}{
		"python":           {"3.11.5", ""},
		"node":             {"20.11.1", ""},
		"jdk":              {"17.0.5", "Temurin"},
		"wildfly":          {"40.0.1.Final", "Red Hat"},
		"jboss-eap":        {"8.0.0.GA", "Red Hat"},
		"tomcat":           {"10.1.20", "Apache"},
		"jetty":            {"12.0.5", "Eclipse"},
		"payara":           {"6.2024.1", "Payara"},
		"glassfish":        {"7.0.11", "Eclipse GlassFish"},
		"weblogic":         {"14.1.1.0", "Oracle"},
		"websphere":        {"unknown", "IBM"},
		"nginx":            {"1.24.0", "nginx"},
		"apache-httpd":     {"2.4.58", "Apache"},
		"iis":              {"10.0", "Microsoft"},
		"rabbitmq":         {"3.12.0", "RabbitMQ"},
		"kafka":            {"3.7.0", "Apache"},
		"activemq":         {"5.18.3", "Apache ActiveMQ"},
		"activemq-artemis": {"2.33.0", "Apache ActiveMQ Artemis"},
	}
	names := agentEmittedRuntimeNames()
	out := make([]runtimeversions.InstalledRuntime, 0, len(names))
	for _, name := range names {
		s := sample[name]
		out = append(out, runtimeversions.InstalledRuntime{
			Name:        name,
			Version:     s.version,
			Cycle:       runtimeversions.CycleFor(name, s.version),
			Distro:      s.distro,
			InstallPath: "/opt/runtimes/" + name,
		})
	}
	return out
}

// TestInstalledRuntimeNames_coveredBySchemaEnum pins the emitted runtime
// NAMES to the schema's name enum. Every value the agent can put in
// InstalledRuntime.Name (see agentEmittedRuntimeNames) must appear in the
// enum at #/definitions/InstalledRuntime/properties/name; otherwise the
// server's v3 ingest would reject a runtime the agent legitimately
// reports. A name the agent emits that the schema lacks is a REAL
// contract drift — the test fails loudly and names the offender rather
// than silently passing.
func TestInstalledRuntimeNames_coveredBySchemaEnum(t *testing.T) {
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "docs", "contracts", "agent-scan-payload-v3.json"))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaPath, err)
	}

	var schema struct {
		Definitions struct {
			InstalledRuntime struct {
				Properties struct {
					Name struct {
						Enum []string `json:"enum"`
					} `json:"name"`
				} `json:"properties"`
			} `json:"InstalledRuntime"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema JSON: %v", err)
	}

	enum := schema.Definitions.InstalledRuntime.Properties.Name.Enum
	if len(enum) == 0 {
		t.Fatal("schema enum for InstalledRuntime.name is empty — schema shape changed?")
	}
	enumSet := make(map[string]struct{}, len(enum))
	for _, e := range enum {
		enumSet[e] = struct{}{}
	}

	var missing []string
	for _, name := range agentEmittedRuntimeNames() {
		if _, ok := enumSet[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		// Loud, actionable failure: these are names the agent emits that
		// the shared schema's enum does not list. The fix belongs in
		// docs/contracts/agent-scan-payload-v3.json (server-owned), not
		// here — do not silently widen the test.
		t.Fatalf("agent emits runtime name(s) missing from schema enum %v: %v\n"+
			"the agent would emit installed_runtimes entries the v3 ingest rejects; "+
			"add them to docs/contracts/agent-scan-payload-v3.json", enum, missing)
	}
}

// agentEmittedSignalTypes enumerates every value the agent can place in
// SupplyChainSignal.SignalType. No exported constants exist for these, so
// the literals are listed here with a pointer at each producing site and
// cross-checked against the schema enum by
// TestConstrainedEnumFields_coveredBySchemaEnum. Keep in sync with
// scanner/supplychain/*.go:
//   - "postinstall_script","preinstall_script","install_script" — npm.go
//     (scriptName+"_script" for scriptName in {postinstall,preinstall,install})
//   - "provenance_attested","unsigned"                          — npm.go
//   - "unsigned"                                                — nuget.go, maven.go
//   - "yanked"                                                  — pypi.go
//   - "maven_checksum_mismatch"                                 — maven_checksum.go
//   - "maven_snapshot_in_release"                               — maven_snapshot.go
//   - "maven_untrusted_repo"                                    — maven_untrusted_repo.go
//
// The remaining schema values (deprecated, maintainer_changed,
// typosquat_suspect, npm/pypi/maven/nuget_malware_advisory) are emitted by
// server-side enrichment only, never by the agent, so they are
// intentionally absent here: this guard asserts every value the AGENT emits
// is present in the schema, not the reverse.
var agentEmittedSignalTypes = []string{
	"postinstall_script",
	"preinstall_script",
	"install_script",
	"provenance_attested",
	"unsigned",
	"yanked",
	"maven_checksum_mismatch",
	"maven_snapshot_in_release",
	"maven_untrusted_repo",
}

// agentEmittedLockfileFormats enumerates every value the agent can place in
// LockfileMeta.Format. Sourced from scanner/lockfiles/discover.go:
//   - the knownLockfiles table: "yarn_v1","pnpm_lock","pom_xml",
//     "packages_lock_json","project_assets_json","poetry_lock","uv_lock",
//     "pipfile_lock","requirements_txt" (and "package_lock_v3" as the table
//     default before version detection)
//   - packageLockFormat(): "package_lock_v2","package_lock_v3" (detected
//     from lockfileVersion at read time)
//   - the yarn-berry probe: "yarn_berry"
//
// This is the full 12-value schema enum — the agent can emit each one.
var agentEmittedLockfileFormats = []string{
	"package_lock_v2",
	"package_lock_v3",
	"yarn_v1",
	"yarn_berry",
	"pnpm_lock",
	"pom_xml",
	"packages_lock_json",
	"project_assets_json",
	"poetry_lock",
	"uv_lock",
	"pipfile_lock",
	"requirements_txt",
}

// agentEmittedDepEdgeTypes enumerates every value the agent can place in
// DepEdge.Type. Sourced from scanner/deptree/*.go:
//   - "direct","transitive"          — every parser (npm/pypi/nuget/maven)
//   - "dev"                          — npm.go (root devDependencies), pypi.go (Pipfile develop)
//   - "peer","optional"              — npm.go (root peer/optional deps)
//
// The schema also lists "test", but the agent never emits it: maven.go skips
// test/provided-scope deps entirely rather than tagging them Type="test".
// Absent-from-this-list is fine — the guard only requires agent-emitted
// values to be in the schema, not that every schema value is emitted.
var agentEmittedDepEdgeTypes = []string{
	"direct",
	"transitive",
	"dev",
	"peer",
	"optional",
}

// agentEmittedLicenseSources enumerates every value the agent can place in
// LicenseEvidence.Source. Sourced from scanner/licenses/*.go:
//   - "spdx_pkg" — npm.go, pypi.go
//   - "trove"    — pypi.go
//   - "pom"      — maven.go
//   - "nuspec"   — nuget.go
//
// The schema also lists "copyright_file","rpm_header","server_enriched",
// which the agent does not currently emit (server-side / reserved). Not
// listing them here is intentional for the same reason as above.
var agentEmittedLicenseSources = []string{
	"spdx_pkg",
	"trove",
	"pom",
	"nuspec",
}

// schemaEnumValues extracts definitions[def].properties[prop].enum from the
// shared v3 schema as a set. It fails the test loudly if the path is missing
// or the enum is empty — either means the schema shape changed and the guard
// below is no longer checking what it claims to.
func schemaEnumValues(t *testing.T, def, prop string) map[string]struct{} {
	t.Helper()
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "docs", "contracts", "agent-scan-payload-v3.json"))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaPath, err)
	}
	var doc struct {
		Definitions map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema JSON: %v", err)
	}
	enum := doc.Definitions[def].Properties[prop].Enum
	if len(enum) == 0 {
		t.Fatalf("schema enum for %s.%s is empty or missing — schema shape changed?", def, prop)
	}
	set := make(map[string]struct{}, len(enum))
	for _, e := range enum {
		set[e] = struct{}{}
	}
	return set
}

// TestConstrainedEnumFields_coveredBySchemaEnum extends the runtime-name
// drift guard (TestInstalledRuntimeNames_coveredBySchemaEnum) to the other
// schema-enum-constrained fields the agent populates:
//   - SupplyChainSignal.signal_type
//   - LockfileMeta.format
//   - DepEdge.type
//   - LicenseEvidence.source
//
// For each, it asserts that every literal the agent emits in production (see
// the agentEmitted* lists, each cross-referenced to its producing package)
// appears in the corresponding enum in agent-scan-payload-v3.json. A value
// the agent emits that the schema lacks is a REAL contract drift: the v3
// ingest path would reject an otherwise-legitimate scan payload. The subtest
// fails loudly and names the offender rather than passing silently. The fix
// for a real drift belongs in the server-owned schema, not in these lists —
// do not widen a list to make a genuine mismatch green.
func TestConstrainedEnumFields_coveredBySchemaEnum(t *testing.T) {
	cases := []struct {
		field   string // human-readable field name for failure output
		def     string // schema definition name
		prop    string // schema property name
		emitted []string
	}{
		{"SupplyChainSignal.signal_type", "SupplyChainSignal", "signal_type", agentEmittedSignalTypes},
		{"LockfileMeta.format", "LockfileMeta", "format", agentEmittedLockfileFormats},
		{"DepEdge.type", "DepEdge", "type", agentEmittedDepEdgeTypes},
		{"LicenseEvidence.source", "LicenseEvidence", "source", agentEmittedLicenseSources},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			enumSet := schemaEnumValues(t, tc.def, tc.prop)
			var missing []string
			for _, v := range tc.emitted {
				if _, ok := enumSet[v]; !ok {
					missing = append(missing, v)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				enum := make([]string, 0, len(enumSet))
				for e := range enumSet {
					enum = append(enum, e)
				}
				sort.Strings(enum)
				t.Fatalf("agent emits %s value(s) missing from schema enum %v: %v\n"+
					"the agent would emit scan-payload entries the v3 ingest rejects; "+
					"add them to docs/contracts/agent-scan-payload-v3.json", tc.field, enum, missing)
			}
		})
	}
}
