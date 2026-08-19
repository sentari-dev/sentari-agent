package scanner

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/runtimeversions"
)

// TestScanPayloadGolden_KeySets is the contract-drift guard for the base scan
// payload the agent PUTs to /api/v1/agent/scan.
//
// It marshals a ScanResult in which EVERY field of ScanResult and every field of
// the embedded PackageRecord is set to a non-zero value — including the five
// container_* fields and the v3 arrays (dep_edges, lockfiles,
// supply_chain_signals, license_evidence, installed_runtimes) — so that no
// `omitempty` tag can hide a key. It then decodes the JSON back into a generic
// map and asserts the EXACT, complete set of json keys per object.
//
// Because every optional field is populated, renaming or removing ANY json tag
// on ScanResult or PackageRecord changes the emitted key set and fails this test
// with a precise added/missing-key diff — long before a renamed tag reaches the
// server's ingest path and silently drops data.
func TestScanPayloadGolden_KeySets(t *testing.T) {
	ts := time.Date(2026, 5, 23, 10, 0, 0, 1, time.UTC)

	result := fullyPopulatedScanResult(ts)

	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal ScanResult: %v", err)
	}

	// Decode into a generic map so we compare the literal wire keys, not the
	// Go struct — this is what pins the json tags.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("unmarshal ScanResult body: %v", err)
	}

	wantTop := []string{
		"agent_version",
		"arch",
		"container_targets",
		"dep_edges",
		"device_id",
		"errors",
		"hostname",
		"installed_runtimes",
		"license_evidence",
		"lockfiles",
		"os",
		"os_release",
		"packages",
		"runtime",
		"scanned_at",
		"supply_chain_signals",
		"tags",
	}
	assertKeySet(t, "ScanResult", top, wantTop)

	// Drill into the single fully-populated PackageRecord.
	var pkgs []map[string]json.RawMessage
	if err := json.Unmarshal(top["packages"], &pkgs); err != nil {
		t.Fatalf("unmarshal packages: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected exactly 1 package object, got %d", len(pkgs))
	}
	wantPkg := []string{
		"container_id",
		"container_image_id",
		"container_image_tags",
		"container_name",
		"container_runtime",
		"env_type",
		"environment",
		"install_date",
		"install_path",
		"installer_user",
		"interpreter_version",
		"license_raw",
		"license_spdx",
		"license_tier",
		"name",
		"source_package",
		"version",
	}
	assertKeySet(t, "PackageRecord", pkgs[0], wantPkg)

	// Value/type assertions. The key-set guard above pins the wire KEY names;
	// these pin the wire VALUE types so a field whose Go type silently changes
	// (string→int, or a scalar accidentally emitted as an array) is caught even
	// when the key name is unchanged. The base payload (packages, errors) is
	// NOT modeled by docs/contracts/agent-scan-payload-v3.json — that schema
	// covers only the v3 extension arrays (dep_edges, lockfiles,
	// supply_chain_signals, license_evidence, installed_runtimes,
	// container_targets, os_release) — so these explicit checks are the sole
	// wire-type guard for PackageRecord and ScanError.
	pkg := pkgs[0]
	// EVERY PackageRecord field gets a wire-VALUE-type assertion. The base
	// packages[] object is NOT schema-modeled, so this is its sole contract
	// guard against a silent Go-type change (e.g. string->int, scalar->array).
	assertJSONString(t, "PackageRecord.name", pkg["name"], "flask")
	assertJSONString(t, "PackageRecord.version", pkg["version"], "3.0.0")
	assertJSONString(t, "PackageRecord.install_path", pkg["install_path"], "/srv/venv/lib/python3.12/site-packages/flask")
	assertJSONString(t, "PackageRecord.env_type", pkg["env_type"], "pip")
	assertJSONString(t, "PackageRecord.source_package", pkg["source_package"], "python-flask")
	assertJSONString(t, "PackageRecord.interpreter_version", pkg["interpreter_version"], "3.12.1")
	assertJSONString(t, "PackageRecord.installer_user", pkg["installer_user"], "root")
	assertJSONString(t, "PackageRecord.environment", pkg["environment"], "/srv/venv")
	assertJSONString(t, "PackageRecord.license_raw", pkg["license_raw"], "BSD-3-Clause")
	assertJSONString(t, "PackageRecord.license_spdx", pkg["license_spdx"], "BSD-3-Clause")
	assertJSONString(t, "PackageRecord.license_tier", pkg["license_tier"], "permissive")
	assertJSONString(t, "PackageRecord.container_image_id", pkg["container_image_id"], "sha256:deadbeef")
	assertJSONString(t, "PackageRecord.container_id", pkg["container_id"], "c0ffee")
	assertJSONString(t, "PackageRecord.container_name", pkg["container_name"], "web")
	assertJSONString(t, "PackageRecord.container_runtime", pkg["container_runtime"], "docker")
	assertJSONStringArray(t, "PackageRecord.container_image_tags", pkg["container_image_tags"])
	assertRFC3339(t, "PackageRecord.install_date", pkg["install_date"])

	// dep_edges is schema-modeled, but its depth field is numeric on the wire;
	// a quick numeric-type check here guards against an accidental string
	// serialization that the schema-less key-set drilling would not catch.
	var depEdges []map[string]json.RawMessage
	if err := json.Unmarshal(top["dep_edges"], &depEdges); err != nil {
		t.Fatalf("unmarshal dep_edges: %v", err)
	}
	if len(depEdges) != 1 {
		t.Fatalf("expected exactly 1 dep_edge object, got %d", len(depEdges))
	}
	assertJSONNumber(t, "DepEdge.depth", depEdges[0]["depth"])

	// Drill into the single fully-populated ScanError. The server ingest path
	// requires these wire fields, so a rename of any ScanError json tag must
	// fail this test the same way a PackageRecord tag rename does.
	var scanErrs []map[string]json.RawMessage
	if err := json.Unmarshal(top["errors"], &scanErrs); err != nil {
		t.Fatalf("unmarshal errors: %v", err)
	}
	if len(scanErrs) != 1 {
		t.Fatalf("expected exactly 1 error object, got %d", len(scanErrs))
	}
	wantErr := []string{
		"env_type",
		"error",
		"path",
		"timestamp",
	}
	assertKeySet(t, "ScanError", scanErrs[0], wantErr)

	se := scanErrs[0]
	assertJSONString(t, "ScanError.path", se["path"], "/broken/env")
	assertJSONString(t, "ScanError.error", se["error"], "unreadable")
	assertJSONString(t, "ScanError.env_type", se["env_type"], "conda")
	assertRFC3339(t, "ScanError.timestamp", se["timestamp"])

	// Drill into os_release. The top-level key-set guard pins that os_release
	// is present but never inspects its inner keys; this closes that gap by
	// asserting the exact key set {id, version_id, kernel} and each value type,
	// so a rename of any OsRelease json tag fails here.
	var osr map[string]json.RawMessage
	if err := json.Unmarshal(top["os_release"], &osr); err != nil {
		t.Fatalf("unmarshal os_release: %v", err)
	}
	assertKeySet(t, "OsRelease", osr, []string{"id", "version_id", "kernel"})
	assertJSONString(t, "OsRelease.id", osr["id"], "debian")
	assertJSONString(t, "OsRelease.version_id", osr["version_id"], "12")
	assertJSONString(t, "OsRelease.kernel", osr["kernel"], "6.1.0-18-amd64")
}

// fullyPopulatedScanResult returns a ScanResult in which every field of
// ScanResult, PackageRecord, ScanError, OsRelease and ContainerTargetSummary is
// set to a non-zero value, and every v3 extension array carries one fully
// populated element. It is the single source of truth shared by the key-set
// guard (TestScanPayloadGolden_KeySets) and the schema guard
// (TestScanPayloadGolden_ValidatesAgainstV3Schema) so both exercise the exact
// same wire shape.
func fullyPopulatedScanResult(ts time.Time) ScanResult {
	return ScanResult{
		DeviceID:     "f1e2d3c4-0000-0000-0000-000000000000",
		Hostname:     "host-01",
		OS:           "linux",
		Arch:         "amd64",
		ScannedAt:    ts,
		AgentVersion: "1.2.3",
		Packages: []PackageRecord{
			{
				Name:               "flask",
				Version:            "3.0.0",
				InstallPath:        "/srv/venv/lib/python3.12/site-packages/flask",
				EnvType:            EnvPip,
				SourcePackage:      "python-flask",
				InterpreterVersion: "3.12.1",
				InstallerUser:      "root",
				InstallDate:        "2026-05-01T00:00:00Z",
				Environment:        "/srv/venv",
				LicenseRaw:         "BSD-3-Clause",
				LicenseSPDX:        "BSD-3-Clause",
				LicenseTier:        "permissive",
				ContainerImageID:   "sha256:deadbeef",
				ContainerImageTags: []string{"app:latest"},
				ContainerID:        "c0ffee",
				ContainerName:      "web",
				ContainerRuntime:   "docker",
			},
		},
		Errors: []ScanError{
			{Path: "/broken/env", EnvType: EnvConda, Error: "unreadable", Timestamp: ts},
		},
		OsRelease: &OsRelease{ID: "debian", VersionID: "12", Kernel: "6.1.0-18-amd64"},
		ContainerTargets: []ContainerTargetSummary{
			{
				Runtime:       "docker",
				ImageID:       "sha256:deadbeef",
				ImageTags:     []string{"app:latest"},
				ContainerID:   "c0ffee",
				ContainerName: "web",
				LayerCount:    7,
				LayerDigests: []string{
					"sha256:1111111111111111111111111111111111111111111111111111111111111111",
					"sha256:2222222222222222222222222222222222222222222222222222222222222222",
				},
			},
		},
		Tags:    &[]string{"pilot", "brussels"},
		Runtime: "container",
		DepEdges: []deptree.DepEdge{
			{
				ParentName:       "flask",
				ParentVersion:    "3.0.0",
				ChildName:        "werkzeug",
				ChildVersion:     "3.0.1",
				Ecosystem:        "pypi",
				Type:             "direct",
				Scope:            "runtime",
				Depth:            1,
				IntroducedByPath: []string{"flask", "werkzeug"},
				Resolved:         true,
			},
		},
		Lockfiles: []deptree.LockfileMeta{
			{
				Path:                  "/srv/app/poetry.lock",
				Format:                "poetry_lock",
				Ecosystem:             "pypi",
				SHA256:                strings.Repeat("a", 64),
				LastModified:          ts,
				DeclaredPackagesCount: 42,
				DriftStatus:           "unknown",
			},
		},
		SupplyChainSignals: []deptree.SupplyChainSignal{
			{
				PackageName:    "flask",
				PackageVersion: "3.0.0",
				Ecosystem:      "pypi",
				SignalType:     "postinstall_script",
				Severity:       "info",
				Source:         "agent",
				Raw:            map[string]interface{}{"k": "v"},
			},
		},
		LicenseEvidence: []deptree.LicenseEvidence{
			{
				PackageName:    "flask",
				PackageVersion: "3.0.0",
				Ecosystem:      "pypi",
				SpdxID:         "BSD-3-Clause",
				Source:         "spdx_pkg",
				Confidence:     0.9,
				RawText:        "BSD",
			},
		},
		InstalledRuntimes: []runtimeversions.InstalledRuntime{
			{Name: "python", Version: "3.12.1", Cycle: "3.12", Distro: "cpython", InstallPath: "/usr/bin/python3"},
		},
	}
}

// TestScanPayloadGolden_ValidatesAgainstV3Schema is the wire-contract guard
// that closes the gap the key-set guard cannot see: os_release and
// container_targets carry object/array VALUES whose inner json tags
// (OsRelease.id/version_id, ContainerTargetSummary.runtime/image_id/
// layer_count/…) the key-set guard never drills into, and
// contract_v3_round_trip_test.go validates only hand-rolled maps for those two
// fields — never the real scanner.OsRelease / scanner.ContainerTargetSummary
// structs (it lives in package deptree and cannot import scanner without a
// cycle).
//
// This test lives in package scanner, so it constructs a REAL, fully populated
// ScanResult (with the actual OsRelease + ContainerTargetSummary structs) and
// validates the marshaled document against the shared
// docs/contracts/agent-scan-payload-v3.json. A Go json-tag rename on OsRelease
// or ContainerTargetSummary (e.g. `id` → `identifier`) then drops a
// schema-required property and fails this test — before the renamed tag reaches
// the server's v3 ingest path.
func TestScanPayloadGolden_ValidatesAgainstV3Schema(t *testing.T) {
	// scanner/ is one level below the repo root; the shared schema lives at
	// repo-root/docs/contracts (mirror contract_v3_round_trip_test.go, which
	// is two levels deep and uses "..","..").
	schemaPath, err := filepath.Abs(filepath.Join("..", "docs", "contracts", "agent-scan-payload-v3.json"))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}

	schema, err := jsonschema.NewCompiler().Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}

	ts := time.Date(2026, 5, 23, 10, 0, 0, 1, time.UTC)
	body, err := json.Marshal(fullyPopulatedScanResult(ts))
	if err != nil {
		t.Fatalf("marshal ScanResult: %v", err)
	}

	var doc interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal ScanResult for validation: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("fully-populated ScanResult failed v3 schema validation: %v\npayload: %s", err, string(body))
	}
}

// assertJSONString fails unless raw is a JSON string; when want != "" it also
// checks the decoded value equals want.
func assertJSONString(t *testing.T, label string, raw json.RawMessage, want string) {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Errorf("%s: expected JSON string, got %s (%v)", label, raw, err)
		return
	}
	if want != "" && s != want {
		t.Errorf("%s: value = %q, want %q", label, s, want)
	}
}

// assertJSONStringArray fails unless raw is a JSON array of strings.
func assertJSONStringArray(t *testing.T, label string, raw json.RawMessage) {
	t.Helper()
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Errorf("%s: expected JSON array of strings, got %s (%v)", label, raw, err)
	}
}

// assertJSONNumber fails unless raw is a JSON number (not a quoted string).
func assertJSONNumber(t *testing.T, label string, raw json.RawMessage) {
	t.Helper()
	var n json.Number
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		t.Errorf("%s: expected JSON number, got %s (%v)", label, raw, err)
	}
}

// assertRFC3339 fails unless raw is a JSON string parseable as an RFC3339
// timestamp.
func assertRFC3339(t *testing.T, label string, raw json.RawMessage) {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Errorf("%s: expected JSON string timestamp, got %s (%v)", label, raw, err)
		return
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		t.Errorf("%s: %q is not RFC3339: %v", label, s, err)
	}
}

// assertKeySet fails with a precise added/missing diff when the marshaled
// object's json key set does not exactly match want.
func assertKeySet(t *testing.T, label string, obj map[string]json.RawMessage, want []string) {
	t.Helper()

	got := make([]string, 0, len(obj))
	for k := range obj {
		got = append(got, k)
	}
	sort.Strings(got)

	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)

	wantSet := make(map[string]bool, len(wantSorted))
	for _, k := range wantSorted {
		wantSet[k] = true
	}
	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}

	var missing, added []string
	for _, k := range wantSorted {
		if !gotSet[k] {
			missing = append(missing, k)
		}
	}
	for _, k := range got {
		if !wantSet[k] {
			added = append(added, k)
		}
	}

	if len(missing) > 0 || len(added) > 0 {
		t.Errorf("%s json key set drift:\n  got:     %v\n  want:    %v\n  missing: %v (removed/renamed tag?)\n  added:   %v (new/renamed tag not pinned?)",
			label, got, wantSorted, missing, added)
	}
}
