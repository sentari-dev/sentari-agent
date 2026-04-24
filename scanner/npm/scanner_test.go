package npm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// writePkg lays out one npm package inside ``root``.  ``name`` may
// be scoped (``@scope/pkg``); the helper handles the scope subdir
// automatically.  A nil ``extraManifest`` means "minimal" (name +
// version only); callers pass a map for edge-case manifests.
func writePkg(t *testing.T, root, name, version string, extraManifest map[string]any) {
	t.Helper()
	pkgDir := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", pkgDir, err)
	}
	m := map[string]any{"name": name, "version": version}
	for k, v := range extraManifest {
		m[k] = v
	}
	data, err := jsonMarshalTestHelper(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func jsonMarshalTestHelper(v any) ([]byte, error) {
	// Tiny wrapper so test code stays readable; real encoding is
	// in parser.go.  Using encoding/json directly via an inline
	// import would bloat the test signature.
	return mustMarshal(v), nil
}

// TestMatch_NodeModulesOnly: Match claims only directories named
// ``node_modules``.  Every other baseName produces Matched=false.
// This is load-bearing because the filesystem walker calls Match
// on every directory it visits — a too-loose match would trigger
// the npm walker on, e.g., ``venv`` or ``.m2``.
func TestMatch_NodeModulesOnly(t *testing.T) {
	var s Scanner
	if r := s.Match("/some/path", "node_modules"); !r.Matched || !r.Terminal {
		t.Errorf("node_modules should be Matched+Terminal; got %+v", r)
	}
	for _, base := range []string{"venv", ".git", "src", "packages", "node_modules.bak"} {
		if r := s.Match("/some/path/"+base, base); r.Matched {
			t.Errorf("%s should not match; got %+v", base, r)
		}
	}
}

// TestScan_FlatLayout: npm/yarn classic flat layout with three
// packages yields three records with the manifest's declared
// name + version.
func TestScan_FlatLayout(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "lodash", "4.17.21", nil)
	writePkg(t, root, "express", "4.18.2", nil)
	writePkg(t, root, "react", "18.2.0", nil)

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		EnvType: EnvNpm,
		Name:    layoutNodeModules,
		Path:    root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	names := map[string]string{}
	for _, r := range records {
		if r.EnvType != EnvNpm {
			t.Errorf("wrong env_type on %s: %q", r.Name, r.EnvType)
		}
		names[r.Name] = r.Version
	}
	for _, want := range []struct{ name, version string }{
		{"lodash", "4.17.21"},
		{"express", "4.18.2"},
		{"react", "18.2.0"},
	} {
		if got := names[want.name]; got != want.version {
			t.Errorf("%s version: got %q, want %q", want.name, got, want.version)
		}
	}
}

// TestScan_ScopedPackages: packages under ``@scope/<pkg>`` must
// surface with their full scoped name (``@types/node``), not the
// bare leaf.  CVE correlation for scoped packages keys off the
// full name; truncating here would silently miss every advisory
// on a scope-heavy project.
func TestScan_ScopedPackages(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "@types/node", "20.0.0", nil)
	writePkg(t, root, "@types/express", "4.17.0", nil)
	writePkg(t, root, "@babel/core", "7.22.0", nil)
	writePkg(t, root, "lodash", "4.17.21", nil) // non-scoped as control

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	names := map[string]bool{}
	for _, r := range records {
		names[r.Name] = true
	}
	for _, want := range []string{"@types/node", "@types/express", "@babel/core", "lodash"} {
		if !names[want] {
			t.Errorf("expected %s in records; got %v", want, names)
		}
	}
}

// TestScan_DotDirsSkipped: entries starting with ``.`` (``.bin``,
// ``.cache``, ``.package-lock.json-shaped`` artefacts) must never
// be treated as packages.  This guards against false-positive
// records when npm drops internal infrastructure into node_modules.
func TestScan_DotDirsSkipped(t *testing.T) {
	root := t.TempDir()
	// Real package.
	writePkg(t, root, "lodash", "4.17.21", nil)
	// Dot-prefixed dir with an otherwise-valid manifest.  Must
	// still be skipped — the name starts with '.'.
	if err := os.MkdirAll(filepath.Join(root, ".cache", "weird"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(root, ".cache", "package.json"),
		[]byte(`{"name":"ghost","version":"0.0.1"}`),
		0o644,
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	for _, r := range records {
		if r.Name == "ghost" {
			t.Errorf("dot-prefixed .cache/ leaked as a package record")
		}
	}
}

// TestScan_MalformedManifestSurfacesScanError: a package dir with
// a malformed package.json produces a ScanError on that path, but
// the walk continues and emits records for the valid siblings.
// One bad manifest never aborts the whole tree.
func TestScan_MalformedManifestSurfacesScanError(t *testing.T) {
	root := t.TempDir()
	// Good sibling.
	writePkg(t, root, "lodash", "4.17.21", nil)
	// Broken sibling.
	broken := filepath.Join(root, "broken")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(broken, "package.json"), []byte(`{not-json`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	// Valid one still surfaces.
	found := false
	for _, r := range records {
		if r.Name == "lodash" {
			found = true
		}
	}
	if !found {
		t.Errorf("valid package missing when malformed sibling present")
	}
	// ScanError references the broken path.
	brokenFlagged := false
	for _, e := range errs {
		if e.EnvType == EnvNpm && e.Path == broken {
			brokenFlagged = true
		}
	}
	if !brokenFlagged {
		t.Errorf("expected a ScanError for the broken package; got %+v", errs)
	}
}

// TestScan_ManifestWithoutIdentitySkipped: a directory with a
// package.json that has no name/version (often a workspace root
// accidentally nested inside node_modules) is silently skipped.
// Emitting a ghost record with empty name would show up on the
// dashboard as a ``""`` package which is worse than missing data.
func TestScan_ManifestWithoutIdentitySkipped(t *testing.T) {
	root := t.TempDir()
	noName := filepath.Join(root, "no-identity")
	if err := os.MkdirAll(noName, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(noName, "package.json"),
		[]byte(`{"scripts":{"build":"echo hi"}}`),
		0o644,
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(records) != 0 {
		t.Errorf("expected 0 records (no identity); got %+v", records)
	}
	if len(errs) != 0 {
		t.Errorf("identity-less manifest should be silent, not a ScanError; got %+v", errs)
	}
}

// TestScan_ExtractsLicenseStringShape: npm's license field can be
// a plain SPDX string ("MIT") or an SPDX expression ("(MIT OR
// Apache-2.0)") — both go through to LicenseRaw untouched.
// Server-side license_tier normalisation keys off this.
func TestScan_ExtractsLicenseStringShape(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "mit-pkg", "1.0.0", map[string]any{"license": "MIT"})
	writePkg(t, root, "expr-pkg", "1.0.0", map[string]any{"license": "(MIT OR Apache-2.0)"})

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	licenses := map[string]string{}
	for _, r := range records {
		licenses[r.Name] = r.LicenseRaw
	}
	if licenses["mit-pkg"] != "MIT" {
		t.Errorf("mit-pkg LicenseRaw: got %q", licenses["mit-pkg"])
	}
	if licenses["expr-pkg"] != "(MIT OR Apache-2.0)" {
		t.Errorf("expr-pkg LicenseRaw: got %q", licenses["expr-pkg"])
	}
}

// TestScan_ExtractsLicenseObjectShape: legacy object form
// {"type": "X", "url": "..."} and legacy array ``licenses`` both
// reduce to LicenseRaw=type.
func TestScan_ExtractsLicenseObjectShape(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "obj-pkg", "1.0.0", map[string]any{
		"license": map[string]any{"type": "BSD-3-Clause", "url": "https://example.com"},
	})
	writePkg(t, root, "legacy-pkg", "1.0.0", map[string]any{
		"licenses": []any{
			map[string]any{"type": "ISC", "url": "https://example.com"},
		},
	})

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	licenses := map[string]string{}
	for _, r := range records {
		licenses[r.Name] = r.LicenseRaw
	}
	if licenses["obj-pkg"] != "BSD-3-Clause" {
		t.Errorf("obj-pkg: got %q", licenses["obj-pkg"])
	}
	if licenses["legacy-pkg"] != "ISC" {
		t.Errorf("legacy-pkg: got %q", licenses["legacy-pkg"])
	}
}

// TestScan_UnknownLayout_ScanError: mirrors the JVM + aiagents
// convention — an unknown layout tag is a wiring bug and must
// surface as a ScanError, not silently drop.
func TestScan_UnknownLayout_ScanError(t *testing.T) {
	var s Scanner
	_, errs := s.Scan(context.Background(), scanner.Environment{
		EnvType: EnvNpm,
		Name:    "bogus-layout",
		Path:    "/tmp/somewhere",
	})
	if len(errs) != 1 {
		t.Fatalf("expected 1 ScanError; got %+v", errs)
	}
	if errs[0].EnvType != EnvNpm {
		t.Errorf("ScanError EnvType: got %q", errs[0].EnvType)
	}
}

// TestScan_SkipsSymlinkedDirs: when a directory entry under
// node_modules is a symlink to another directory (the pnpm
// non-hoisted case), it must be skipped — not followed.  Without
// this, a hostile layer could plant a symlink to
// /etc/.../package.json and exfiltrate contents as a ghost
// package record.  Documents the pnpm-default-mode gap.
func TestScan_SkipsSymlinkedDirs(t *testing.T) {
	// Real, flat packages.
	root := t.TempDir()
	writePkg(t, root, "lodash", "4.17.21", nil)

	// Plant a symlink-dir alongside.  Simulates pnpm's
	// ``node_modules/<pkg>`` → ``.pnpm/<pkg>@<ver>/node_modules/<pkg>``
	// shape by symlinking to a real package dir elsewhere.
	target := t.TempDir()
	writePkg(t, target, "should-not-appear", "9.9.9", nil)
	symlink := filepath.Join(root, "should-not-appear")
	if err := os.Symlink(filepath.Join(target, "should-not-appear"), symlink); err != nil {
		t.Skipf("symlink creation not supported on this platform: %v", err)
	}

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	for _, r := range records {
		if r.Name == "should-not-appear" {
			t.Errorf("symlinked package surfaced as a record; got %+v", r)
		}
	}
	// The real package still comes through.
	found := false
	for _, r := range records {
		if r.Name == "lodash" {
			found = true
		}
	}
	if !found {
		t.Errorf("real package missed alongside symlinked one")
	}
}

// TestScan_EnvironmentFieldIsNodeModulesRoot: every emitted
// record — flat, scoped, or nested — must carry the same
// ``Environment`` value: the node_modules directory the scan
// started in.  Previously scoped packages got ``@scope`` as
// their Environment which split records across dashboard
// filters.  Regression test.
func TestScan_EnvironmentFieldIsNodeModulesRoot(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "lodash", "4.17.21", nil)            // flat
	writePkg(t, root, "@types/node", "20.0.0", nil)        // scoped

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(records) != 2 {
		t.Fatalf("expected 2 records; got %+v", records)
	}
	for _, r := range records {
		if r.Environment != root {
			t.Errorf("record %s Environment: got %q, want %q", r.Name, r.Environment, root)
		}
	}
}
