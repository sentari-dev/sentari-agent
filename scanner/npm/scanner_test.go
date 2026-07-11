package npm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// writePkg lays out one npm package inside `root`.  `name` may
// be scoped (`@scope/pkg`); the helper handles the scope subdir
// automatically.  A nil `extraManifest` means "minimal" (name +
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
// `node_modules`.  Every other baseName produces Matched=false.
// This is load-bearing because the filesystem walker calls Match
// on every directory it visits — a too-loose match would trigger
// the npm walker on, e.g., `venv` or `.m2`.
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

// TestScan_ScopedPackages: packages under `@scope/<pkg>` must
// surface with their full scoped name (`@types/node`), not the
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

// TestScan_DotDirsSkipped: entries starting with `.` (`.bin`,
// `.cache`, `.package-lock.json-shaped` artefacts) must never
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
// dashboard as a `""` package which is worse than missing data.
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

// TestScan_BOMManifestParses: a package.json prefixed with a UTF-8 BOM
// (EF BB BF) must be stripped before json.Unmarshal so the package still
// surfaces in inventory. Without the strip, encoding/json rejects the
// leading U+FEFF and the package silently drops out.
func TestScan_BOMManifestParses(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "bommy")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bom := []byte{0xEF, 0xBB, 0xBF}
	body := []byte(`{"name":"bommy","version":"1.2.3"}`)
	if err := os.WriteFile(
		filepath.Join(pkgDir, "package.json"),
		append(bom, body...),
		0o644,
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(errs) != 0 {
		t.Fatalf("BOM'd manifest should parse cleanly; got errs %+v", errs)
	}
	var found bool
	for _, r := range records {
		if r.Name == "bommy" && r.Version == "1.2.3" {
			found = true
		}
	}
	if !found {
		t.Errorf("BOM'd package.json did not parse — expected bommy@1.2.3; got %+v", records)
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
// {"type": "X", "url": "..."} and legacy array `licenses` both
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
	// `node_modules/<pkg>` → `.pnpm/<pkg>@<ver>/node_modules/<pkg>`
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

// TestScan_PnpmDefaultModeStoreWalk: a pnpm default-mode install lays
// `node_modules/<pkg>` down as a symlink into the virtual store at
// `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>` (the real dir).
// The main walk skips the symlinks (and the dot-prefixed `.pnpm`), so
// before the store walk a default-mode install produced ZERO records.
// scanPnpmStore must inventory the real store dirs — flat and scoped —
// while the symlinked `node_modules/<pkg>` entries stay skipped and no
// package is double-counted.
func TestScan_PnpmDefaultModeStoreWalk(t *testing.T) {
	root := t.TempDir() // this is the node_modules dir
	store := filepath.Join(root, ".pnpm")

	// Real store package dirs: .pnpm/<pkg>@<ver>/node_modules/<pkg>.
	expressNM := filepath.Join(store, "express@4.18.2", "node_modules")
	qsNM := filepath.Join(store, "qs@6.11.0", "node_modules")
	scopedNM := filepath.Join(store, "@acme+tool@2.0.0", "node_modules")
	writePkg(t, expressNM, "express", "4.18.2", nil)
	writePkg(t, qsNM, "qs", "6.11.0", nil)
	writePkg(t, scopedNM, "@acme/tool", "2.0.0", nil)

	// express depends on qs: inside express's store node_modules, `qs` is
	// a SYMLINK into qs's own store entry.  It must be skipped (qs is
	// emitted once, from its own entry) — never double-counted or
	// followed as a real dir.
	qsLink := filepath.Join(expressNM, "qs")
	if err := os.Symlink(filepath.Join(qsNM, "qs"), qsLink); err != nil {
		t.Skipf("symlink creation not supported on this platform: %v", err)
	}

	// Top-level default-mode symlink: node_modules/express → the store.
	// The main walk must skip it (it's a symlink), so express is emitted
	// exactly once, from the store walk.
	if err := os.Symlink(filepath.Join(expressNM, "express"), filepath.Join(root, "express")); err != nil {
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

	counts := map[string]int{}
	versions := map[string]string{}
	for _, r := range records {
		counts[r.Name]++
		versions[r.Name] = r.Version
		if r.Environment != root {
			t.Errorf("store record %s Environment: got %q, want node_modules root %q", r.Name, r.Environment, root)
		}
	}
	for _, want := range []struct{ name, version string }{
		{"express", "4.18.2"},
		{"qs", "6.11.0"},
		{"@acme/tool", "2.0.0"},
	} {
		if versions[want.name] != want.version {
			t.Errorf("store package %s: got version %q, want %q (records=%+v)", want.name, versions[want.name], want.version, records)
		}
		if counts[want.name] != 1 {
			t.Errorf("store package %s emitted %d times, want exactly 1 (symlink double-count?)", want.name, counts[want.name])
		}
	}
	if len(records) != 3 {
		t.Errorf("expected exactly 3 store records, got %d: %+v", len(records), records)
	}
}

// TestScan_PnpmStoreAbsentIsNoOp: a plain npm/yarn layout (no `.pnpm`)
// must be unaffected by the store walk — it emits only the real flat
// packages and never errors on the missing store.
func TestScan_PnpmStoreAbsentIsNoOp(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "lodash", "4.17.21", nil)

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(records) != 1 || records[0].Name != "lodash" {
		t.Errorf("expected exactly [lodash], got %+v", records)
	}
}

// TestScan_PnpmStoreSymlinkRefused: a `.pnpm` that is itself a symlink
// must NOT be followed — same threat model as every other symlink
// refusal (a planted `.pnpm` symlink could redirect the store walk
// outside the scanned tree).
func TestScan_PnpmStoreSymlinkRefused(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "lodash", "4.17.21", nil)

	// Real store elsewhere holding a package we must not see.
	target := t.TempDir()
	writePkg(t, filepath.Join(target, "evil@9.9.9", "node_modules"), "should-not-appear", "9.9.9", nil)

	if err := os.Symlink(target, filepath.Join(root, ".pnpm")); err != nil {
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
			t.Errorf("symlinked .pnpm store was followed; got %+v", r)
		}
	}
}

// TestScan_EnvironmentFieldIsNodeModulesRoot: every emitted
// record — flat, scoped, or nested — must carry the same
// `Environment` value: the node_modules directory the scan
// started in.  Previously scoped packages got `@scope` as
// their Environment which split records across dashboard
// filters.  Regression test.
func TestScan_EnvironmentFieldIsNodeModulesRoot(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "lodash", "4.17.21", nil)     // flat
	writePkg(t, root, "@types/node", "20.0.0", nil) // scoped

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

// TestScan_NestedNodeModulesConflictingVersions: npm's standard
// version-conflict layout nests a private node_modules inside a
// package dir (node_modules/a/node_modules/lodash@3) when the
// depending package needs a version different from the hoisted
// top-level one (lodash@4). Both versions must surface as distinct
// PackageRecords — the whole reason CVE correlation needs the
// nested layout: the vulnerable pinned version hides one level down.
func TestScan_NestedNodeModulesConflictingVersions(t *testing.T) {
	root := t.TempDir()
	// Hoisted top-level lodash@4.x.
	writePkg(t, root, "lodash", "4.17.21", nil)
	// Package `a` pins lodash@3 — npm nests it privately.
	writePkg(t, root, "a", "1.0.0", nil)
	nested := filepath.Join(root, "a", "node_modules")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	writePkg(t, nested, "lodash", "3.10.1", nil)

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	var lodashVers []string
	for _, r := range records {
		if r.Name == "lodash" {
			lodashVers = append(lodashVers, r.Version)
		}
	}
	if len(lodashVers) != 2 {
		t.Fatalf("expected 2 lodash records; got %v", lodashVers)
	}
	set := map[string]bool{}
	for _, v := range lodashVers {
		set[v] = true
	}
	if !set["4.17.21"] || !set["3.10.1"] {
		t.Errorf("expected distinct versions 4.17.21 and 3.10.1; got %v", lodashVers)
	}
}

// TestScan_NestedScopedPackageRecursed: a scoped package can also
// carry a nested node_modules
// (node_modules/@scope/pkg/node_modules/lodash). The recursion must
// reach it via the scope walk, not just the flat one.
func TestScan_NestedScopedPackageRecursed(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "@acme/tool", "2.0.0", nil)
	nested := filepath.Join(root, "@acme", "tool", "node_modules")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	writePkg(t, nested, "lodash", "3.10.1", nil)

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	names := map[string]string{}
	for _, r := range records {
		names[r.Name] = r.Version
	}
	if names["@acme/tool"] != "2.0.0" {
		t.Errorf("scoped parent missing; got %v", names)
	}
	if names["lodash"] != "3.10.1" {
		t.Errorf("nested lodash under scoped package missing; got %v", names)
	}
}

// TestScan_NestedEnvironmentIsNestedRoot: a nested node_modules is
// its own scan root, so records it emits carry the nested path as
// their Environment (not the top-level one). This keeps the
// dashboard grouping honest — the pinned version genuinely lives in
// a different tree.
func TestScan_NestedEnvironmentIsNestedRoot(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "a", "1.0.0", nil)
	nested := filepath.Join(root, "a", "node_modules")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	writePkg(t, nested, "lodash", "3.10.1", nil)

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	for _, r := range records {
		switch r.Name {
		case "a":
			if r.Environment != root {
				t.Errorf("top-level `a` Environment: got %q, want %q", r.Environment, root)
			}
		case "lodash":
			if r.Environment != nested {
				t.Errorf("nested lodash Environment: got %q, want %q", r.Environment, nested)
			}
		}
	}
}

// TestScan_NestedSymlinkRefused: a symlinked nested node_modules
// must NOT be followed — same threat model as the per-entry
// symlink filter. A planted symlink could otherwise redirect the
// walk to a package tree outside the scanned root.
func TestScan_NestedSymlinkRefused(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "a", "1.0.0", nil)

	// Real node_modules elsewhere holding a package we must not see.
	target := t.TempDir()
	writePkg(t, target, "should-not-appear", "9.9.9", nil)

	link := filepath.Join(root, "a", "node_modules")
	if err := os.Symlink(target, link); err != nil {
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
			t.Errorf("symlinked nested node_modules was followed; got %+v", r)
		}
	}
}

// TestScan_NestedDepthCapEmitsScanError: a nesting chain deeper
// than maxNestedNodeModulesDepth must surface a ScanError rather
// than silently truncating (or looping) — a pathological or
// hostile layout is auditable, not invisible.
func TestScan_NestedDepthCapEmitsScanError(t *testing.T) {
	root := t.TempDir()
	// Build root/a/node_modules/a/node_modules/... one level past
	// the cap. Each `a` is a real package whose nested node_modules
	// holds the next `a`, so the recursion keeps descending.
	dir := root
	for i := 0; i <= maxNestedNodeModulesDepth+1; i++ {
		writePkg(t, dir, "a", "1.0.0", nil)
		dir = filepath.Join(dir, "a", "node_modules")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir level %d: %v", i, err)
		}
	}

	var s Scanner
	_, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	capHit := false
	for _, e := range errs {
		if e.EnvType == EnvNpm && strings.Contains(e.Error, "depth exceeds cap") {
			capHit = true
		}
	}
	if !capHit {
		t.Errorf("expected a depth-cap ScanError; got %+v", errs)
	}
}
