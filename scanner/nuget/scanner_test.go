package nuget

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// writeNuGetPkg lays out one package dir in NuGet's global-
// packages layout.  ``id`` is the canonical-cased manifest ID
// (e.g. ``Newtonsoft.Json``); the on-disk dir uses the lowercase
// form per NuGet's own convention.  ``nuspecBody`` replaces the
// default minimal manifest when the test wants a specific shape.
func writeNuGetPkg(t *testing.T, root, id, version string, nuspecBody string) {
	t.Helper()
	lowerID := toLowerASCII(id)
	pkgDir := filepath.Join(root, lowerID, version)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", pkgDir, err)
	}
	if nuspecBody == "" {
		nuspecBody = `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>` + id + `</id>
    <version>` + version + `</version>
    <authors>Test Author</authors>
  </metadata>
</package>`
	}
	nuspec := filepath.Join(pkgDir, lowerID+".nuspec")
	if err := os.WriteFile(nuspec, []byte(nuspecBody), 0o644); err != nil {
		t.Fatalf("write nuspec: %v", err)
	}
}

// toLowerASCII is a tiny local helper to avoid importing
// strings for one use.  Test code only — production uses
// strings.ToLower via the stdlib.
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// TestDiscoverAll_NoHome: host with no HOME / USERPROFILE env
// var set returns zero envs and zero errors.  Minimal-CI setup.
func TestDiscoverAll_NoHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("NUGET_PACKAGES", "")
	var s Scanner
	envs, errs := s.DiscoverAll(context.Background())
	if len(envs) != 0 || len(errs) != 0 {
		t.Errorf("expected (nil, nil); got (%+v, %+v)", envs, errs)
	}
}

// TestDiscoverAll_RespectsNUGET_PACKAGES: the env-var override
// is the documented way to redirect the packages folder.  The
// plugin honours it over the default path.
func TestDiscoverAll_RespectsNUGET_PACKAGES(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("NUGET_PACKAGES", custom)
	var s Scanner
	envs, errs := s.DiscoverAll(context.Background())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(envs) != 1 {
		t.Fatalf("expected 1 env for NUGET_PACKAGES dir; got %+v", envs)
	}
	if envs[0].Path != custom {
		t.Errorf("env Path: got %q, want %q", envs[0].Path, custom)
	}
}

// TestDiscoverAll_NUGET_PACKAGES_PointsAtFile: operator
// misconfiguration — env var set, path exists, but it's a file.
// Surface as a ScanError so the operator notices.
func TestDiscoverAll_NUGET_PACKAGES_PointsAtFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("NUGET_PACKAGES", f)
	var s Scanner
	envs, errs := s.DiscoverAll(context.Background())
	if len(envs) != 0 {
		t.Errorf("expected 0 envs when NUGET_PACKAGES names a file; got %+v", envs)
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 ScanError; got %+v", errs)
	}
}

// TestScan_GlobalPackagesLayout: the common case — NuGet global
// packages folder with three packages of different casing and
// version strings.  Every one surfaces with the manifest's
// canonical-cased ID (not the on-disk lowercased dir name).
func TestScan_GlobalPackagesLayout(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "Newtonsoft.Json", "13.0.3", "")
	writeNuGetPkg(t, root, "Serilog", "3.1.1", "")
	writeNuGetPkg(t, root, "Microsoft.Extensions.Logging", "8.0.0", "")

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		EnvType: EnvNuGet,
		Name:    layoutGlobalPackages,
		Path:    root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	want := map[string]string{
		"Newtonsoft.Json":              "13.0.3",
		"Serilog":                      "3.1.1",
		"Microsoft.Extensions.Logging": "8.0.0",
	}
	got := map[string]string{}
	for _, r := range records {
		if r.EnvType != EnvNuGet {
			t.Errorf("wrong env_type on %s: %q", r.Name, r.EnvType)
		}
		got[r.Name] = r.Version
	}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("%s: got version %q, want %q", name, got[name], version)
		}
	}
}

// TestScan_MultipleVersionsOfSamePackage: NuGet keeps every
// installed version side-by-side under ``<id>/<version>/``.
// Each becomes its own record — CVE correlation needs the
// exact version, so merging would lose data.
func TestScan_MultipleVersionsOfSamePackage(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "Newtonsoft.Json", "12.0.3", "")
	writeNuGetPkg(t, root, "Newtonsoft.Json", "13.0.1", "")
	writeNuGetPkg(t, root, "Newtonsoft.Json", "13.0.3", "")

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutGlobalPackages,
		Path: root,
	})
	versions := map[string]bool{}
	for _, r := range records {
		if r.Name == "Newtonsoft.Json" {
			versions[r.Version] = true
		}
	}
	for _, want := range []string{"12.0.3", "13.0.1", "13.0.3"} {
		if !versions[want] {
			t.Errorf("version %s missing from records; got %v", want, versions)
		}
	}
}

// TestScan_LicenseExpression: modern nuspec uses
// ``<license type="expression">MIT</license>`` and
// ``<license type="expression">(MIT OR Apache-2.0)</license>``.
// Both pass through to LicenseRaw.
func TestScan_LicenseExpression(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "MitPkg", "1.0.0", `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>MitPkg</id>
    <version>1.0.0</version>
    <license type="expression">MIT</license>
  </metadata>
</package>`)
	writeNuGetPkg(t, root, "ExprPkg", "1.0.0", `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>ExprPkg</id>
    <version>1.0.0</version>
    <license type="expression">(MIT OR Apache-2.0)</license>
  </metadata>
</package>`)

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutGlobalPackages,
		Path: root,
	})
	licenses := map[string]string{}
	for _, r := range records {
		licenses[r.Name] = r.LicenseRaw
	}
	if licenses["MitPkg"] != "MIT" {
		t.Errorf("MitPkg LicenseRaw: got %q", licenses["MitPkg"])
	}
	if licenses["ExprPkg"] != "(MIT OR Apache-2.0)" {
		t.Errorf("ExprPkg LicenseRaw: got %q", licenses["ExprPkg"])
	}
}

// TestScan_LegacyLicenseURL: older nuspec files carry
// ``<licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>``
// instead of the modern ``<license>``.  The well-known URL
// pattern reduces to the SPDX-ish ID; a custom URL passes
// through verbatim.
func TestScan_LegacyLicenseURL(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "LegacyMit", "1.0.0", `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>LegacyMit</id>
    <version>1.0.0</version>
    <licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>
  </metadata>
</package>`)
	writeNuGetPkg(t, root, "CustomURL", "1.0.0", `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>CustomURL</id>
    <version>1.0.0</version>
    <licenseUrl>https://example.com/custom-license.txt</licenseUrl>
  </metadata>
</package>`)

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutGlobalPackages,
		Path: root,
	})
	licenses := map[string]string{}
	for _, r := range records {
		licenses[r.Name] = r.LicenseRaw
	}
	if licenses["LegacyMit"] != "MIT" {
		t.Errorf("LegacyMit LicenseRaw: got %q, want MIT", licenses["LegacyMit"])
	}
	if licenses["CustomURL"] != "https://example.com/custom-license.txt" {
		t.Errorf("CustomURL LicenseRaw: got %q", licenses["CustomURL"])
	}
}

// TestScan_MalformedNuspecSurfacesScanError: a package dir with
// a malformed .nuspec produces a ScanError for that path but
// leaves the sibling packages intact.  One bad manifest never
// aborts the whole tree.
func TestScan_MalformedNuspecSurfacesScanError(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "ValidPkg", "1.0.0", "")
	// Malformed manifest.
	brokenDir := filepath.Join(root, "broken", "1.0.0")
	if err := os.MkdirAll(brokenDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(brokenDir, "broken.nuspec"),
		[]byte(`<package><not xml>`),
		0o644,
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		Name: layoutGlobalPackages,
		Path: root,
	})

	// Valid sibling still surfaces.
	found := false
	for _, r := range records {
		if r.Name == "ValidPkg" {
			found = true
		}
	}
	if !found {
		t.Errorf("valid package missing when malformed sibling present")
	}
	// ScanError flags the broken path.
	brokenFlagged := false
	for _, e := range errs {
		if e.EnvType == EnvNuGet && e.Path == brokenDir {
			brokenFlagged = true
		}
	}
	if !brokenFlagged {
		t.Errorf("expected a ScanError for the broken package; got %+v", errs)
	}
}

// TestScan_EnvironmentFieldIsPackagesRoot: every record carries
// the global-packages folder as its ``Environment``, regardless
// of which ID/version it is.  Matches the same-tree-grouping
// behaviour of the npm plugin.
func TestScan_EnvironmentFieldIsPackagesRoot(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "A", "1.0.0", "")
	writeNuGetPkg(t, root, "B", "2.0.0", "")
	writeNuGetPkg(t, root, "A", "2.0.0", "")

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutGlobalPackages,
		Path: root,
	})
	if len(records) != 3 {
		t.Fatalf("expected 3 records; got %d: %+v", len(records), records)
	}
	for _, r := range records {
		if r.Environment != root {
			t.Errorf("record %s@%s Environment: got %q, want %q",
				r.Name, r.Version, r.Environment, root)
		}
	}
}

// TestScan_UnknownLayout_ScanError: mirrors the JVM + aiagents +
// npm convention.
func TestScan_UnknownLayout_ScanError(t *testing.T) {
	var s Scanner
	_, errs := s.Scan(context.Background(), scanner.Environment{
		EnvType: EnvNuGet,
		Name:    "bogus",
		Path:    "/tmp/x",
	})
	if len(errs) != 1 {
		t.Fatalf("expected 1 ScanError; got %+v", errs)
	}
}
