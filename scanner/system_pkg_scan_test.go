package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// detectRpmDbFormat — confirms each of the three branches emits the right
// ScanError (or no error for SQLite-present), without needing a real rpmdb.
// ---------------------------------------------------------------------------

// setRpmPaths swaps the package-level rpmdb path vars to point at files
// inside dir.  Restored on test cleanup so subsequent tests are unaffected.
func setRpmPaths(t *testing.T, dir string) {
	t.Helper()
	origSqlite, origNdb, origBdb := rpmdbSqlite, rpmdbNdb, rpmdbBdb
	rpmdbSqlite = filepath.Join(dir, "rpmdb.sqlite")
	rpmdbNdb = filepath.Join(dir, "Packages.db")
	rpmdbBdb = filepath.Join(dir, "Packages")
	t.Cleanup(func() {
		rpmdbSqlite = origSqlite
		rpmdbNdb = origNdb
		rpmdbBdb = origBdb
	})
}

func TestDetectRpmDbFormat_NoneFound(t *testing.T) {
	setRpmPaths(t, t.TempDir())
	path, errs := detectRpmDbFormat()
	if path != "" {
		t.Errorf("expected empty path when no rpmdb present, got %q", path)
	}
	if len(errs) != 0 {
		t.Errorf("expected no ScanErrors when rpmdb is absent, got %+v", errs)
	}
}

func TestDetectRpmDbFormat_SqlitePreferred(t *testing.T) {
	dir := t.TempDir()
	// All three present → SQLite must win and no ScanError emitted.
	if err := os.WriteFile(filepath.Join(dir, "rpmdb.sqlite"), []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Packages.db"), []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Packages"), []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	setRpmPaths(t, dir)
	path, errs := detectRpmDbFormat()
	if path == "" || filepath.Base(path) != "rpmdb.sqlite" {
		t.Errorf("expected SQLite path, got %q", path)
	}
	if len(errs) != 0 {
		t.Errorf("expected no ScanErrors when SQLite is present, got %+v", errs)
	}
}

func TestDetectRpmDbFormat_NdbSurfacesScanError(t *testing.T) {
	dir := t.TempDir()
	// Only the NDB file → must surface a ScanError describing the
	// unsupported format.  Path must remain "" so callers don't try
	// to open it as SQLite.
	if err := os.WriteFile(filepath.Join(dir, "Packages.db"), []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	setRpmPaths(t, dir)
	path, errs := detectRpmDbFormat()
	if path != "" {
		t.Errorf("expected empty path for NDB-only rpmdb, got %q", path)
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 ScanError for NDB rpmdb, got %d: %+v", len(errs), errs)
	}
	if errs[0].EnvType != EnvSystemRpm {
		t.Errorf("EnvType = %q, want %q", errs[0].EnvType, EnvSystemRpm)
	}
	if errs[0].Path != filepath.Join(dir, "Packages.db") {
		t.Errorf("Path = %q, want %q", errs[0].Path, filepath.Join(dir, "Packages.db"))
	}
	wantSubstr := "NDB-format rpmdb"
	if !contains(errs[0].Error, wantSubstr) {
		t.Errorf("Error message %q does not contain %q", errs[0].Error, wantSubstr)
	}
}

func TestDetectRpmDbFormat_BdbSurfacesScanError(t *testing.T) {
	dir := t.TempDir()
	// Only the BDB file → must surface a ScanError describing the
	// unsupported format.
	if err := os.WriteFile(filepath.Join(dir, "Packages"), []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	setRpmPaths(t, dir)
	path, errs := detectRpmDbFormat()
	if path != "" {
		t.Errorf("expected empty path for BDB-only rpmdb, got %q", path)
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 ScanError for BDB rpmdb, got %d: %+v", len(errs), errs)
	}
	if errs[0].EnvType != EnvSystemRpm {
		t.Errorf("EnvType = %q, want %q", errs[0].EnvType, EnvSystemRpm)
	}
	if errs[0].Path != filepath.Join(dir, "Packages") {
		t.Errorf("Path = %q, want %q", errs[0].Path, filepath.Join(dir, "Packages"))
	}
	wantSubstr := "BDB-format rpmdb"
	if !contains(errs[0].Error, wantSubstr) {
		t.Errorf("Error message %q does not contain %q", errs[0].Error, wantSubstr)
	}
}

// ---------------------------------------------------------------------------
// osScanMode — SENTARI_SCAN_OS_PACKAGES env var contract.
// ---------------------------------------------------------------------------

func TestOsScanMode_DefaultIsPythonOnly(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "")
	if got := osScanMode(); got != "python_only" {
		t.Errorf("osScanMode() default = %q, want %q", got, "python_only")
	}
}

func TestOsScanMode_AllLiftsFilter(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	if got := osScanMode(); got != "all" {
		t.Errorf("osScanMode() = %q, want %q", got, "all")
	}
}

func TestOsScanMode_ArbitraryValuePreserved(t *testing.T) {
	// An unknown mode passes through; callers compare against "all" only,
	// so anything else is effectively "python_only".  We assert the raw
	// pass-through so a future mode can be added without changing osScanMode.
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "future_mode")
	if got := osScanMode(); got != "future_mode" {
		t.Errorf("osScanMode() = %q, want %q (env value should pass through)", got, "future_mode")
	}
}

// ---------------------------------------------------------------------------
// scanDebianViaStatusFile — confirms the SENTARI_SCAN_OS_PACKAGES filter
// behaves correctly across both modes.  Uses a TempDir-resident status
// fixture injected via dpkgStatusPath.
// ---------------------------------------------------------------------------

const debStatusFixture = `Package: python3
Version: 3.11.4-1
Status: install ok installed

Package: openssl
Version: 3.0.11-1ubuntu2
Status: install ok installed

Package: libssl3
Version: 3.0.11-1ubuntu2
Status: install ok installed

Package: nginx
Version: 1.24.0-1
Status: install ok installed
`

// setDpkgStatusPath swaps the package-level dpkgStatusPath at a TempDir
// fixture file and restores it on cleanup.
func setDpkgStatusPath(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "status")
	if err := os.WriteFile(fixture, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := dpkgStatusPath
	dpkgStatusPath = fixture
	t.Cleanup(func() { dpkgStatusPath = orig })
}

func TestScanDebianViaStatusFile_PythonOnlyModeFiltersOpenssl(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "python_only")
	setDpkgStatusPath(t, debStatusFixture)

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if _, ok := got["python3"]; !ok {
		t.Errorf("python_only: expected python3 to be emitted, got names: %v", keysOf(got))
	}
	if _, ok := got["openssl"]; ok {
		t.Errorf("python_only: openssl must NOT be emitted (got %+v)", got)
	}
	if _, ok := got["libssl3"]; ok {
		t.Errorf("python_only: libssl3 must NOT be emitted (got %+v)", got)
	}
	if _, ok := got["nginx"]; ok {
		t.Errorf("python_only: nginx must NOT be emitted (got %+v)", got)
	}
}

func TestScanDebianViaStatusFile_AllModeEmitsEverything(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	setDpkgStatusPath(t, debStatusFixture)

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	for _, name := range []string{"python3", "openssl", "libssl3", "nginx"} {
		if _, ok := got[name]; !ok {
			t.Errorf("mode=all: expected %q in emitted names, got %v", name, keysOf(got))
		}
	}
}

// keysOf returns map keys for stable error messages.
func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
