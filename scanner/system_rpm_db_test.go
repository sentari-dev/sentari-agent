package scanner

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// rpmdb SQLite scanning — exercises the real scan path against an in-test
// fixture built with the vendored pure-Go modernc driver.  A minimal but
// valid RPM header blob is synthesised in-process (buildRPMHeaderBlob) with
// the store layout parseRPMHeader expects, including a nonzero EPOCH entry.
// ---------------------------------------------------------------------------

// buildRPMHeaderBlob synthesises a big-endian RPM header blob matching the
// layout parseRPMHeader reads from the Packages.blob column:
//
//	[0:4]  nindex
//	[4:8]  hsize (data-store byte length)
//	[8:]   nindex × 16-byte index entries (tag, type, offset, count)
//	       followed by the data store
//
// EPOCH is emitted as an INT32; the remaining tags as null-terminated
// strings.  Empty strings and a zero epoch are omitted entirely.
func buildRPMHeaderBlob(epoch uint32, version, release, license, sourceRPM string) []byte {
	type entry struct {
		tag, typ uint32
		data     []byte
	}
	var entries []entry

	if epoch > 0 {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, epoch)
		entries = append(entries, entry{rpmTagEpoch, rpmTypeInt32, b})
	}
	addStr := func(tag uint32, s string) {
		if s == "" {
			return
		}
		entries = append(entries, entry{tag, rpmTypeString, append([]byte(s), 0)})
	}
	addStr(rpmTagVersion, version)
	addStr(rpmTagRelease, release)
	addStr(rpmTagLicense, license)
	addStr(rpmTagSourceRPM, sourceRPM)

	var store, index []byte
	for _, e := range entries {
		offset := len(store)
		ent := make([]byte, rpmEntrySize)
		binary.BigEndian.PutUint32(ent[0:4], e.tag)
		binary.BigEndian.PutUint32(ent[4:8], e.typ)
		binary.BigEndian.PutUint32(ent[8:12], uint32(offset))
		binary.BigEndian.PutUint32(ent[12:16], 1) // count
		index = append(index, ent...)
		store = append(store, e.data...)
	}

	blob := make([]byte, rpmBlobHeaderSize)
	binary.BigEndian.PutUint32(blob[0:4], uint32(len(entries)))
	binary.BigEndian.PutUint32(blob[4:8], uint32(len(store)))
	blob = append(blob, index...)
	blob = append(blob, store...)
	return blob
}

// rpmFixtureRow is one (name, header-blob) pair to seed into the fixture.
type rpmFixtureRow struct {
	name string
	blob []byte
}

// buildRpmdbFixture writes a fixture rpmdb.sqlite at path using the pure-Go
// modernc driver.  When withPackages is false the Packages blob table is
// omitted, forcing the name-only fallback query path.
func buildRpmdbFixture(t *testing.T, path string, withPackages bool, rows []rpmFixtureRow) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rwc")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE Name(key TEXT, hnum INTEGER)`); err != nil {
		t.Fatalf("create Name: %v", err)
	}
	if withPackages {
		if _, err := db.Exec(`CREATE TABLE Packages(hnum INTEGER, blob BLOB)`); err != nil {
			t.Fatalf("create Packages: %v", err)
		}
	}
	for i, r := range rows {
		hnum := i + 1
		if _, err := db.Exec(`INSERT INTO Name(key, hnum) VALUES(?, ?)`, r.name, hnum); err != nil {
			t.Fatalf("insert Name %q: %v", r.name, err)
		}
		if withPackages {
			if _, err := db.Exec(`INSERT INTO Packages(hnum, blob) VALUES(?, ?)`, hnum, r.blob); err != nil {
				t.Fatalf("insert Packages %q: %v", r.name, err)
			}
		}
	}
}

// pointRpmdbAt swaps the package-level rpmdb path vars so the scanner reads
// the SQLite fixture at sqlitePath and never matches a real host rpmdb.  The
// NDB/BDB paths are pointed at guaranteed-absent files inside the same dir so
// detectRpmDbFormat resolves to the SQLite branch deterministically.  Vars are
// restored on cleanup.  Named distinctly from setRpmPaths (owned elsewhere) to
// avoid a redeclaration collision.
func pointRpmdbAt(t *testing.T, sqlitePath string) {
	t.Helper()
	dir := filepath.Dir(sqlitePath)
	origSqlite, origNdb, origBdb := rpmdbSqlite, rpmdbNdb, rpmdbBdb
	rpmdbSqlite = sqlitePath
	rpmdbNdb = filepath.Join(dir, "does-not-exist-Packages.db")
	rpmdbBdb = filepath.Join(dir, "does-not-exist-Packages")
	t.Cleanup(func() {
		rpmdbSqlite = origSqlite
		rpmdbNdb = origNdb
		rpmdbBdb = origBdb
	})
}

func sha256Of(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return sha256.Sum256(b)
}

// TestScanRpmPackages_EpochPrefixedVersion — a package with a nonzero epoch
// surfaces the "epoch:version-release" EVR the server's splitter expects.
func TestScanRpmPackages_EpochPrefixedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	blob := buildRPMHeaderBlob(32, "9.16.23", "11.el9", "MIT", "python3-bind-9.16.23-11.el9.src.rpm")
	buildRpmdbFixture(t, path, true, []rpmFixtureRow{{"python3-bind", blob}})
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Version != "32:9.16.23-11.el9" {
		t.Errorf("Version = %q, want %q", pkgs[0].Version, "32:9.16.23-11.el9")
	}
	if pkgs[0].EnvType != EnvSystemRpm {
		t.Errorf("EnvType = %q, want %q", pkgs[0].EnvType, EnvSystemRpm)
	}
	if pkgs[0].SourcePackage != "python3-bind" {
		t.Errorf("SourcePackage = %q, want %q", pkgs[0].SourcePackage, "python3-bind")
	}
}

// TestScanRpmPackages_PythonOnlyVsAllFilter — the default python_only filter
// emits only python-named packages; SENTARI_SCAN_OS_PACKAGES=all lifts it.
func TestScanRpmPackages_PythonOnlyVsAllFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	rows := []rpmFixtureRow{
		{"python3-libs", buildRPMHeaderBlob(0, "3.9.18", "1.el9", "PSF", "")},
		{"openssl", buildRPMHeaderBlob(1, "3.0.7", "27.el9", "Apache-2.0", "")},
	}
	buildRpmdbFixture(t, path, true, rows)
	pointRpmdbAt(t, path)

	// Default mode → python-only.
	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("python_only scan errors: %+v", errs)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "python3-libs" {
		t.Fatalf("python_only got %+v, want just python3-libs", pkgs)
	}

	// all mode → both packages.
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	pkgs, errs = scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("all-mode scan errors: %+v", errs)
	}
	if len(pkgs) != 2 {
		t.Fatalf("all-mode got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
}

// TestScanRpmPackages_PythonOnlyMatchesDebPredicate — a pypy3/jython package
// carries no "python" substring, so the legacy `WHERE key LIKE '%python%'`
// filter silently dropped it on RHEL/Fedora/SUSE while a Debian host reported
// it (dpkg's isPythonPackage matches python/pip/pypy/jython).  The rpm path
// now applies the SAME isPythonPackage predicate in Go, so both scanners agree:
// pypy3 and jython are emitted in python_only mode, and a genuinely non-Python
// rpm (openssl) stays excluded there but appears under SENTARI_SCAN_OS_PACKAGES=all.
func TestScanRpmPackages_PythonOnlyMatchesDebPredicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	rows := []rpmFixtureRow{
		{"pypy3", buildRPMHeaderBlob(0, "7.3.15", "1.el9", "MIT", "")},
		{"jython", buildRPMHeaderBlob(0, "2.7.3", "1.el9", "PSF", "")},
		{"openssl", buildRPMHeaderBlob(1, "3.0.7", "27.el9", "Apache-2.0", "")},
	}
	buildRpmdbFixture(t, path, true, rows)
	pointRpmdbAt(t, path)

	// python_only (default): pypy3 + jython emitted, openssl excluded.
	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("python_only scan errors: %+v", errs)
	}
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.Name] = true
	}
	if !names["pypy3"] {
		t.Errorf("python_only dropped pypy3; want it emitted (no 'python' substring but Python-related)")
	}
	if !names["jython"] {
		t.Errorf("python_only dropped jython; want it emitted (no 'python' substring but Python-related)")
	}
	if names["openssl"] {
		t.Errorf("python_only emitted openssl; a non-Python rpm must be excluded")
	}
	if len(pkgs) != 2 {
		t.Fatalf("python_only got %d packages, want 2 (pypy3, jython): %+v", len(pkgs), pkgs)
	}

	// all mode: every package emitted, including openssl.
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	pkgs, errs = scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("all-mode scan errors: %+v", errs)
	}
	if len(pkgs) != 3 {
		t.Fatalf("all-mode got %d packages, want 3: %+v", len(pkgs), pkgs)
	}
}

// TestScanRpmPackages_NameOnlyPythonPredicate — the name-only fallback (no
// Packages blob table) applies the same isPythonPackage gate: pypy3/jython are
// kept and a non-Python rpm is dropped in python_only mode.
func TestScanRpmPackages_NameOnlyPythonPredicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	rows := []rpmFixtureRow{
		{"pypy3", nil},
		{"jython", nil},
		{"openssl", nil},
	}
	buildRpmdbFixture(t, path, false, rows) // no Packages table → name-only path
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.Name] = true
	}
	if !names["pypy3"] || !names["jython"] {
		t.Errorf("name-only fallback dropped pypy3/jython: got %+v", pkgs)
	}
	if names["openssl"] {
		t.Errorf("name-only fallback emitted non-Python openssl in python_only mode: got %+v", pkgs)
	}
	if len(pkgs) != 2 {
		t.Fatalf("name-only got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
}

// TestScanRpmPackages_MultilibDedup — a package installed for two arches
// (glibc.i686 + glibc.x86_64) has two Packages rows with identical name+EVR+
// source.  The v3 wire contract has no arch field, so both rows would emit
// byte-identical PackageRecords; the name+version+source dedup collapses them
// to ONE record.  Exercised under mode=all so glibc (non-Python) is emitted.
func TestScanRpmPackages_MultilibDedup(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	// Same name + identical EVR + identical source RPM for two arches.
	src := "glibc-2.34-100.el9.src.rpm"
	rows := []rpmFixtureRow{
		{"glibc", buildRPMHeaderBlob(0, "2.34", "100.el9", "LGPL-2.1-only", src)},
		{"glibc", buildRPMHeaderBlob(0, "2.34", "100.el9", "LGPL-2.1-only", src)},
	}
	buildRpmdbFixture(t, path, true, rows)
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (multilib duplicate must collapse): %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "glibc" || pkgs[0].Version != "2.34-100.el9" {
		t.Errorf("got %+v, want glibc 2.34-100.el9", pkgs[0])
	}
}

// TestScanRpmPackages_DistinctVersionsKept — two genuinely different versions
// of the same name differ in the dedup key and are BOTH retained (the dedup
// only collapses byte-identical multilib duplicates, never distinct versions).
func TestScanRpmPackages_DistinctVersionsKept(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	rows := []rpmFixtureRow{
		{"kernel", buildRPMHeaderBlob(0, "5.14.0", "100.el9", "GPL-2.0-only", "")},
		{"kernel", buildRPMHeaderBlob(0, "5.14.0", "200.el9", "GPL-2.0-only", "")},
	}
	buildRpmdbFixture(t, path, true, rows)
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (distinct versions must both be kept): %+v", len(pkgs), pkgs)
	}
}

// TestScanRpmPackages_MultilibDedupNameOnly — the name-only fallback (no
// Packages blob table) applies the same dedup: two Name rows for one package
// (one per arch) collapse to a single "unknown"-version record.
func TestScanRpmPackages_MultilibDedupNameOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	rows := []rpmFixtureRow{
		{"python3-libs", nil},
		{"python3-libs", nil},
	}
	buildRpmdbFixture(t, path, false, rows) // no Packages table → name-only path
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (name-only multilib duplicate must collapse): %+v", len(pkgs), pkgs)
	}
}

// TestScanRpmPackages_UnknownVersionFallback — an unparseable header blob
// yields the "unknown" version sentinel rather than an empty string.
func TestScanRpmPackages_UnknownVersionFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	// A too-short blob fails the parseRPMHeader length guard → "".
	buildRpmdbFixture(t, path, true, []rpmFixtureRow{{"python3-broken", []byte{0x00, 0x01}}})
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if pkgs[0].Version != "unknown" {
		t.Errorf("Version = %q, want %q", pkgs[0].Version, "unknown")
	}
}

// TestScanRpmPackages_NameOnlyFallback — when the Packages blob table is
// absent the JOIN query errors and the scanner falls back to the Name-only
// query, emitting packages with version "unknown".
func TestScanRpmPackages_NameOnlyFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	rows := []rpmFixtureRow{
		{"python3-libs", nil},
		{"python3-pip", nil},
	}
	buildRpmdbFixture(t, path, false, rows) // no Packages table
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Version != "unknown" {
			t.Errorf("%s Version = %q, want %q", p.Name, p.Version, "unknown")
		}
	}
}

// TestScanRpmPackages_DoesNotMutateFixture — scanning a present rpmdb reads
// only; the file's bytes are byte-identical before and after (proves the
// mode=ro open never triggers a write/journal rewrite of the db file).
func TestScanRpmPackages_DoesNotMutateFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	blob := buildRPMHeaderBlob(0, "3.9.18", "1.el9", "PSF", "")
	buildRpmdbFixture(t, path, true, []rpmFixtureRow{{"python3-libs", blob}})
	pointRpmdbAt(t, path)

	before := sha256Of(t, path)
	if _, errs := scanRpmPackages(); len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	after := sha256Of(t, path)
	if before != after {
		t.Errorf("fixture bytes changed by scan: %x != %x", before, after)
	}
}

// TestScanRpmPackages_NonexistentPathNoCreate — pointing the scanner at a
// nonexistent rpmdb neither errors nor creates any file on disk.
func TestScanRpmPackages_NonexistentPathNoCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	pointRpmdbAt(t, path)

	pkgs, errs := scanRpmPackages()
	if len(pkgs) != 0 {
		t.Errorf("got %d packages, want 0", len(pkgs))
	}
	if len(errs) != 0 {
		t.Errorf("got errors %+v, want none for absent rpmdb", errs)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("scan created %s (stat err = %v); rpmdb must never be created", path, err)
	}
}

// TestRpmdbFileURIReadOnly_NoCreate — the "file:...?mode=ro" DSN used by the
// scanner must NOT create a missing database file (unlike a plain path, which
// the modernc driver silently opens READWRITE|CREATE).
func TestRpmdbFileURIReadOnly_NoCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.sqlite")

	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	// sql.Open is lazy; force a real connection so the driver attempts the
	// open.  A read-only open of a missing file must fail, not create it.
	if err := db.Ping(); err == nil {
		t.Error("Ping succeeded on a missing read-only db; file was likely created")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("mode=ro created %s (stat err = %v); read-only must not create", path, err)
	}
}

// TestRpmdbFileURIReadOnly_WriteFails — a write against a "file:...?mode=ro"
// connection to an existing db must be rejected, proving the URI mode is
// honoured by the vendored modernc driver.
func TestRpmdbFileURIReadOnly_WriteFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpmdb.sqlite")
	buildRpmdbFixture(t, path, true, []rpmFixtureRow{
		{"python3-libs", buildRPMHeaderBlob(0, "3.9.18", "1.el9", "PSF", "")},
	})

	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE ShouldFail(x INTEGER)`); err == nil {
		t.Error("write against mode=ro connection succeeded; expected a read-only error")
	}
}
