package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

// rpmdb file-format candidates.  RHEL 9+ and Fedora 38+ ship the SQLite
// backend; some EL8 installs ship the NDB ("New Database") variant; RHEL 7
// and EL7 ship the legacy Berkeley DB.  Sentari currently only supports
// the SQLite layout — the others are detected explicitly and surface as
// ScanErrors so operators understand why their rpmdb returned nothing
// (previously these hosts silently produced zero packages).
//
// Declared as vars rather than consts so tests can point them at a
// TempDir to exercise each detection branch.
var (
	rpmdbSqlite = "/var/lib/rpm/rpmdb.sqlite" // RHEL 9+, Fedora 38+
	rpmdbNdb    = "/var/lib/rpm/Packages.db"  // EL8 NDB variant
	rpmdbBdb    = "/var/lib/rpm/Packages"     // RHEL 7 / EL7
)

// detectRpmDbFormat probes the three known rpmdb layouts and returns the
// SQLite path when it exists.  For the NDB and BDB variants it returns
// an explicit ScanError so callers can surface "not yet supported" rather
// than silently emitting an empty package list.  When no rpmdb file is
// found at all, it returns "", nil — the caller decides whether that is
// an error in context.
func detectRpmDbFormat() (string, []ScanError) {
	if _, err := os.Stat(rpmdbSqlite); err == nil {
		return rpmdbSqlite, nil
	}
	if _, err := os.Stat(rpmdbNdb); err == nil {
		return "", []ScanError{{
			Path:      rpmdbNdb,
			EnvType:   EnvSystemRpm,
			Error:     "NDB-format rpmdb (RHEL 8 NDB variant) — not yet supported by Sentari agent",
			Timestamp: time.Now().UTC(),
		}}
	}
	if _, err := os.Stat(rpmdbBdb); err == nil {
		return "", []ScanError{{
			Path:      rpmdbBdb,
			EnvType:   EnvSystemRpm,
			Error:     "BDB-format rpmdb (RHEL 7/EL7) — upgrade to RHEL 8+ for support",
			Timestamp: time.Now().UTC(),
		}}
	}
	return "", nil // no rpmdb found at all
}

// rpmScanner discovers system-installed Python packages on RHEL/Fedora
// by querying /var/lib/rpm/rpmdb.sqlite directly.  Like debScanner, its
// source is a fixed OS path → RootScanner.
type rpmScanner struct{}

func (rpmScanner) EnvType() string { return EnvSystemRpm }

func (rpmScanner) DiscoverAll(ctx context.Context) ([]Environment, []ScanError) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	// Same scope gate as debScanner — scoped runs shouldn't pull in every
	// system-wide Python from the rpmdb.
	if !IsFullSystemScan(ctx) {
		return nil, nil
	}
	if _, err := os.Stat("/var/lib/rpm"); err != nil {
		return nil, nil
	}
	return []Environment{{
		EnvType: EnvSystemRpm,
		Path:    "/var/lib/rpm",
		Name:    "rpm",
	}}, nil
}

func (rpmScanner) Scan(_ context.Context, _ Environment) ([]PackageRecord, []ScanError) {
	return scanRpmPackages()
}

func init() {
	Register(rpmScanner{})
}

// scanRpmPackages scans system-installed Python packages on RHEL/CentOS/Fedora
// by reading the RPM SQLite database directly — no binary invocation.
func scanRpmPackages() ([]PackageRecord, []ScanError) {
	pkgs, errs := scanRpmViaDatabase()

	for i := range pkgs {
		pkgs[i].EnvType = EnvSystemRpm
		pkgs[i].Environment = "system"
		pkgs[i].InstallDate = ""
	}

	return pkgs, errs
}

// scanRpmViaDatabase queries /var/lib/rpm/rpmdb.sqlite (RHEL 9+ schema).
// It joins the Name index table with the Packages blob table to obtain both
// the package name and version by parsing the binary RPM header.
//
// NDB- and BDB-format rpmdbs (RHEL 7/8 variants) are detected up front and
// surface a ScanError instead of silently returning zero packages.
func scanRpmViaDatabase() ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var scanErrs []ScanError

	dbPath, formatErrs := detectRpmDbFormat()
	if dbPath == "" {
		return packages, formatErrs
	}

	// Use the "file:" URI form so the modernc SQLite driver honours
	// mode=ro.  On a plain path the driver silently discards the query
	// string and opens READWRITE|CREATE, which would create/mutate the
	// host rpmdb — a charter violation (agents never write host state).
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("open rpmdb: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}
	defer db.Close()

	// Default behaviour (osScanMode == "python_only") bounds the rows the
	// SQLite driver materialises with the cheap Name-index prefilter below,
	// then applies isPythonPackage in Go as the AUTHORITATIVE membership
	// test — the same predicate system_deb.go uses.  That parity matters:
	// an rpm-installed pypy/pypy3 (EPEL) or jython carries no "python"
	// substring, so a bare LIKE '%python%' filter would silently drop it on
	// RHEL/Fedora/SUSE while a Debian host reports it.  The LIKE list mirrors
	// isPythonPackage's patterns purely as a row-bounding optimisation;
	// isPythonPackage remains the single source of truth for what counts as
	// a Python package.  Setting SENTARI_SCAN_OS_PACKAGES=all lifts both the
	// SQL prefilter and the Go gate so curated CPE entries for non-Python OS
	// packages (openssl, glibc, libssl3, ...) can fire on the server side.
	pythonOnly := osScanMode() != "all"
	query := `
		SELECT n.key, p.blob
		FROM Name n
		JOIN Packages p ON n.hnum = p.hnum
		WHERE n.key LIKE '%python%'
		   OR n.key LIKE '%pip%'
		   OR n.key LIKE '%pypy%'
		   OR n.key LIKE '%jython%'
	`
	if !pythonOnly {
		query = `
			SELECT n.key, p.blob
			FROM Name n
			JOIN Packages p ON n.hnum = p.hnum
		`
	}
	rows, err := db.Query(query)
	if err != nil {
		// Fallback: name-only query for older schema variants without Packages table.
		return scanRpmNameOnly(db, dbPath)
	}
	defer rows.Close()

	// seen de-duplicates byte-identical records.  On a multilib RHEL/Fedora
	// host a package installed for two arches (glibc.i686 AND glibc.x86_64)
	// has two Packages rows with identical name+EVR+source; the v3 wire
	// contract has no architecture field, so both would emit indistinguishable
	// PackageRecords and double-count in inventory/CVE.  The key is the full
	// wire identity name+version+source: two rows sharing it emit byte-identical
	// records, so keeping one is lossless; genuinely different versions of the
	// same name differ in the key and are both kept.  Mirrors system_deb.go.
	seen := make(map[string]struct{})
	for rows.Next() {
		var name string
		var blob []byte
		if err := rows.Scan(&name, &blob); err != nil {
			continue
		}
		// Authoritative python_only gate — shared with system_deb.go so both
		// scanners agree on the definition of a Python package.
		if pythonOnly && !isPythonPackage(name) {
			continue
		}
		version, license, source := parseRPMHeader(blob)
		if version == "" {
			version = "unknown"
		}
		key := name + "\x00" + version + "\x00" + source
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkg := PackageRecord{
			Name:          name,
			Version:       version,
			SourcePackage: source,
		}
		if license != "" {
			pkg.LicenseRaw = license
			pkg.LicenseSPDX, pkg.LicenseTier = NormalizeLicense(license)
		} else {
			pkg.LicenseTier = "unknown"
		}
		packages = append(packages, pkg)
	}

	if err := rows.Err(); err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("read rows: %v", err),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, scanErrs
}

// scanRpmNameOnly is a fallback for older rpmdb schemas where the Packages
// table is absent. Returns packages with version "unknown".
func scanRpmNameOnly(db *sql.DB, dbPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var scanErrs []ScanError

	// Same prefilter-plus-Go-gate strategy as the JOIN path above: the LIKE
	// list only bounds rows, and isPythonPackage is the authoritative test
	// so pypy/pypy3/jython (no "python" substring) survive in python_only
	// mode, matching system_deb.go.
	pythonOnly := osScanMode() != "all"
	q := `SELECT key FROM Name
		WHERE key LIKE '%python%'
		   OR key LIKE '%pip%'
		   OR key LIKE '%pypy%'
		   OR key LIKE '%jython%'`
	if !pythonOnly {
		q = `SELECT key FROM Name`
	}
	rows, err := db.Query(q)
	if err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("query Name table: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}
	defer rows.Close()

	// Same multilib dedup as scanRpmViaDatabase: multiple Name rows for one
	// package (one per installed arch) collapse to a single record on the
	// name+version+source wire identity.  Here version is always "unknown"
	// and source empty, so multilib rows for a name share the key losslessly.
	seen := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		if pythonOnly && !isPythonPackage(name) {
			continue
		}
		key := name + "\x00" + "unknown" + "\x00" + ""
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, PackageRecord{
			Name:    name,
			Version: "unknown",
		})
	}

	if err := rows.Err(); err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("read rows: %v", err),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, scanErrs
}

// osScanMode returns the active OS package-scan mode.  Values:
//
//   - "python_only" (default, backward-compatible) — apply the
//     isPythonPackage filter; only Python-related packages are emitted.
//   - "all" — emit every installed OS package; lets curated CPE entries
//     for non-Python packages (openssl, glibc, libssl3, ...) match on
//     the server.
//
// The variable name is shared between system_rpm.go and system_deb.go so
// that the two scanners always agree on intent.
func osScanMode() string {
	v := os.Getenv("SENTARI_SCAN_OS_PACKAGES")
	if v == "" {
		return "python_only"
	}
	return v
}
