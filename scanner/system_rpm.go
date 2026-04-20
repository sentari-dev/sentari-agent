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
func scanRpmViaDatabase() ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var errors []ScanError

	dbPath := "/var/lib/rpm/rpmdb.sqlite"

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		errors = append(errors, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("open rpmdb: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}
	defer db.Close()

	// Join Name index with Packages blobs to get name + version in one pass.
	const query = `
		SELECT n.key, p.blob
		FROM Name n
		JOIN Packages p ON n.hnum = p.hnum
		WHERE n.key LIKE '%python%'
	`
	rows, err := db.Query(query)
	if err != nil {
		// Fallback: name-only query for older schema variants without Packages table.
		return scanRpmNameOnly(db, dbPath)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var blob []byte
		if err := rows.Scan(&name, &blob); err != nil {
			continue
		}
		version, license := parseRPMHeader(blob)
		if version == "" {
			version = "unknown"
		}
		pkg := PackageRecord{
			Name:    name,
			Version: version,
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
		errors = append(errors, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("read rows: %v", err),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, errors
}

// scanRpmNameOnly is a fallback for older rpmdb schemas where the Packages
// table is absent. Returns packages with version "unknown".
func scanRpmNameOnly(db *sql.DB, dbPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var errors []ScanError

	rows, err := db.Query(`SELECT key FROM Name WHERE key LIKE '%python%'`)
	if err != nil {
		errors = append(errors, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("query Name table: %v", err),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		packages = append(packages, PackageRecord{
			Name:    name,
			Version: "unknown",
		})
	}

	if err := rows.Err(); err != nil {
		errors = append(errors, ScanError{
			Path:      dbPath,
			EnvType:   EnvSystemRpm,
			Error:     fmt.Sprintf("read rows: %v", err),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, errors
}
