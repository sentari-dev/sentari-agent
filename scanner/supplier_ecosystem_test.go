package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPipSupplierFromMetadata proves the METADATA Author header lands on
// PackageRecord.Supplier end-to-end through scanPipEnvironment (Gap 1).
func TestPipSupplierFromMetadata(t *testing.T) {
	envDir := t.TempDir()
	site := filepath.Join(envDir, "lib", "python3.11", "site-packages")
	distInfo := filepath.Join(site, "requests-2.31.0.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"),
		[]byte("Name: requests\nVersion: 2.31.0\nAuthor: Kenneth Reitz\nAuthor-email: me@kennethreitz.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, errs := scanPipEnvironment(envDir)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	var found bool
	for _, p := range pkgs {
		if p.Name == "requests" {
			found = true
			if p.Supplier != "Kenneth Reitz" {
				t.Errorf("supplier = %q, want %q", p.Supplier, "Kenneth Reitz")
			}
		}
	}
	if !found {
		t.Fatal("requests not emitted")
	}
}

// TestDebSupplierCapturedAndEmailStripped proves the dpkg Maintainer: field is
// captured onto Supplier with its email stripped (SBOM-completeness v2 Gap 1).
func TestDebSupplierCapturedAndEmailStripped(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	setDpkgStatusPath(t, `Package: openssl
Version: 3.0.11-1ubuntu2
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Status: install ok installed
`)

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	var found bool
	for _, p := range pkgs {
		if p.Name == "openssl" {
			found = true
			if p.Supplier != "Ubuntu Developers" {
				t.Errorf("supplier = %q, want %q (email must be stripped)", p.Supplier, "Ubuntu Developers")
			}
		}
	}
	if !found {
		t.Fatal("openssl not emitted")
	}
}

// TestDebSupplierAbsentWhenNoMaintainer confirms a stanza without a Maintainer
// leaves Supplier empty (omitted on the wire).
func TestDebSupplierAbsentWhenNoMaintainer(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	setDpkgStatusPath(t, `Package: nomaint
Version: 1.0
Status: install ok installed
`)
	pkgs, _ := scanDebianViaStatusFile()
	for _, p := range pkgs {
		if p.Name == "nomaint" && p.Supplier != "" {
			t.Errorf("supplier = %q, want empty", p.Supplier)
		}
	}
}

// TestRpmHeaderSupplierPrefersVendor confirms parseRPMHeader returns VENDOR
// over PACKAGER, and PACKAGER only as a fallback.
func TestRpmHeaderSupplierPrefersVendor(t *testing.T) {
	blob := buildRPMHeaderBlobFull(0, "3.0.7", "27.el9", "Apache-2.0", "", "Red Hat, Inc.", "Fedora Project <build@fedoraproject.org>")
	_, _, _, supplier := parseRPMHeader(blob)
	if supplier != "Red Hat, Inc." {
		t.Errorf("supplier = %q, want VENDOR %q", supplier, "Red Hat, Inc.")
	}

	blobPackagerOnly := buildRPMHeaderBlobFull(0, "3.0.7", "27.el9", "Apache-2.0", "", "", "Fedora Project")
	_, _, _, supplier = parseRPMHeader(blobPackagerOnly)
	if supplier != "Fedora Project" {
		t.Errorf("packager fallback supplier = %q, want %q", supplier, "Fedora Project")
	}
}

// TestRpmScanSupplierNormalized proves the full rpm scan path lands a
// normalized (email-stripped) Supplier on the emitted record.
func TestRpmScanSupplierNormalized(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rpmdb.sqlite")
	buildRpmdbFixture(t, dbPath, true, []rpmFixtureRow{
		{"openssl", buildRPMHeaderBlobFull(1, "3.0.7", "27.el9", "Apache-2.0", "", "", "Red Hat Packaging <rel-eng@redhat.com>")},
	})
	orig := rpmdbSqlite
	rpmdbSqlite = dbPath
	t.Cleanup(func() { rpmdbSqlite = orig })

	pkgs, errs := scanRpmViaDatabase()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	var found bool
	for _, p := range pkgs {
		if p.Name == "openssl" {
			found = true
			if p.Supplier != "Red Hat Packaging" {
				t.Errorf("supplier = %q, want %q (email stripped)", p.Supplier, "Red Hat Packaging")
			}
		}
	}
	if !found {
		t.Fatal("openssl not emitted")
	}
}
