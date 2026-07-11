package scanner

import (
	"strings"
	"testing"
)

// --- Finding 1: multi-arch de-duplication -----------------------------------

// debStatusMultiArchFixture is a multi-arch host: libssl3 appears once per
// architecture (amd64 + i386) at the SAME Version, plus glibc at two DIFFERENT
// versions.  Because the v3 wire contract carries no architecture field, the
// two libssl3 stanzas would serialize to byte-identical PackageRecords and must
// collapse to one; the two glibc versions are genuinely distinct and both stay.
const debStatusMultiArchFixture = `Package: libssl3
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1ubuntu2
Source: openssl

Package: libssl3
Status: install ok installed
Architecture: i386
Version: 3.0.11-1ubuntu2
Source: openssl

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.35-0ubuntu3
Source: glibc

Package: libc6
Status: install ok installed
Architecture: i386
Version: 2.36-0ubuntu1
Source: glibc
`

func countName(pkgs []PackageRecord, name string) int {
	n := 0
	for _, p := range pkgs {
		if p.Name == name {
			n++
		}
	}
	return n
}

func TestScanDebianViaStatusFile_MultiArchDedupesIdentical(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "all")
	setDpkgStatusPath(t, debStatusMultiArchFixture)

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}

	// libssl3 amd64 + i386 at the same version → exactly ONE record.
	if got := countName(pkgs, "libssl3"); got != 1 {
		t.Errorf("libssl3 (same version, two arches) = %d records, want 1", got)
	}

	// libc6 at two different versions → BOTH kept.
	if got := countName(pkgs, "libc6"); got != 2 {
		t.Errorf("libc6 (two distinct versions) = %d records, want 2", got)
	}
	versions := map[string]bool{}
	for _, p := range pkgs {
		if p.Name == "libc6" {
			versions[p.Version] = true
		}
	}
	for _, v := range []string{"2.35-0ubuntu3", "2.36-0ubuntu1"} {
		if !versions[v] {
			t.Errorf("libc6 version %q missing from emitted records: %v", v, versions)
		}
	}
}

// --- Finding 2: oversized field must not truncate remaining inventory -------

// A dpkg Depends:/Provides: line on a big metapackage is a single unfolded
// line that can exceed bufio's default 64 KiB token cap.  With the default
// buffer, Scan returns bufio.ErrTooLong and every stanza after the oversized
// one is silently dropped.  The raised buffer must keep parsing.
func TestScanDebianViaStatusFile_OversizedLineDoesNotTruncate(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "python_only")

	// A Depends: field ~128 KiB long — well past the 64 KiB default cap.
	bigDepends := "Depends: " + strings.Repeat("libpython3-dep-000000, ", 6000)

	var b strings.Builder
	b.WriteString("Package: python3-meta\n")
	b.WriteString("Version: 1.0.0\n")
	b.WriteString("Status: install ok installed\n")
	b.WriteString(bigDepends + "\n")
	b.WriteString("\n")
	// The trailing stanza must still be emitted despite the giant line above.
	b.WriteString("Package: python3-after\n")
	b.WriteString("Version: 2.0.0\n")
	b.WriteString("Status: install ok installed\n")

	setDpkgStatusPath(t, b.String())

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors (oversized line should not error): %+v", errs)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Name] = true
	}
	if !got["python3-meta"] {
		t.Errorf("python3-meta (stanza with oversized Depends) missing: %v", got)
	}
	if !got["python3-after"] {
		t.Errorf("python3-after (stanza AFTER oversized line) was dropped — buffer not raised: %v", got)
	}
}
