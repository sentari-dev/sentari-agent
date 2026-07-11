package jvm

import (
	"fmt"
	"strings"
	"testing"
)

// TestExtractFromJar_PomRecordCapEnforced proves the per-outer-JAR
// record budget (maxRecordsPerJAR) is enforced across the *whole*
// extraction, not just the nested-jar descent.  A crafted archive whose
// central directory lists far more META-INF/maven/.../pom.properties
// entries than the cap must emit at most maxRecordsPerJAR records and a
// single "record cap exceeded" ScanError — never one record (or one
// error) per entry, which would let a tiny on-disk archive amplify into
// unbounded resident memory.
//
// The cap is lowered via the package var so the test stays cheap: we
// build a handful of entries above the lowered cap instead of 10 000.
func TestExtractFromJar_PomRecordCapEnforced(t *testing.T) {
	orig := maxRecordsPerJAR
	maxRecordsPerJAR = 5
	t.Cleanup(func() { maxRecordsPerJAR = orig })

	// Build well above the lowered cap so both the classification bound
	// and the emission cap have something to trip on.
	const nPoms = 12
	entries := map[string][]byte{}
	for i := 0; i < nPoms; i++ {
		id := fmt.Sprintf("lib%02d", i)
		entries[fmt.Sprintf("META-INF/maven/g/%s/pom.properties", id)] = []byte(
			fmt.Sprintf("groupId=g\nartifactId=%s\nversion=1\n", id))
	}
	jar := buildJAR(t, entries)

	records, errs := extractFromJar(jar)

	if len(records) != maxRecordsPerJAR {
		t.Fatalf("record cap not enforced: got %d records, want %d", len(records), maxRecordsPerJAR)
	}

	capErrs := 0
	for _, e := range errs {
		if strings.Contains(e.Error, "record cap exceeded") {
			capErrs++
		}
	}
	if capErrs != 1 {
		t.Fatalf("expected exactly one 'record cap exceeded' ScanError, got %d (errs=%+v)", capErrs, errs)
	}
	// Every emitted record must still be a well-formed coordinate — the
	// cap truncates, it does not corrupt.
	for _, r := range records {
		if !strings.HasPrefix(r.Name, "g:lib") {
			t.Errorf("unexpected record under cap: %+v", r)
		}
	}
}

// TestExtractFromJar_NormalUberJarUnaffectedByRecordCap is the negative
// control: a legitimate uber-jar with a handful of pom.properties (well
// under the cap) is fully extracted with no cap ScanError.  The cap only
// bites on abuse.
func TestExtractFromJar_NormalUberJarUnaffectedByRecordCap(t *testing.T) {
	jar := buildJAR(t, map[string][]byte{
		"META-INF/maven/org.a/lib-a/pom.properties": []byte("groupId=org.a\nartifactId=lib-a\nversion=1.0\n"),
		"META-INF/maven/org.b/lib-b/pom.properties": []byte("groupId=org.b\nartifactId=lib-b\nversion=2.0\n"),
		"META-INF/maven/org.c/lib-c/pom.properties": []byte("groupId=org.c\nartifactId=lib-c\nversion=3.0\n"),
	})

	records, errs := extractFromJar(jar)
	for _, e := range errs {
		if strings.Contains(e.Error, "record cap exceeded") {
			t.Fatalf("unexpected record-cap error on a normal uber-jar: %+v", errs)
		}
	}
	if len(records) != 3 {
		t.Fatalf("expected all 3 coordinates, got %d", len(records))
	}
}

// TestExtractFromJar_SharedRecordCapAcrossPomAndNested proves the cap is
// a SINGLE shared counter spanning both the pom.properties path and the
// nested-jar descent: a JAR mixing direct poms with a nested jar full of
// poms cannot exceed the cap by splitting records across the two paths.
//
// Cap lowered to 5.  Outer carries 3 direct poms (consuming 3 of the
// budget); a nested jar carries 4 more poms but only 2 of the remaining
// budget is left — so the total must be exactly 5, not 3+4=7.
func TestExtractFromJar_SharedRecordCapAcrossPomAndNested(t *testing.T) {
	orig := maxRecordsPerJAR
	maxRecordsPerJAR = 5
	t.Cleanup(func() { maxRecordsPerJAR = orig })

	inner := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/n/inner1/pom.properties": []byte("groupId=n\nartifactId=inner1\nversion=1\n"),
		"META-INF/maven/n/inner2/pom.properties": []byte("groupId=n\nartifactId=inner2\nversion=1\n"),
		"META-INF/maven/n/inner3/pom.properties": []byte("groupId=n\nartifactId=inner3\nversion=1\n"),
		"META-INF/maven/n/inner4/pom.properties": []byte("groupId=n\nartifactId=inner4\nversion=1\n"),
	})
	outer := buildJAR(t, map[string][]byte{
		"META-INF/maven/o/outer1/pom.properties": []byte("groupId=o\nartifactId=outer1\nversion=1\n"),
		"META-INF/maven/o/outer2/pom.properties": []byte("groupId=o\nartifactId=outer2\nversion=1\n"),
		"META-INF/maven/o/outer3/pom.properties": []byte("groupId=o\nartifactId=outer3\nversion=1\n"),
		"BOOT-INF/lib/inner.jar":                 inner,
	})

	records, errs := extractFromJar(outer)

	if len(records) != maxRecordsPerJAR {
		t.Fatalf("shared counter breached: got %d records, want %d (poms + nested must not exceed the cap together)",
			len(records), maxRecordsPerJAR)
	}
	// All three outer coordinates are processed before descent, so they
	// are always present; the nested jar contributes only what budget is
	// left.
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.Name] = true
	}
	for _, want := range []string{"o:outer1", "o:outer2", "o:outer3"} {
		if !seen[want] {
			t.Errorf("expected outer coordinate %q, got %v", want, seen)
		}
	}
	capErrs := 0
	for _, e := range errs {
		if strings.Contains(e.Error, "record cap exceeded") {
			capErrs++
		}
	}
	if capErrs == 0 {
		t.Fatalf("expected a 'record cap exceeded' ScanError from the truncated nested jar, got errs=%+v", errs)
	}
}
