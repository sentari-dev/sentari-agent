package jvm

import (
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestExtractFromJar_SpringBootNested reproduces the Spring Boot
// uber-jar shape: an outer JAR whose own pom.properties describes the
// application, plus multiple nested JARs under ``BOOT-INF/lib/`` —
// each of which is a dependency with its own Maven coordinates.
//
// The product invariant: we emit **every** coordinate we can find,
// outer + nested.  A tool that only reported the outer JAR would miss
// every transitive dependency's CVE — which is the whole reason we're
// doing deployed-state scanning rather than manifest-reading.
func TestExtractFromJar_SpringBootNested(t *testing.T) {
	innerA := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/org.springframework/spring-core/pom.properties": []byte(
			"groupId=org.springframework\nartifactId=spring-core\nversion=6.1.0\n",
		),
	})
	innerB := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/com.fasterxml.jackson.core/jackson-core/pom.properties": []byte(
			"groupId=com.fasterxml.jackson.core\nartifactId=jackson-core\nversion=2.15.3\n",
		),
	})

	outer := buildJAR(t, map[string][]byte{
		"META-INF/maven/com.customer/myapp/pom.properties": []byte(
			"groupId=com.customer\nartifactId=myapp\nversion=1.0.0\n",
		),
		// Spring Boot convention.
		"BOOT-INF/lib/spring-core-6.1.0.jar":    innerA,
		"BOOT-INF/lib/jackson-core-2.15.3.jar":  innerB,
		// Non-jar file in the same directory is ignored (defensive).
		"BOOT-INF/lib/LICENSE.txt": []byte("Apache 2.0\n"),
	})

	records, errs := extractFromJar(outer)
	if len(errs) > 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	// Expect: 1 outer + 2 inner = 3 records.
	if len(records) != 3 {
		t.Fatalf("expected 3 records (outer app + 2 nested deps), got %d: %+v",
			len(records), records)
	}

	// The outer app record carries the physical path only.
	// The nested deps carry ``<outer>!/BOOT-INF/lib/<inner>.jar`` so an
	// operator can tell at a glance which uber-jar the dep came from.
	names := map[string]scanner.PackageRecord{}
	for _, r := range records {
		names[r.Name] = r
	}

	app, ok := names["com.customer:myapp"]
	if !ok {
		t.Fatalf("missing outer app record; got names: %v", keysOf(names))
	}
	if app.InstallPath != outer {
		t.Errorf("outer app InstallPath: got %q want %q", app.InstallPath, outer)
	}

	spring, ok := names["org.springframework:spring-core"]
	if !ok {
		t.Fatalf("missing nested spring-core record; got names: %v", keysOf(names))
	}
	wantSpringPath := outer + "!/BOOT-INF/lib/spring-core-6.1.0.jar"
	if spring.InstallPath != wantSpringPath {
		t.Errorf("nested spring-core InstallPath:\n got %q\nwant %q",
			spring.InstallPath, wantSpringPath)
	}

	if _, ok := names["com.fasterxml.jackson.core:jackson-core"]; !ok {
		t.Fatalf("missing nested jackson-core record; got names: %v", keysOf(names))
	}
}

// TestExtractFromJar_QuarkusNested covers the Quarkus uber-jar shape,
// which uses ``quarkus-app/lib/main/`` and ``quarkus-app/lib/boot/``
// rather than Spring Boot's ``BOOT-INF/lib/``.  The scanner is
// deliberately path-agnostic — it descends into any ``.jar`` entry it
// finds — so both layouts Just Work without per-framework code.
func TestExtractFromJar_QuarkusNested(t *testing.T) {
	inner := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/io.quarkus/quarkus-core/pom.properties": []byte(
			"groupId=io.quarkus\nartifactId=quarkus-core\nversion=3.7.0\n",
		),
	})
	outer := buildJAR(t, map[string][]byte{
		"META-INF/maven/com.customer/quarkus-service/pom.properties": []byte(
			"groupId=com.customer\nartifactId=quarkus-service\nversion=1.0\n",
		),
		"quarkus-app/lib/main/io.quarkus.quarkus-core-3.7.0.jar": inner,
	})

	records, errs := extractFromJar(outer)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records (outer + 1 nested), got %d", len(records))
	}
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.Name] = true
	}
	if !seen["io.quarkus:quarkus-core"] {
		t.Errorf("expected io.quarkus:quarkus-core from nested jar, got %v", keysOf2(seen))
	}
}

// TestExtractFromJar_DepthCapRespected builds a 5-level-deep chain of
// nested JARs (outer → d1 → d2 → d3 → d4) and asserts the scanner
// extracts records through depth 3 inclusive, then emits a ScanError
// naming the depth-4 path and does NOT recurse further.  Without the
// cap a malicious JAR could recurse indefinitely and OOM the scanner.
func TestExtractFromJar_DepthCapRespected(t *testing.T) {
	// Build from the inside out.
	d4Bytes := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/d/four/pom.properties": []byte(
			"groupId=d\nartifactId=four\nversion=4\n",
		),
	})
	d3Bytes := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/d/three/pom.properties": []byte(
			"groupId=d\nartifactId=three\nversion=3\n",
		),
		"lib/d4.jar": d4Bytes,
	})
	d2Bytes := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/d/two/pom.properties": []byte(
			"groupId=d\nartifactId=two\nversion=2\n",
		),
		"lib/d3.jar": d3Bytes,
	})
	d1Bytes := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/d/one/pom.properties": []byte(
			"groupId=d\nartifactId=one\nversion=1\n",
		),
		"lib/d2.jar": d2Bytes,
	})
	outer := buildJAR(t, map[string][]byte{
		"META-INF/maven/d/outer/pom.properties": []byte(
			"groupId=d\nartifactId=outer\nversion=0\n",
		),
		"lib/d1.jar": d1Bytes,
	})

	records, errs := extractFromJar(outer)

	// Depths 0..3 should all have produced a record; depth 4 should
	// have triggered a ScanError and zero records.
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.Name] = true
	}
	for _, want := range []string{"d:outer", "d:one", "d:two", "d:three"} {
		if !seen[want] {
			t.Errorf("expected record %q (within depth cap), got %v", want, keysOf2(seen))
		}
	}
	if seen["d:four"] {
		t.Errorf("unexpected depth-4 record emitted; cap was not enforced")
	}

	// Exactly one ScanError should be present, mentioning the depth
	// cap and the offending virtual path.
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 depth-cap ScanError, got %d: %+v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error, "depth") {
		t.Errorf("ScanError should mention depth cap, got %q", errs[0].Error)
	}
	// The path must point at the depth-4 jar (d4.jar nested inside d3).
	if !strings.Contains(errs[0].Path, "d4.jar") {
		t.Errorf("ScanError path should identify the offending nested jar, got %q", errs[0].Path)
	}
}

// TestExtractFromJar_NestedCorruptedSurfacesAsScanError: a nested
// entry whose name ends in .jar but whose bytes are not a valid zip
// must produce a ScanError rather than panic, and must not prevent
// the outer JAR's own identity extraction.  Regression guard for
// "one bad nested dep tombstones the whole uber-jar scan."
func TestExtractFromJar_NestedCorruptedSurfacesAsScanError(t *testing.T) {
	outer := buildJAR(t, map[string][]byte{
		"META-INF/maven/o/a/pom.properties": []byte("groupId=o\nartifactId=a\nversion=1\n"),
		"BOOT-INF/lib/corrupt.jar":          []byte("not a zip, lying about it"),
	})

	records, errs := extractFromJar(outer)

	// Outer identity must still be present.
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.Name] = true
	}
	if !seen["o:a"] {
		t.Errorf("outer identity record lost due to nested corruption; got %v", keysOf2(seen))
	}
	// At least one error naming the corrupt nested path.
	foundNestedErr := false
	for _, e := range errs {
		if strings.Contains(e.Path, "corrupt.jar") {
			foundNestedErr = true
			break
		}
	}
	if !foundNestedErr {
		t.Errorf("expected ScanError for corrupt nested jar, got errs: %+v", errs)
	}
}

// TestExtractFromJar_NestedIdentityIsolatedFromOuter verifies that the
// outer JAR's pom.properties is not accidentally emitted twice (once
// as "outer identity", once because the recursion sees it again).
// Regression guard if the author forgets to seed the recursion's
// skip-outer-identity set correctly.
func TestExtractFromJar_NestedIdentityIsolatedFromOuter(t *testing.T) {
	inner := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/inner/dep/pom.properties": []byte(
			"groupId=inner\nartifactId=dep\nversion=2\n",
		),
	})
	outer := buildJAR(t, map[string][]byte{
		"META-INF/maven/outer/app/pom.properties": []byte(
			"groupId=outer\nartifactId=app\nversion=1\n",
		),
		"BOOT-INF/lib/inner.jar": inner,
	})

	records, _ := extractFromJar(outer)
	count := map[string]int{}
	for _, r := range records {
		count[r.Name]++
	}
	if count["outer:app"] != 1 {
		t.Errorf("outer:app should appear exactly once, got %d", count["outer:app"])
	}
	if count["inner:dep"] != 1 {
		t.Errorf("inner:dep should appear exactly once, got %d", count["inner:dep"])
	}
}

// ---------------------------------------------------------------------------
// local helpers
// ---------------------------------------------------------------------------

func keysOf(m map[string]scanner.PackageRecord) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOf2(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
