package deptree

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestVersionRange covers two cases:
//
// (a) A dep declared with a version range and a matching artifact present in
//
//	~/.m2 → resolves to the installed artifact version, Resolved=true.
//
// (b) A dep declared with a version range but nothing installed in ~/.m2 →
//
//	keeps the range string verbatim, Resolved=false.
func TestVersionRange(t *testing.T) {
	t.Run("range_resolved_from_installed", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")

		// Install com.acme/ranged/1.4/ranged-1.4.pom — satisfies [1.0,2.0).
		rangedDir := filepath.Join(m2, "com", "acme", "ranged", "1.4")
		if err := os.MkdirAll(rangedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rangedDir, "ranged-1.4.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.acme</groupId><artifactId>ranged</artifactId><version>1.4</version>
</project>`), 0o644); err != nil {
			t.Fatal(err)
		}

		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>ranged</artifactId>
            <version>[1.0,2.0)</version>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(context.Background(), filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom failed: %v", err)
		}

		var rangedEdge *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.acme:ranged" {
				rangedEdge = &edges[i]
			}
		}
		if rangedEdge == nil {
			t.Fatalf("expected edge to com.acme:ranged; edges=%+v", edges)
		}
		if rangedEdge.ChildVersion != "1.4" {
			t.Errorf("com.acme:ranged version=%q; want 1.4 (resolved from installed cache artifact)", rangedEdge.ChildVersion)
		}
		if !rangedEdge.Resolved {
			t.Errorf("com.acme:ranged should be Resolved=true after range resolution")
		}
	})

	t.Run("range_unresolved_when_nothing_installed", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository") // empty

		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>ranged</artifactId>
            <version>[1.0,2.0)</version>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(context.Background(), filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom should not error: %v", err)
		}

		// May be dropped (no installed version) or emitted with verbatim range and Resolved=false.
		for _, e := range edges {
			if e.ChildName == "com.acme:ranged" {
				if e.Resolved {
					t.Errorf("com.acme:ranged should be Resolved=false when nothing installed; version=%q", e.ChildVersion)
				}
				if e.ChildVersion != "[1.0,2.0)" {
					t.Errorf("com.acme:ranged version should stay verbatim [1.0,2.0); got %q", e.ChildVersion)
				}
				return
			}
		}
		// Also acceptable: dep dropped entirely (no version → skip).
		t.Logf("com.acme:ranged not emitted (dropped due to unresolvable range) — acceptable")
	})

	t.Run("exact_range_bracket", func(t *testing.T) {
		// [1.5] means exactly 1.5.
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")

		exactDir := filepath.Join(m2, "com", "acme", "exact", "1.5")
		if err := os.MkdirAll(exactDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(exactDir, "exact-1.5.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.acme</groupId><artifactId>exact</artifactId><version>1.5</version>
</project>`), 0o644); err != nil {
			t.Fatal(err)
		}

		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>exact</artifactId>
            <version>[1.5]</version>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(context.Background(), filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom failed: %v", err)
		}
		var exactEdge *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.acme:exact" {
				exactEdge = &edges[i]
			}
		}
		if exactEdge == nil {
			t.Fatalf("expected edge to com.acme:exact; edges=%+v", edges)
		}
		if exactEdge.ChildVersion != "1.5" {
			t.Errorf("com.acme:exact version=%q; want 1.5 (resolved from [1.5] bracket)", exactEdge.ChildVersion)
		}
		if !exactEdge.Resolved {
			t.Errorf("com.acme:exact should be Resolved=true")
		}
	})

	// TestResolveVersionRange_malformedNoPanic guards against a panic on a
	// 1-char '[' or '(' (or empty) version. isVersionRange accepts these
	// because it only checks the first byte, but slicing s[1:len(s)-1] on a
	// 1-char string panics on the bounds. resolveVersionRange must bail out
	// (return "" / verbatim, Resolved=false) instead of crashing.
	t.Run("malformed_1char_range_no_panic", func(t *testing.T) {
		for _, bad := range []string{"[", "(", ""} {
			got := resolveVersionRange(t.TempDir(), "com.acme", "widget", bad)
			if got != "" {
				t.Errorf("resolveVersionRange(%q) = %q; want \"\" (clean skip)", bad, got)
			}
		}
	})

	// A pom whose dep carries a malformed 1-char range must not panic the
	// whole parse, and well-formed deps in the same pom must still emit.
	t.Run("malformed_range_in_pom_wellformed_still_emits", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")

		// A real installed artifact for the well-formed dep.
		goodDir := filepath.Join(m2, "com", "acme", "good", "1.0")
		if err := os.MkdirAll(goodDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(goodDir, "good-1.0.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.acme</groupId><artifactId>good</artifactId><version>1.0</version>
</project>`), 0o644); err != nil {
			t.Fatal(err)
		}

		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>broken</artifactId>
            <version>[</version>
        </dependency>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>good</artifactId>
            <version>1.0</version>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(context.Background(), filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom should not error on malformed range: %v", err)
		}

		var good *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.acme:good" {
				good = &edges[i]
			}
		}
		if good == nil {
			t.Fatalf("well-formed com.acme:good dep must still emit alongside malformed dep; edges=%+v", edges)
		}
		if good.ChildVersion != "1.0" || !good.Resolved {
			t.Errorf("com.acme:good wrong (want 1.0 Resolved=true): %+v", good)
		}
	})
}

// TestVersionRange_picksHighestNumericSegment covers the tie-break
// comparator (mavenVersionLess / mavenVersionCompare) that selects the
// highest satisfying installed version. With 1.2.0, 1.9.0 and 1.10.0 all
// installed and all satisfying [1.0,2.0), the resolver must pick 1.10.0.
// This forces numeric-segment ordering: a lexicographic sort would rank
// "1.9.0" above "1.10.0" (because "9" > "1") and pick the wrong version.
func TestVersionRange_picksHighestNumericSegment(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")

	// Install three satisfying versions of com.acme/multi.
	for _, v := range []string{"1.2.0", "1.9.0", "1.10.0"} {
		vDir := filepath.Join(m2, "com", "acme", "multi", v)
		if err := os.MkdirAll(vDir, 0o755); err != nil {
			t.Fatal(err)
		}
		pom := "<?xml version=\"1.0\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n" +
			"    <groupId>com.acme</groupId><artifactId>multi</artifactId><version>" + v + "</version>\n</project>"
		if err := os.WriteFile(filepath.Join(vDir, "multi-"+v+".pom"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pomDir := filepath.Join(dir, "project")
	if err := os.MkdirAll(pomDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>multi</artifactId>
            <version>[1.0,2.0)</version>
        </dependency>
    </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}

	edges, err := ParseMavenPom(context.Background(), filepath.Join(pomDir, "pom.xml"), m2)
	if err != nil {
		t.Fatalf("ParseMavenPom failed: %v", err)
	}

	var multi *DepEdge
	for i := range edges {
		if edges[i].ChildName == "com.acme:multi" {
			multi = &edges[i]
		}
	}
	if multi == nil {
		t.Fatalf("expected edge to com.acme:multi; edges=%+v", edges)
	}
	if multi.ChildVersion != "1.10.0" {
		t.Errorf("com.acme:multi version=%q; want 1.10.0 (highest satisfying, numeric-segment ordering)", multi.ChildVersion)
	}
	if !multi.Resolved {
		t.Errorf("com.acme:multi should be Resolved=true after range resolution")
	}
}
