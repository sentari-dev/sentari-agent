package deptree

import (
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

		edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
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

		edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
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

		edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
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
}
