package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBomImport covers two cases for import-scoped dependencyManagement entries:
//
// (a) BOM POM present on disk → a versionless dep resolves to the version
//
//	managed by the BOM, Resolved=true.
//
// (b) BOM coordinate absent from disk → dep stays Resolved=false (preserves
//
//	TestParseMavenPom_bomImportEmitsUnresolved semantics).
func TestBomImport(t *testing.T) {
	t.Run("bom_on_disk_resolves_dep", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")

		// BOM POM: manages com.acme:widget:5.0.
		bomDir := filepath.Join(m2, "com", "acme", "platform-bom", "2.0")
		if err := os.MkdirAll(bomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		bomPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.acme</groupId>
    <artifactId>platform-bom</artifactId>
    <version>2.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.acme</groupId>
                <artifactId>widget</artifactId>
                <version>5.0</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>`
		if err := os.WriteFile(filepath.Join(bomDir, "platform-bom-2.0.pom"), []byte(bomPom), 0o644); err != nil {
			t.Fatal(err)
		}

		// Stub dep POM so BFS recursion terminates normally.
		widgetDir := filepath.Join(m2, "com", "acme", "widget", "5.0")
		if err := os.MkdirAll(widgetDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(widgetDir, "widget-5.0.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.acme</groupId><artifactId>widget</artifactId><version>5.0</version>
</project>`), 0o644); err != nil {
			t.Fatal(err)
		}

		// Root POM: imports the BOM; declares a dep on com.acme:widget with no version.
		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		rootPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.acme</groupId>
                <artifactId>platform-bom</artifactId>
                <version>2.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>widget</artifactId>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(rootPom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom failed: %v", err)
		}

		var widgetEdge *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.acme:widget" && edges[i].Type == "direct" {
				widgetEdge = &edges[i]
			}
		}
		if widgetEdge == nil {
			t.Fatalf("expected direct edge to com.acme:widget; edges=%+v", edges)
		}
		if widgetEdge.ChildVersion != "5.0" {
			t.Errorf("com.acme:widget version=%q; want 5.0 (resolved from BOM-managed version)", widgetEdge.ChildVersion)
		}
		if !widgetEdge.Resolved {
			t.Errorf("com.acme:widget edge should be Resolved=true; got false")
		}
	})

	t.Run("bom_absent_dep_unresolved", func(t *testing.T) {
		// This mirrors TestParseMavenPom_bomImportEmitsUnresolved: BOM not on
		// disk → the dep can't be version-resolved, stays Resolved=false.
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository") // empty

		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}
		rootPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0</version>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.missing</groupId>
                <artifactId>absent-bom</artifactId>
                <version>1.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.missing</groupId>
            <artifactId>some-dep</artifactId>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(rootPom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom should not error: %v", err)
		}

		// The BOM import edge itself should appear (Resolved=false).
		var bomEdge *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.missing:absent-bom" {
				bomEdge = &edges[i]
			}
		}
		if bomEdge == nil {
			t.Fatal("expected BOM-import edge for com.missing:absent-bom")
		}
		if bomEdge.Resolved {
			t.Errorf("absent BOM edge should be Resolved=false")
		}

		// com.missing:some-dep has no version (BOM absent) — must NOT have a
		// fabricated version; may be absent (dropped) or emitted unresolved.
		for _, e := range edges {
			if e.ChildName == "com.missing:some-dep" && e.Resolved {
				t.Errorf("dep from absent BOM should not be Resolved=true; edge=%+v", e)
			}
		}
	})
}
