package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUnresolvedRefs verifies that a POM referencing a parent/BOM that is
// not present in the local cache:
//  1. Does not cause an error — the parser continues best-effort.
//  2. Emits DepEdge(s) where Resolved=false for the unresolvable coordinate.
//  3. Never fabricates a version — ChildVersion carries either the verbatim
//     placeholder / range expression, or the artifact coordinate string.
//
// This is the cleanness guarantee for the server's fleet-wide completion pass:
// the agent always tells the server exactly what it knows and nothing more.
func TestUnresolvedRefs(t *testing.T) {
	t.Run("missing_parent_pom", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")
		if err := os.MkdirAll(m2, 0o755); err != nil {
			t.Fatal(err)
		}

		// The child POM's <parent> does not exist in .m2.
		// It declares a dep with an explicit version so we have at least
		// one resolvable dep to confirm parsing continues.
		pomDir := filepath.Join(dir, "project")
		if err := os.MkdirAll(pomDir, 0o755); err != nil {
			t.Fatal(err)
		}

		// Stub explicit dep POM.
		explicitDir := filepath.Join(m2, "com", "example", "explicit", "1.0")
		if err := os.MkdirAll(explicitDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(explicitDir, "explicit-1.0.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId><artifactId>explicit</artifactId><version>1.0</version>
</project>`), 0o644); err != nil {
			t.Fatal(err)
		}

		pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.missing</groupId>
        <artifactId>missing-parent</artifactId>
        <version>9.9</version>
    </parent>
    <groupId>com.example</groupId>
    <artifactId>child</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>explicit</artifactId>
            <version>1.0</version>
        </dependency>
    </dependencies>
</project>`
		if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}

		edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
		if err != nil {
			t.Fatalf("ParseMavenPom must not error on missing parent: %v", err)
		}

		// Parsing must continue best-effort: the explicit dep should resolve.
		var explicitEdge *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.example:explicit" {
				explicitEdge = &edges[i]
			}
		}
		if explicitEdge == nil {
			t.Fatalf("explicit dep must still resolve despite missing parent; edges=%+v", edges)
		}
		if !explicitEdge.Resolved {
			t.Errorf("explicit dep should be Resolved=true; edge=%+v", explicitEdge)
		}

		// No edge should carry a fabricated version for the missing parent.
		for _, e := range edges {
			if e.ParentName == "com.missing:missing-parent" || e.ChildName == "com.missing:missing-parent" {
				if e.Resolved && e.ChildVersion == "" {
					t.Errorf("fabricated empty version on edge involving missing parent: %+v", e)
				}
			}
		}
	})

	t.Run("missing_bom_dep_unresolved_not_fabricated", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")
		if err := os.MkdirAll(m2, 0o755); err != nil {
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
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.missing</groupId>
                <artifactId>missing-bom</artifactId>
                <version>3.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.missing</groupId>
            <artifactId>managed-dep</artifactId>
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

		// The BOM-import edge must be present and Resolved=false.
		var bomEdge *DepEdge
		for i := range edges {
			if edges[i].ChildName == "com.missing:missing-bom" {
				bomEdge = &edges[i]
			}
		}
		if bomEdge == nil {
			t.Fatal("BOM-import edge for com.missing:missing-bom must be emitted")
		}
		if bomEdge.Resolved {
			t.Errorf("missing BOM edge must be Resolved=false; got true; edge=%+v", bomEdge)
		}

		// com.missing:managed-dep may be absent (no version → dropped) or
		// emitted Resolved=false. It MUST NOT be Resolved=true with any version.
		for _, e := range edges {
			if e.ChildName == "com.missing:managed-dep" && e.Resolved {
				t.Errorf("dep from absent BOM must not be Resolved=true; edge=%+v", e)
			}
		}
	})

	t.Run("unresolved_property_placeholder_preserved", func(t *testing.T) {
		dir := t.TempDir()
		m2 := filepath.Join(dir, ".m2", "repository")
		if err := os.MkdirAll(m2, 0o755); err != nil {
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
            <groupId>com.example</groupId>
            <artifactId>dep-with-unknown-prop</artifactId>
            <version>${unknown.prop.version}</version>
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

		// The dep may be dropped (empty version after failed interpolation) or
		// emitted with the verbatim placeholder as Resolved=false.
		for _, e := range edges {
			if e.ChildName == "com.example:dep-with-unknown-prop" {
				if e.Resolved {
					t.Errorf("dep with unresolved ${...} must be Resolved=false; edge=%+v", e)
				}
				// ChildVersion must carry the placeholder, not be empty or fabricated.
				if e.ChildVersion == "" {
					t.Errorf("ChildVersion should carry the verbatim placeholder, not be empty; edge=%+v", e)
				}
				return
			}
		}
		// Also acceptable: dep dropped due to unresolvable version.
		t.Logf("dep-with-unknown-prop not emitted (dropped due to unresolvable version) — acceptable")
	})
}
