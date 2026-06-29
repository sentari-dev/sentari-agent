package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParentChain verifies that a child POM with <parent> correctly inherits:
//   - <properties> declared by the parent (used in dependencyManagement version)
//   - <dependencyManagement> entries from the parent
//
// so that a versionless dep in the child resolves to the parent-managed version.
func TestParentChain(t *testing.T) {
	// Build a temp .m2 layout:
	//   com/acme/platform/1.0/platform-1.0.pom  — parent POM
	//   com/acme/lib/3.2/lib-3.2.pom            — the managed dep
	//   child/pom.xml                            — child POM with <parent>
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")

	parentPomDir := filepath.Join(m2, "com", "acme", "platform", "1.0")
	if err := os.MkdirAll(parentPomDir, 0o755); err != nil {
		t.Fatal(err)
	}
	libPomDir := filepath.Join(m2, "com", "acme", "lib", "3.2")
	if err := os.MkdirAll(libPomDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Parent POM: declares property + dependencyManagement using ${lib.version}.
	parentPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.acme</groupId>
    <artifactId>platform</artifactId>
    <version>1.0</version>
    <properties>
        <lib.version>3.2</lib.version>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.acme</groupId>
                <artifactId>lib</artifactId>
                <version>${lib.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
</project>`
	if err := os.WriteFile(filepath.Join(parentPomDir, "platform-1.0.pom"), []byte(parentPom), 0o644); err != nil {
		t.Fatal(err)
	}

	// Stub lib POM (no deps, just needs to exist so we can recurse).
	libPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.acme</groupId>
    <artifactId>lib</artifactId>
    <version>3.2</version>
</project>`
	if err := os.WriteFile(filepath.Join(libPomDir, "lib-3.2.pom"), []byte(libPom), 0o644); err != nil {
		t.Fatal(err)
	}

	// Child POM: references parent; declares dep on com.acme:lib with no <version>.
	childDir := filepath.Join(dir, "child")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatal(err)
	}
	childPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.acme</groupId>
        <artifactId>platform</artifactId>
        <version>1.0</version>
    </parent>
    <artifactId>child</artifactId>
    <version>2.0</version>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>lib</artifactId>
        </dependency>
    </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(childDir, "pom.xml"), []byte(childPom), 0o644); err != nil {
		t.Fatal(err)
	}

	edges, err := ParseMavenPom(filepath.Join(childDir, "pom.xml"), m2)
	if err != nil {
		t.Fatalf("ParseMavenPom failed: %v", err)
	}

	// Must find exactly one edge: child → com.acme:lib resolved to version 3.2.
	var libEdge *DepEdge
	for i := range edges {
		if edges[i].ChildName == "com.acme:lib" {
			libEdge = &edges[i]
		}
	}
	if libEdge == nil {
		t.Fatalf("expected edge to com.acme:lib; edges=%+v", edges)
	}
	if libEdge.ChildVersion != "3.2" {
		t.Errorf("com.acme:lib version=%q; want 3.2 (resolved from parent dependencyManagement via ${lib.version})", libEdge.ChildVersion)
	}
	if !libEdge.Resolved {
		t.Errorf("edge to com.acme:lib should be Resolved=true; got false")
	}
}

// TestParentChain_missingParent verifies that when the parent POM is not in
// the local cache, resolution continues best-effort: the dep is still emitted
// but stays Resolved=false because its version is genuinely unknown.
func TestParentChain_missingParent(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")
	if err := os.MkdirAll(m2, 0o755); err != nil {
		t.Fatal(err)
	}

	// Child POM references a parent not present in .m2, and relies on
	// the parent for dependency version resolution.
	childDir := filepath.Join(dir, "child")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatal(err)
	}
	childPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.missing</groupId>
        <artifactId>platform</artifactId>
        <version>9.9</version>
    </parent>
    <groupId>com.child</groupId>
    <artifactId>child</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.missing</groupId>
            <artifactId>lib</artifactId>
        </dependency>
    </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(childDir, "pom.xml"), []byte(childPom), 0o644); err != nil {
		t.Fatal(err)
	}

	// ParseMavenPom must not error — it should continue best-effort.
	edges, err := ParseMavenPom(filepath.Join(childDir, "pom.xml"), m2)
	if err != nil {
		t.Fatalf("ParseMavenPom should not error on missing parent: %v", err)
	}
	// The dep on com.missing:lib has no version locally derivable; it
	// should either be absent (dropped because version=="") or emitted
	// as Resolved=false.  Either is acceptable — the key invariant is
	// we do NOT fabricate a version.
	for _, e := range edges {
		if e.ChildName == "com.missing:lib" && e.Resolved && e.ChildVersion != "" {
			t.Errorf("dep on com.missing:lib should not have a fabricated version %q; want unresolved", e.ChildVersion)
		}
	}
}
