package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultProfile verifies that:
//   - Dependencies inside <profile><activation><activeByDefault>true</activeByDefault></activation>
//     are included in the resolved dep graph.
//   - Dependencies inside a profile with a different activation condition
//     (property-based, OS-based, etc.) are NOT included — only activeByDefault
//     profiles are honoured by the local-resolution pass.
func TestDefaultProfile(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")
	if err := os.MkdirAll(m2, 0o755); err != nil {
		t.Fatal(err)
	}

	// Stub POM for the expected dep from the default-active profile.
	extraDir := filepath.Join(m2, "com", "acme", "extra", "1.0")
	if err := os.MkdirAll(extraDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extraDir, "extra-1.0.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.acme</groupId><artifactId>extra</artifactId><version>1.0</version>
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
    <profiles>
        <profile>
            <id>default-extras</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <dependencies>
                <dependency>
                    <groupId>com.acme</groupId>
                    <artifactId>extra</artifactId>
                    <version>1.0</version>
                </dependency>
            </dependencies>
        </profile>
        <profile>
            <id>property-activated</id>
            <activation>
                <property>
                    <name>skipThisProfile</name>
                </property>
            </activation>
            <dependencies>
                <dependency>
                    <groupId>com.acme</groupId>
                    <artifactId>skip</artifactId>
                    <version>1.0</version>
                </dependency>
            </dependencies>
        </profile>
    </profiles>
</project>`
	if err := os.WriteFile(filepath.Join(pomDir, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}

	edges, err := ParseMavenPom(filepath.Join(pomDir, "pom.xml"), m2)
	if err != nil {
		t.Fatalf("ParseMavenPom failed: %v", err)
	}

	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}

	// com.acme:extra must be present — from the default-active profile.
	extra, ok := byChild["com.acme:extra"]
	if !ok {
		t.Fatalf("expected edge for com.acme:extra (from activeByDefault profile); edges=%+v", edges)
	}
	if extra.ChildVersion != "1.0" {
		t.Errorf("com.acme:extra version=%q; want 1.0", extra.ChildVersion)
	}
	if !extra.Resolved {
		t.Errorf("com.acme:extra should be Resolved=true")
	}

	// com.acme:skip must be absent — from a property-activated profile only.
	if _, present := byChild["com.acme:skip"]; present {
		t.Errorf("com.acme:skip should NOT be present (property-activated profile should be ignored); edges=%+v", edges)
	}
}

// TestDefaultProfile_managedVersionsInheritedFromProfile verifies that
// <dependencyManagement> declared inside a default-active profile also
// merges into the managedVersions map, so a versionless dep in the
// main <dependencies> block can be resolved from the profile's management.
func TestDefaultProfile_managedVersionsInheritedFromProfile(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")
	if err := os.MkdirAll(m2, 0o755); err != nil {
		t.Fatal(err)
	}

	// Stub lib POM.
	libDir := filepath.Join(m2, "com", "acme", "lib", "7.0")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "lib-7.0.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.acme</groupId><artifactId>lib</artifactId><version>7.0</version>
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
    <profiles>
        <profile>
            <id>mgmt-profile</id>
            <activation>
                <activeByDefault>true</activeByDefault>
            </activation>
            <dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>com.acme</groupId>
                        <artifactId>lib</artifactId>
                        <version>7.0</version>
                    </dependency>
                </dependencies>
            </dependencyManagement>
        </profile>
    </profiles>
    <dependencies>
        <dependency>
            <groupId>com.acme</groupId>
            <artifactId>lib</artifactId>
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

	var libEdge *DepEdge
	for i := range edges {
		if edges[i].ChildName == "com.acme:lib" {
			libEdge = &edges[i]
		}
	}
	if libEdge == nil {
		t.Fatalf("expected edge for com.acme:lib (version from profile dependencyManagement); edges=%+v", edges)
	}
	if libEdge.ChildVersion != "7.0" {
		t.Errorf("com.acme:lib version=%q; want 7.0 (from profile dependencyManagement)", libEdge.ChildVersion)
	}
	if !libEdge.Resolved {
		t.Errorf("com.acme:lib should be Resolved=true")
	}
}
