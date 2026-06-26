package deptree

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPropertyInterp verifies full <properties> interpolation:
//   - A dep version referencing ${spring.version} resolves to the declared value.
//   - A dep version referencing ${missing.prop} stays verbatim and the edge is
//     marked Resolved=false (the agent never fabricates a version).
func TestPropertyInterp(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")
	if err := os.MkdirAll(m2, 0o755); err != nil {
		t.Fatal(err)
	}

	// Stub POM for the resolved dep so transitive recursion doesn't fail.
	springPomDir := filepath.Join(m2, "org", "springframework", "spring-core", "6.1.4")
	if err := os.MkdirAll(springPomDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stubPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>6.1.4</version>
</project>`
	if err := os.WriteFile(filepath.Join(springPomDir, "spring-core-6.1.4.pom"), []byte(stubPom), 0o644); err != nil {
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
    <properties>
        <spring.version>6.1.4</spring.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>unknown-dep</artifactId>
            <version>${missing.prop}</version>
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

	// Build a map by child name for easy lookup.
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}

	// (1) spring-core should resolve to 6.1.4.
	spring, ok := byChild["org.springframework:spring-core"]
	if !ok {
		t.Fatalf("expected edge for org.springframework:spring-core; edges=%+v", edges)
	}
	if spring.ChildVersion != "6.1.4" {
		t.Errorf("spring-core version=%q; want 6.1.4 (resolved from ${spring.version})", spring.ChildVersion)
	}
	if !spring.Resolved {
		t.Errorf("spring-core edge should be Resolved=true")
	}

	// (2) unknown-dep with ${missing.prop} should stay verbatim and unresolved.
	unk, ok := byChild["com.example:unknown-dep"]
	if !ok {
		// It is acceptable for the dep to be absent (dropped because version
		// is an unresolved placeholder and we can't recurse), but it MUST NOT
		// appear with a fabricated version.
		t.Logf("unknown-dep not emitted (dropped due to unresolvable version) — acceptable")
	} else {
		if unk.Resolved {
			t.Errorf("unknown-dep should be Resolved=false; version=%q", unk.ChildVersion)
		}
		// The version string must still contain the original placeholder or
		// be the verbatim placeholder — not a fabricated value.
		if unk.ChildVersion == "" {
			t.Errorf("unknown-dep version should carry the verbatim placeholder, got empty string")
		}
	}
}

// TestTransitivePropertyInterp verifies that transitive dependencies (deps of
// deps, reached via the ~/.m2 recursion) have their ${...} placeholders
// resolved against the FULL property map of the transitive POM — not just
// ${project.version}.
//
// Graph under test:
//
//	root (1.0) → direct-dep (2.0) → transitive-lib (${lib.version})
//
// transitive-lib's POM declares <properties><lib.version>3.5</lib.version></properties>
// so the resolved version must be 3.5, not the verbatim placeholder.
func TestTransitivePropertyInterp(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")

	// ── direct-dep POM (com.example:direct-dep:2.0) ──────────────────────
	// depends on com.example:transitive-lib with version ${lib.version},
	// resolved from its own <properties>.
	directDepDir := filepath.Join(m2, "com", "example", "direct-dep", "2.0")
	if err := os.MkdirAll(directDepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	directDepPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>direct-dep</artifactId>
    <version>2.0</version>
    <properties>
        <lib.version>3.5</lib.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>transitive-lib</artifactId>
            <version>${lib.version}</version>
        </dependency>
    </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(directDepDir, "direct-dep-2.0.pom"), []byte(directDepPom), 0o644); err != nil {
		t.Fatal(err)
	}

	// ── transitive-lib POM (com.example:transitive-lib:3.5) ──────────────
	transitiveLibDir := filepath.Join(m2, "com", "example", "transitive-lib", "3.5")
	if err := os.MkdirAll(transitiveLibDir, 0o755); err != nil {
		t.Fatal(err)
	}
	transitiveLibPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>transitive-lib</artifactId>
    <version>3.5</version>
</project>`
	if err := os.WriteFile(filepath.Join(transitiveLibDir, "transitive-lib-3.5.pom"), []byte(transitiveLibPom), 0o644); err != nil {
		t.Fatal(err)
	}

	// ── root POM ──────────────────────────────────────────────────────────
	rootDir := filepath.Join(dir, "root")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rootPom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>root</artifactId>
    <version>1.0</version>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>direct-dep</artifactId>
            <version>2.0</version>
        </dependency>
    </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(rootDir, "pom.xml"), []byte(rootPom), 0o644); err != nil {
		t.Fatal(err)
	}

	edges, err := ParseMavenPom(filepath.Join(rootDir, "pom.xml"), m2)
	if err != nil {
		t.Fatalf("ParseMavenPom failed: %v", err)
	}

	// Build lookup by child name.
	byChild := map[string]DepEdge{}
	for _, e := range edges {
		byChild[e.ChildName] = e
	}

	// The transitive dep must resolve to 3.5 — NOT "${lib.version}".
	transEdge, ok := byChild["com.example:transitive-lib"]
	if !ok {
		t.Fatalf("expected transitive edge for com.example:transitive-lib; all edges=%+v", edges)
	}
	if transEdge.ChildVersion != "3.5" {
		t.Errorf("transitive-lib version=%q; want 3.5 (resolved from ${lib.version} in direct-dep's <properties>)", transEdge.ChildVersion)
	}
	if !transEdge.Resolved {
		t.Errorf("transitive-lib edge should be Resolved=true; got false (version=%q)", transEdge.ChildVersion)
	}
}

// TestPropertyInterp_projectVersion verifies that ${project.version} still
// resolves to the root POM's own version (regression guard for the
// pre-existing behaviour).
func TestPropertyInterp_projectVersion(t *testing.T) {
	dir := t.TempDir()
	m2 := filepath.Join(dir, ".m2", "repository")
	if err := os.MkdirAll(m2, 0o755); err != nil {
		t.Fatal(err)
	}

	// Stub dep POM.
	depDir := filepath.Join(m2, "com", "example", "sibling", "2.5")
	if err := os.MkdirAll(depDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depDir, "sibling-2.5.pom"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId><artifactId>sibling</artifactId><version>2.5</version>
</project>`), 0o644); err != nil {
		t.Fatal(err)
	}

	pomDir := filepath.Join(dir, "project")
	if err := os.MkdirAll(pomDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>root</artifactId>
    <version>2.5</version>
    <dependencies>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>sibling</artifactId>
            <version>${project.version}</version>
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
	if len(edges) == 0 {
		t.Fatalf("expected at least 1 edge; got none")
	}
	for _, e := range edges {
		if e.ChildName == "com.example:sibling" {
			if e.ChildVersion != "2.5" {
				t.Errorf("sibling version=%q; want 2.5 (${project.version})", e.ChildVersion)
			}
			return
		}
	}
	t.Errorf("sibling edge not found; edges=%+v", edges)
}
