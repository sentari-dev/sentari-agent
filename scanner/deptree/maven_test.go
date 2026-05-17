package deptree

import (
	"path/filepath"
	"testing"
)

func TestParseMavenPom_directWithTransitive(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "maven", "simple")
	m2Dir := filepath.Join(fixtureDir, ".m2", "repository")
	edges, err := ParseMavenPom(filepath.Join(fixtureDir, "pom.xml"), m2Dir)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges (1 direct + 1 transitive), got %d: %+v", len(edges), edges)
	}

	var direct, transitive *DepEdge
	for i := range edges {
		if edges[i].Type == "direct" {
			direct = &edges[i]
		} else {
			transitive = &edges[i]
		}
	}
	if direct == nil || direct.ChildName != "com.example:lib-a" || direct.ChildVersion != "1.0.0" {
		t.Errorf("direct edge wrong: %+v", direct)
	}
	if direct == nil || direct.ParentName != "com.example.app:my-app" {
		t.Errorf("direct parent wrong: %+v", direct)
	}
	if transitive == nil || transitive.ChildName != "org.example:util" || transitive.ChildVersion != "2.5.0" {
		t.Errorf("transitive edge wrong: %+v", transitive)
	}
	if transitive == nil || transitive.Depth != 2 {
		t.Errorf("transitive depth wrong: %d", transitive.Depth)
	}
	if !direct.Resolved || !transitive.Resolved {
		t.Errorf("both edges should be resolved")
	}
}

func TestParseMavenPom_bomImportEmitsUnresolved(t *testing.T) {
	fixtureDir := filepath.Join("testdata", "maven", "with-bom")
	// No .m2 needed — the spring-boot-dependencies POM is intentionally
	// absent so we can verify BOM import emits Resolved=false without
	// recursing into anything.
	edges, err := ParseMavenPom(filepath.Join(fixtureDir, "pom.xml"), filepath.Join(fixtureDir, "nonexistent-m2"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	// We expect: 1 BOM (resolved=false) + 1 direct (resolved=true, but with
	// no version because we can't resolve it without the BOM).
	if len(edges) < 1 {
		t.Fatalf("expected at least the BOM-import edge, got %d", len(edges))
	}
	var bomEdge *DepEdge
	for i := range edges {
		if edges[i].ChildName == "org.springframework.boot:spring-boot-dependencies" {
			bomEdge = &edges[i]
			break
		}
	}
	if bomEdge == nil {
		t.Fatal("expected a BOM-import edge")
	}
	if bomEdge.Resolved {
		t.Error("BOM-import edge should have Resolved=false")
	}
	if bomEdge.Scope != "import" {
		t.Errorf("BOM-import edge should have scope=import, got %q", bomEdge.Scope)
	}
}

func TestMavenPomLocation(t *testing.T) {
	path := mavenPomLocation("/home/user/.m2/repository", "com.example", "lib-a", "1.0.0")
	want := filepath.Join("/home/user/.m2/repository", "com", "example", "lib-a", "1.0.0", "lib-a-1.0.0.pom")
	if path != want {
		t.Errorf("mavenPomLocation = %q, want %q", path, want)
	}
}
