package licenses

import (
	"path/filepath"
	"testing"
)

func TestExtractMaven_singleLicense(t *testing.T) {
	m2 := t.TempDir()
	dir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "lib-a-1.0.0.pom"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>lib-a</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license><name>Apache License 2.0</name><url>https://...</url></license>
  </licenses>
</project>`)
	out, err := ExtractMaven(m2)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].PackageName != "com.example:lib-a" || out[0].RawText != "Apache License 2.0" || out[0].Confidence != 0.9 {
		t.Errorf("wrong: %+v", out)
	}
}

func TestExtractMaven_dualLicensed(t *testing.T) {
	m2 := t.TempDir()
	dir := filepath.Join(m2, "org", "x", "dual", "2.0.0")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "dual-2.0.0.pom"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>org.x</groupId>
  <artifactId>dual</artifactId>
  <version>2.0.0</version>
  <licenses>
    <license><name>MIT</name></license>
    <license><name>Apache-2.0</name></license>
  </licenses>
</project>`)
	out, err := ExtractMaven(m2)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d: %+v", len(out), out)
	}
}

// TestExtractMaven_emptyGroupIdSkipped guards against emitting a
// malformed ":artifactId" coordinate when a POM inherits its groupId
// from a <parent> (so the local <groupId> element is absent).  The
// extractor must skip such a POM rather than produce a coordinate with
// an empty group segment.
func TestExtractMaven_emptyGroupIdSkipped(t *testing.T) {
	m2 := t.TempDir()
	dir := filepath.Join(m2, "com", "example", "child", "1.0.0")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "child-1.0.0.pom"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license><name>MIT</name></license>
  </licenses>
</project>`)
	out, err := ExtractMaven(m2)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 evidence (empty groupId must be skipped, no ':child' coord), got %d: %+v", len(out), out)
	}
}
