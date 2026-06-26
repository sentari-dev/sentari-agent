package supplychain

import (
	"path/filepath"
	"testing"
)

const snapshotDepPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib-b</artifactId>
      <version>2.0-SNAPSHOT</version>
    </dependency>
  </dependencies>
</project>
`

const allReleasePOM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib-c</artifactId>
      <version>3.0.0</version>
    </dependency>
  </dependencies>
</project>
`

// TestSnapshotInRelease_emitsSignal verifies that a non-SNAPSHOT artifact
// whose POM declares a SNAPSHOT dependency emits one maven_snapshot_in_release
// signal with the correct coordinates of the root artifact.
func TestSnapshotInRelease_emitsSignal(t *testing.T) {
	m2 := t.TempDir()
	pomDir := filepath.Join(m2, "com", "example", "myapp", "1.0.0")
	mustMkdir(t, pomDir)
	mustWrite(t, filepath.Join(pomDir, "myapp-1.0.0.pom"), snapshotDepPOM)

	signals, err := DetectSnapshotInRelease(m2)
	if err != nil {
		t.Fatalf("DetectSnapshotInRelease failed: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(signals), signals)
	}
	s := signals[0]
	if s.SignalType != "maven_snapshot_in_release" {
		t.Errorf("wrong signal_type: %q", s.SignalType)
	}
	if s.Severity != "medium" {
		t.Errorf("wrong severity: %q", s.Severity)
	}
	if s.Source != "agent-maven-snapshot" {
		t.Errorf("wrong source: %q", s.Source)
	}
	if s.PackageName != "com.example:myapp" {
		t.Errorf("wrong package_name: %q", s.PackageName)
	}
	if s.PackageVersion != "1.0.0" {
		t.Errorf("wrong package_version: %q", s.PackageVersion)
	}
	if s.Ecosystem != "maven" {
		t.Errorf("wrong ecosystem: %q", s.Ecosystem)
	}
	// Assert Raw fields.
	if s.Raw == nil {
		t.Fatal("Raw map is nil")
	}
	if pomPath, ok := s.Raw["pom_path"].(string); !ok || pomPath == "" {
		t.Errorf("Raw[pom_path] missing or empty: %v", s.Raw["pom_path"])
	}
	snapshotDep, ok := s.Raw["snapshot_dep"].(string)
	if !ok || snapshotDep == "" {
		t.Errorf("Raw[snapshot_dep] missing or empty: %v", s.Raw["snapshot_dep"])
	}
	if snapshotDep != "2.0-SNAPSHOT" {
		t.Errorf("Raw[snapshot_dep] = %q, want 2.0-SNAPSHOT", snapshotDep)
	}
}

// TestSnapshotInRelease_allReleaseNoSignal verifies that a non-SNAPSHOT
// artifact whose POM only declares release dependencies produces no signal.
func TestSnapshotInRelease_allReleaseNoSignal(t *testing.T) {
	m2 := t.TempDir()
	pomDir := filepath.Join(m2, "com", "example", "myapp", "1.0.0")
	mustMkdir(t, pomDir)
	mustWrite(t, filepath.Join(pomDir, "myapp-1.0.0.pom"), allReleasePOM)

	signals, err := DetectSnapshotInRelease(m2)
	if err != nil {
		t.Fatalf("DetectSnapshotInRelease failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals, got %+v", signals)
	}
}

// TestSnapshotInRelease_snapshotRootSkipped verifies that SNAPSHOT artifacts
// (whose version directory contains "SNAPSHOT") are not inspected — only
// non-SNAPSHOT roots can trigger this signal.
func TestSnapshotInRelease_snapshotRootSkipped(t *testing.T) {
	m2 := t.TempDir()
	pomDir := filepath.Join(m2, "com", "example", "myapp", "1.0.0-SNAPSHOT")
	mustMkdir(t, pomDir)
	mustWrite(t, filepath.Join(pomDir, "myapp-1.0.0-SNAPSHOT.pom"), snapshotDepPOM)

	signals, err := DetectSnapshotInRelease(m2)
	if err != nil {
		t.Fatalf("DetectSnapshotInRelease failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals for SNAPSHOT root, got %+v", signals)
	}
}
