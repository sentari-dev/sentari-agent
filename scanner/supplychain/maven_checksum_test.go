package supplychain

import (
	"crypto/sha1" //nolint:gosec // SHA1 is mandated by the Maven checksum spec
	"fmt"
	"path/filepath"
	"testing"
)

// TestChecksumMismatch_mismatchEmitsSignal verifies that a jar whose .sha1
// file disagrees with the actual SHA1 of the jar bytes emits one
// maven_checksum_mismatch signal with the correct coordinates.
func TestChecksumMismatch_mismatchEmitsSignal(t *testing.T) {
	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)

	jarContent := "fake jar bytes"
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar"), jarContent)
	// Write a deliberately WRONG sha1
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar.sha1"), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	signals, err := DetectChecksumMismatches(m2)
	if err != nil {
		t.Fatalf("DetectChecksumMismatches failed: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d: %+v", len(signals), signals)
	}
	s := signals[0]
	if s.SignalType != "maven_checksum_mismatch" {
		t.Errorf("wrong signal_type: %q", s.SignalType)
	}
	if s.Severity != "high" {
		t.Errorf("wrong severity: %q", s.Severity)
	}
	if s.Source != "agent-maven-sha1" {
		t.Errorf("wrong source: %q", s.Source)
	}
	if s.PackageName != "com.example:lib-a" {
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
	if jarPath, ok := s.Raw["jar_path"].(string); !ok || jarPath == "" {
		t.Errorf("Raw[jar_path] missing or empty: %v", s.Raw["jar_path"])
	}
	expectedRaw, ok := s.Raw["expected"].(string)
	if !ok || expectedRaw == "" {
		t.Errorf("Raw[expected] missing or empty: %v", s.Raw["expected"])
	}
	if expectedRaw != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("Raw[expected] = %q, want deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", expectedRaw)
	}
	computedRaw, ok := s.Raw["computed"].(string)
	if !ok || computedRaw == "" {
		t.Errorf("Raw[computed] missing or empty: %v", s.Raw["computed"])
	}
	if computedRaw == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("Raw[computed] should differ from the wrong sha1 we wrote")
	}
}

// TestChecksumMismatch_matchingChecksumNoSignal verifies that a jar whose
// .sha1 matches the actual content produces no signal.
func TestChecksumMismatch_matchingChecksumNoSignal(t *testing.T) {
	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)

	jarContent := "fake jar bytes"
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar"), jarContent)

	// Compute the correct sha1
	h := sha1.New() //nolint:gosec // SHA1 is mandated by the Maven checksum spec
	h.Write([]byte(jarContent))
	correctSHA1 := fmt.Sprintf("%x", h.Sum(nil))
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar.sha1"), correctSHA1)

	signals, err := DetectChecksumMismatches(m2)
	if err != nil {
		t.Fatalf("DetectChecksumMismatches failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals for matching checksum, got %+v", signals)
	}
}

// TestChecksumMismatch_noSha1FileNoSignal verifies that a jar with no
// .sha1 sibling produces no signal — we cannot verify without a reference.
func TestChecksumMismatch_noSha1FileNoSignal(t *testing.T) {
	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar"), "fake jar bytes")
	// No .sha1 file

	signals, err := DetectChecksumMismatches(m2)
	if err != nil {
		t.Fatalf("DetectChecksumMismatches failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals when .sha1 is absent, got %+v", signals)
	}
}
