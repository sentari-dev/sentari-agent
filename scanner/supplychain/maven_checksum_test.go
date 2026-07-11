package supplychain

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA1 is mandated by the Maven checksum spec
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// resetChecksumMemo clears the process-lifetime memo so a test starts from a
// cold cache regardless of what earlier tests hashed.
func resetChecksumMemo() {
	checksumMemoMu.Lock()
	checksumMemo = make(map[checksumMemoKey]string)
	checksumMemoMu.Unlock()
}

// spyHashJar swaps hashJar for a counting wrapper around the real
// implementation and returns the counter plus a restore func.
func spyHashJar(t *testing.T) (*int64, func()) {
	t.Helper()
	var count int64
	orig := hashJar
	hashJar = func(path string) (string, error) {
		atomic.AddInt64(&count, 1)
		return orig(path)
	}
	return &count, func() { hashJar = orig }
}

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

	signals, err := DetectChecksumMismatches(context.Background(), m2)
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

	signals, err := DetectChecksumMismatches(context.Background(), m2)
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

	signals, err := DetectChecksumMismatches(context.Background(), m2)
	if err != nil {
		t.Fatalf("DetectChecksumMismatches failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals when .sha1 is absent, got %+v", signals)
	}
}

// TestChecksumMismatch_memoSkipsReHash verifies that a second scan of the same
// unchanged jar (same path, mtime, size) is served from the memo and does not
// re-invoke the streaming hash.
func TestChecksumMismatch_memoSkipsReHash(t *testing.T) {
	resetChecksumMemo()
	count, restore := spyHashJar(t)
	defer restore()

	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)
	jarPath := filepath.Join(jarDir, "lib-a-1.0.0.jar")
	mustWrite(t, jarPath, "fake jar bytes")
	mustWrite(t, jarPath+".sha1", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	if _, err := DetectChecksumMismatches(context.Background(), m2); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
	if got := atomic.LoadInt64(count); got != 1 {
		t.Fatalf("first scan: expected 1 hash call, got %d", got)
	}

	// Second scan of the identical (path, mtime, size) — must hit the memo.
	if _, err := DetectChecksumMismatches(context.Background(), m2); err != nil {
		t.Fatalf("second scan failed: %v", err)
	}
	if got := atomic.LoadInt64(count); got != 1 {
		t.Fatalf("second scan: expected memo hit (still 1 hash call), got %d", got)
	}
}

// TestChecksumMismatch_memoInvalidatesOnMTimeChange verifies that touching the
// jar (changing its mtime) invalidates the memo and forces a re-hash.
func TestChecksumMismatch_memoInvalidatesOnMTimeChange(t *testing.T) {
	resetChecksumMemo()
	count, restore := spyHashJar(t)
	defer restore()

	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)
	jarPath := filepath.Join(jarDir, "lib-a-1.0.0.jar")
	mustWrite(t, jarPath, "fake jar bytes")
	mustWrite(t, jarPath+".sha1", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	if _, err := DetectChecksumMismatches(context.Background(), m2); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
	if got := atomic.LoadInt64(count); got != 1 {
		t.Fatalf("first scan: expected 1 hash call, got %d", got)
	}

	// Bump the jar's mtime a second into the past to change the memo key
	// deterministically (a fresh mtime differs from the recorded one).
	newTime := time.Now().Add(-2 * time.Second)
	if err := os.Chtimes(jarPath, newTime, newTime); err != nil {
		t.Fatalf("chtimes failed: %v", err)
	}

	if _, err := DetectChecksumMismatches(context.Background(), m2); err != nil {
		t.Fatalf("second scan failed: %v", err)
	}
	if got := atomic.LoadInt64(count); got != 2 {
		t.Fatalf("second scan: expected re-hash after mtime change (2 calls), got %d", got)
	}
}
