package supplychain

import (
	"context"
	"path/filepath"
	"testing"
)

// TestDetectInM2_unsignedJarSuppressedWhenNoSigningInUse covers the
// common case: a repository where no artifact is signed. A lone unsigned
// jar there is expected, not suspicious, so no signal is emitted —
// otherwise nearly every jar in a real ~/.m2 would flood the fleet.
func TestDetectInM2_unsignedJarSuppressedWhenNoSigningInUse(t *testing.T) {
	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar"), "fake jar bytes")

	signals, err := DetectInM2(context.Background(), m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected no signals when signing isn't in use, got %+v", signals)
	}
}

// TestDetectInM2_unsignedJarFlaggedWhenSigningInUse covers the
// signal-worthy case: the repository demonstrably practices PGP signing
// (one jar carries a .asc), so a *different* runtime jar that lacks one
// is a genuine anomaly worth reporting.
func TestDetectInM2_unsignedJarFlaggedWhenSigningInUse(t *testing.T) {
	m2 := t.TempDir()

	signedDir := filepath.Join(m2, "com", "example", "signed-lib", "2.0.0")
	mustMkdir(t, signedDir)
	mustWrite(t, filepath.Join(signedDir, "signed-lib-2.0.0.jar"), "fake jar")
	mustWrite(t, filepath.Join(signedDir, "signed-lib-2.0.0.jar.asc"), "fake pgp sig")

	unsignedDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, unsignedDir)
	mustWrite(t, filepath.Join(unsignedDir, "lib-a-1.0.0.jar"), "fake jar bytes")

	signals, err := DetectInM2(context.Background(), m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 1 || signals[0].SignalType != "unsigned" {
		t.Fatalf("expected 1 unsigned signal for the anomalous jar, got %+v", signals)
	}
	if signals[0].PackageName != "com.example:lib-a" || signals[0].PackageVersion != "1.0.0" {
		t.Errorf("wrong coords: %+v", signals[0])
	}
}

func TestDetectInM2_signedJarSkipped(t *testing.T) {
	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "signed-lib", "2.0.0")
	mustMkdir(t, jarDir)
	mustWrite(t, filepath.Join(jarDir, "signed-lib-2.0.0.jar"), "fake jar")
	mustWrite(t, filepath.Join(jarDir, "signed-lib-2.0.0.jar.asc"), "fake pgp sig")

	signals, err := DetectInM2(context.Background(), m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals for signed jar, got %+v", signals)
	}
}

// TestDetectInM2_nonexistentRoot proves a missing ~/.m2/repository is a clean
// no-op (no panic, no error, no signals) rather than a walk-error crash.
func TestDetectInM2_nonexistentRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does", "not", "exist")
	signals, err := DetectInM2(context.Background(), missing)
	if err != nil {
		t.Fatalf("expected no error for a missing m2 root, got %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals for a missing m2 root, got %+v", signals)
	}
}

// TestDetectInM2_malformedLayout feeds jars sitting at on-disk paths too
// shallow to carry valid group/artifact/version coordinates — even with PGP
// signing demonstrably in use elsewhere in the tree — and asserts the coord
// derivation refuses them (no coordinate-less signal) without panicking. A
// ~/.m2 tree is attacker-influenceable, so a fabricated or empty-coordinate
// signal corrupts the supply-chain report.
func TestDetectInM2_malformedLayout(t *testing.T) {
	m2 := t.TempDir()

	// Establish that signing IS in use so the suppression path doesn't mask
	// the coord-derivation behavior we want to exercise.
	signedDir := filepath.Join(m2, "com", "example", "signed-lib", "2.0.0")
	mustMkdir(t, signedDir)
	mustWrite(t, filepath.Join(signedDir, "signed-lib-2.0.0.jar"), "jar")
	mustWrite(t, filepath.Join(signedDir, "signed-lib-2.0.0.jar.asc"), "sig")

	// Jars too shallow for <group>/<artifact>/<version>/<file> (fewer than 4
	// path segments below m2) — mavenCoordsFromJarPath must return empty and
	// no signal may be emitted for them.
	mustWrite(t, filepath.Join(m2, "toplevel.jar"), "jar")                  // 1 segment
	mustWrite(t, filepath.Join(m2, "group", "shallow.jar"), "jar")          // 2 segments
	mustWrite(t, filepath.Join(m2, "group", "art", "alsoshallow.jar"), "j") // 3 segments

	signals, err := DetectInM2(context.Background(), m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	// The only well-formed jar (signed-lib) is signed, so the ONLY acceptable
	// outcome is zero signals: the shallow jars must not produce coordinate-
	// less unsigned signals.
	for _, s := range signals {
		if s.PackageName == "" || s.PackageVersion == "" {
			t.Errorf("emitted a coordinate-less signal from a malformed path: %+v", s)
		}
		if s.PackageName == "com.example:signed-lib" {
			t.Errorf("signed jar must not be flagged: %+v", s)
		}
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals from a malformed/signed-only layout, got %+v", signals)
	}
}

func TestDetectInM2_ignoresJavadocAndSourcesJars(t *testing.T) {
	m2 := t.TempDir()
	dir := filepath.Join(m2, "org", "example", "util", "1.0.0")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "util-1.0.0-javadoc.jar"), "javadoc")
	mustWrite(t, filepath.Join(dir, "util-1.0.0-sources.jar"), "sources")
	signals, err := DetectInM2(context.Background(), m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("javadoc/sources jars should be ignored, got %+v", signals)
	}
}
