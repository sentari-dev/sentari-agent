package supplychain

import (
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

	signals, err := DetectInM2(m2)
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

	signals, err := DetectInM2(m2)
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

	signals, err := DetectInM2(m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals for signed jar, got %+v", signals)
	}
}

func TestDetectInM2_ignoresJavadocAndSourcesJars(t *testing.T) {
	m2 := t.TempDir()
	dir := filepath.Join(m2, "org", "example", "util", "1.0.0")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "util-1.0.0-javadoc.jar"), "javadoc")
	mustWrite(t, filepath.Join(dir, "util-1.0.0-sources.jar"), "sources")
	signals, err := DetectInM2(m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("javadoc/sources jars should be ignored, got %+v", signals)
	}
}
