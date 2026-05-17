package supplychain

import (
	"path/filepath"
	"testing"
)

func TestDetectInM2_unsignedJar(t *testing.T) {
	m2 := t.TempDir()
	jarDir := filepath.Join(m2, "com", "example", "lib-a", "1.0.0")
	mustMkdir(t, jarDir)
	mustWrite(t, filepath.Join(jarDir, "lib-a-1.0.0.jar"), "fake jar bytes")

	signals, err := DetectInM2(m2)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 1 || signals[0].SignalType != "unsigned" {
		t.Fatalf("expected 1 unsigned, got %+v", signals)
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
