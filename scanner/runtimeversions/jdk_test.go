package runtimeversions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectJDKInDir_temurin17(t *testing.T) {
	dir := filepath.Join("testdata", "jdk", "temurin-17")
	got, err := DetectJDKInDir(dir)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected an InstalledRuntime, got nil")
	}
	if got.Name != "jdk" {
		t.Errorf("Name = %q, want jdk", got.Name)
	}
	if got.Version != "17.0.5" {
		t.Errorf("Version = %q, want 17.0.5", got.Version)
	}
	if got.Cycle != "17" {
		t.Errorf("Cycle = %q, want 17", got.Cycle)
	}
	if got.Distro != "Temurin" {
		t.Errorf("Distro = %q, want Temurin", got.Distro)
	}
	if got.InstallPath != dir {
		t.Errorf("InstallPath = %q, want %q", got.InstallPath, dir)
	}
}

func TestDetectJDKInDir_corretto8_legacyVersion(t *testing.T) {
	dir := filepath.Join("testdata", "jdk", "corretto-8")
	got, err := DetectJDKInDir(dir)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got.Version != "1.8.0_392" || got.Cycle != "8" {
		t.Errorf("wrong version/cycle: %s / %s", got.Version, got.Cycle)
	}
	if got.Distro != "Corretto" {
		t.Errorf("Distro = %q, want Corretto", got.Distro)
	}
}

func TestDetectJDKInDir_missingReleaseFile(t *testing.T) {
	dir := t.TempDir() // empty dir
	got, err := DetectJDKInDir(dir)
	if err != nil {
		t.Fatalf("expected no error on missing release file, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// TestDetectAllJDKs_respectsDepthCap covers the perf fix: an unbounded
// WalkDir under /opt or /srv on hosts with deep nested container
// volumes used to dominate scan latency. The depth cap (4) skips any
// JDK that lives more than 4 levels below a candidate root.
func TestDetectAllJDKs_respectsDepthCap(t *testing.T) {
	root := t.TempDir()
	// Deep JDK at depth 6 — beyond the default cap of 4.
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "release"), []byte(`JAVA_VERSION="11.0.20"`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Shallow JDK at depth 1 — within the cap.
	shallow := filepath.Join(root, "shallow-jdk")
	if err := os.MkdirAll(shallow, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shallow, "release"), []byte(`JAVA_VERSION="17.0.5"`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := DetectAllJDKs([]string{root})
	versions := make(map[string]bool)
	for _, r := range got {
		versions[r.Version] = true
	}
	if !versions["17.0.5"] {
		t.Errorf("expected to find shallow 17.0.5 JDK, got %+v", got)
	}
	if versions["11.0.20"] {
		t.Errorf("should NOT have found deep 11.0.20 JDK (beyond depth cap), got %+v", got)
	}
}

func TestParseJDKDistroFromImplementor(t *testing.T) {
	cases := map[string]string{
		"Eclipse Adoptium":           "Temurin",
		"Amazon.com Inc.":            "Corretto",
		"Microsoft":                  "Microsoft",
		"Azul Systems, Inc.":         "Zulu",
		"AdoptOpenJDK":               "Temurin",
		"Oracle Corporation":         "Oracle",
		"":                           "",
		"Unknown Vendor":             "Unknown Vendor",
	}
	for in, want := range cases {
		if got := parseJDKDistroFromImplementor(in); got != want {
			t.Errorf("parseJDKDistroFromImplementor(%q) = %q, want %q", in, got, want)
		}
	}
}
