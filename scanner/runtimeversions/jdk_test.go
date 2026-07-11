package runtimeversions

import (
	"context"
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

	got := DetectAllJDKs(context.Background(), []string{root})
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

// TestDetectHomebrewJDKs_findsBrewOpenJDK covers finding scanner-2: a
// brew-installed OpenJDK buries its release file at
// <cellar>/openjdk[@NN]/<version>/libexec/openjdk.jdk/Contents/Home/release,
// far below the walk depth cap and unreachable from the /opt candidate root.
// The dedicated Cellar reader must probe the fixed keg sub-path directly.
func TestDetectHomebrewJDKs_findsBrewOpenJDK(t *testing.T) {
	cellar := t.TempDir()

	// Unversioned `openjdk` keg (Homebrew's rolling latest).
	writeBrewKeg(t, cellar, "openjdk", "21.0.1", `JAVA_VERSION="21.0.1"
IMPLEMENTOR="Homebrew"`)
	// Versioned `openjdk@17` keg.
	writeBrewKeg(t, cellar, "openjdk@17", "17.0.9", `JAVA_VERSION="17.0.9"
IMPLEMENTOR="Homebrew"`)
	// A non-JDK formula must be ignored.
	if err := os.MkdirAll(filepath.Join(cellar, "wget", "1.21.4", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := detectHomebrewJDKs([]string{cellar})
	versions := make(map[string]bool)
	for _, r := range got {
		if r.Name != "jdk" {
			t.Errorf("Name = %q, want jdk", r.Name)
		}
		versions[r.Version] = true
	}
	if !versions["21.0.1"] {
		t.Errorf("expected brew openjdk 21.0.1, got %+v", got)
	}
	if !versions["17.0.9"] {
		t.Errorf("expected brew openjdk@17 17.0.9, got %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 JDKs (wget ignored), got %d: %+v", len(got), got)
	}
}

// A missing Cellar root (the common case on Linux, or Intel paths on Apple
// Silicon) must be a silent no-op, not an error or panic.
func TestDetectHomebrewJDKs_missingRootIsNoOp(t *testing.T) {
	got := detectHomebrewJDKs([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if len(got) != 0 {
		t.Errorf("expected no JDKs from a missing root, got %+v", got)
	}
}

// writeBrewKeg materialises a Homebrew openjdk keg layout under cellar:
// <cellar>/<formula>/<version>/libexec/openjdk.jdk/Contents/Home/release.
func writeBrewKeg(t *testing.T, cellar, formula, version, release string) {
	t.Helper()
	home := filepath.Join(cellar, formula, version, "libexec", "openjdk.jdk", "Contents", "Home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "release"), []byte(release+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestParseJDKReleaseFile_graalVMImplementor guards against a sibling-key
// false-capture: a GraalVM `release` file contains both IMPLEMENTOR= and
// IMPLEMENTOR_JVMCI_VERSION=. A prefix match on "IMPLEMENTOR=" must NOT
// match "IMPLEMENTOR_JVMCI_VERSION=" — the implementor must stay the
// vendor string, so distro detection (e.g. GraalVM) is correct.
func TestParseJDKReleaseFile_graalVMImplementor(t *testing.T) {
	raw := []byte(`IMPLEMENTOR_JVMCI_VERSION="23.0-b15"
JAVA_VERSION="21.0.1"
IMPLEMENTOR="GraalVM Community"
`)
	javaVersion, implementor := parseJDKReleaseFile(raw)
	if javaVersion != "21.0.1" {
		t.Errorf("javaVersion = %q, want 21.0.1", javaVersion)
	}
	if implementor != "GraalVM Community" {
		t.Errorf("implementor = %q, want \"GraalVM Community\" (not the JVMCI sibling key)", implementor)
	}
}

func TestParseJDKDistroFromImplementor(t *testing.T) {
	cases := map[string]string{
		"Eclipse Adoptium":   "Temurin",
		"Amazon.com Inc.":    "Corretto",
		"Microsoft":          "Microsoft",
		"Azul Systems, Inc.": "Zulu",
		"AdoptOpenJDK":       "Temurin",
		"Oracle Corporation": "Oracle",
		"":                   "",
		"Unknown Vendor":     "Unknown Vendor",
	}
	for in, want := range cases {
		if got := parseJDKDistroFromImplementor(in); got != want {
			t.Errorf("parseJDKDistroFromImplementor(%q) = %q, want %q", in, got, want)
		}
	}
}
