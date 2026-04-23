package jvm

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// seedJDKFixture creates a minimal on-disk tree that looks like a
// JDK install: a ``release`` file with the standard Oracle / OpenJDK
// key=value shape, a couple of classic ``.jar`` files under ``lib/``,
// and one ``.jmod`` file under ``jmods/``.  The JARs carry real
// Maven coordinates via pom.properties so the assertion side can
// recognise them; the JMOD is plain (no metadata) so the version-
// stamping path is exercised.
func seedJDKFixture(t *testing.T, root string, jdkVersion string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "lib"), 0o755); err != nil {
		t.Fatalf("mkdir lib: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "jmods"), 0o755); err != nil {
		t.Fatalf("mkdir jmods: %v", err)
	}

	// release file — Oracle/OpenJDK convention.  Quoted values.
	release := []byte(`JAVA_VERSION="` + jdkVersion + `"` + "\n" +
		`IMPLEMENTOR="Eclipse Adoptium"` + "\n" +
		`OS_NAME="Linux"` + "\n")
	if err := os.WriteFile(filepath.Join(root, "release"), release, 0o644); err != nil {
		t.Fatalf("write release: %v", err)
	}

	// One JAR with real metadata.
	jar := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/org.openjdk/some-jdk-lib/pom.properties": []byte(
			"groupId=org.openjdk\nartifactId=some-jdk-lib\nversion=1.0\n",
		),
	})
	if err := os.WriteFile(filepath.Join(root, "lib", "some-jdk-lib.jar"), jar, 0o644); err != nil {
		t.Fatalf("write lib jar: %v", err)
	}

	// One JMOD with NO identity metadata inside — forces the filename
	// fallback + JDK-version stamping path.
	jmod := buildJARBytes(t, map[string][]byte{
		"classes/module-info.class": []byte{0xCA, 0xFE, 0xBA, 0xBE}, // placeholder bytes
	})
	if err := os.WriteFile(filepath.Join(root, "jmods", "java.base.jmod"), jmod, 0o644); err != nil {
		t.Fatalf("write jmod: %v", err)
	}
}

// TestDiscoverJDK_JavaHomeWins: when JAVA_HOME is set and points at a
// directory that looks like a JDK, discovery emits a single
// Environment for it.  The ``looks like a JDK'' test is a heuristic —
// we check for the presence of a ``release`` file or a
// ``lib/modules`` image, either of which uniquely identifies an
// installed JDK vs, say, a random directory a user set JAVA_HOME to
// by mistake.
func TestDiscoverJDK_JavaHomeWins(t *testing.T) {
	tmp := t.TempDir()
	jdk := filepath.Join(tmp, "jdk-21")
	seedJDKFixture(t, jdk, "21.0.3")

	t.Setenv("JAVA_HOME", jdk)
	// Clear USERPROFILE/HOME so the well-known install walk can't
	// accidentally add extras.
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	envs := discoverJDK()
	if len(envs) != 1 {
		t.Fatalf("expected 1 JDK Environment from JAVA_HOME, got %d: %+v", len(envs), envs)
	}
	got := envs[0]
	if got.EnvType != EnvJVM {
		t.Errorf("EnvType: got %q want %q", got.EnvType, EnvJVM)
	}
	if got.Name != layoutJDKRuntime {
		t.Errorf("Name: got %q want %q", got.Name, layoutJDKRuntime)
	}
	if got.Path != jdk {
		t.Errorf("Path: got %q want %q", got.Path, jdk)
	}
}

// TestDiscoverJDK_JavaHomeButNotAJDK: if JAVA_HOME points at a path
// that is NOT a JDK (no release file, no lib/modules), we refuse to
// scan it.  Protects against stray env vars that would cause us to
// walk arbitrary directories.
func TestDiscoverJDK_JavaHomeButNotAJDK(t *testing.T) {
	tmp := t.TempDir()
	bogus := filepath.Join(tmp, "not-a-jdk")
	if err := os.MkdirAll(bogus, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("JAVA_HOME", bogus)
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	envs := discoverJDK()
	if len(envs) != 0 {
		t.Fatalf("expected 0 Environments when JAVA_HOME is not a JDK, got %d: %+v", len(envs), envs)
	}
}

// TestDiscoverJDK_WellKnownPaths_Linux: on Linux, /usr/lib/jvm/* is
// where Debian / RHEL / Alpine-via-community-JDK packages land.  We
// walk one level deep looking for subdirectories that themselves
// pass the JDK-shape check.  Skipped on non-Linux so the test suite
// stays hermetic.
func TestDiscoverJDK_WellKnownPaths_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("well-known-path discovery is Linux-specific here")
	}
	// Redirect the well-known-roots slice at a controlled fixture tree;
	// done via a package-local test hook rather than patching /usr/lib
	// (which we can't on CI without root).
	tmp := t.TempDir()
	jvmRoot := filepath.Join(tmp, "usr", "lib", "jvm")
	jdk := filepath.Join(jvmRoot, "temurin-21")
	seedJDKFixture(t, jdk, "21.0.3")
	// A second directory that is NOT a JDK — must be skipped.
	if err := os.MkdirAll(filepath.Join(jvmRoot, "not-a-jdk"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	originalRoots := jdkWellKnownRoots
	t.Cleanup(func() { jdkWellKnownRoots = originalRoots })
	jdkWellKnownRoots = []string{jvmRoot}

	t.Setenv("JAVA_HOME", "") // don't let JAVA_HOME also emit an Env
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	envs := discoverJDK()
	if len(envs) != 1 {
		t.Fatalf("expected 1 JDK from well-known roots, got %d: %+v", len(envs), envs)
	}
	if envs[0].Path != jdk {
		t.Errorf("Path: got %q want %q", envs[0].Path, jdk)
	}
}

// TestDiscoverJDK_NoDuplicates: JAVA_HOME and a well-known-roots hit
// may point at the same physical JDK; we must emit exactly one
// Environment for it.  Duplicate discovery would cause the same
// tree to be scanned twice and all package records to double.
func TestDiscoverJDK_NoDuplicates(t *testing.T) {
	tmp := t.TempDir()
	jvmRoot := filepath.Join(tmp, "usr", "lib", "jvm")
	jdk := filepath.Join(jvmRoot, "adoptium-21")
	seedJDKFixture(t, jdk, "21.0.3")

	originalRoots := jdkWellKnownRoots
	t.Cleanup(func() { jdkWellKnownRoots = originalRoots })
	jdkWellKnownRoots = []string{jvmRoot}

	t.Setenv("JAVA_HOME", jdk)
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	envs := discoverJDK()
	if len(envs) != 1 {
		t.Fatalf("duplicate JDK Environment emitted: got %d, want 1: %+v", len(envs), envs)
	}
}

// TestScanner_Scan_JDKLayoutUsesReleaseFileVersion: end-to-end test
// that runs the JDK layout through Scanner.Scan() and verifies
// .jmod records are stamped with the version read from the release
// file.  Without this stamping the filename fallback produces
// records like (java.base, "") which are useless to CVE correlation.
func TestScanner_Scan_JDKLayoutUsesReleaseFileVersion(t *testing.T) {
	tmp := t.TempDir()
	jdk := filepath.Join(tmp, "jdk-21")
	seedJDKFixture(t, jdk, "21.0.3")

	env := scanner.Environment{
		EnvType: EnvJVM,
		Name:    layoutJDKRuntime,
		Path:    jdk,
	}
	var s Scanner
	records, errs := s.Scan(context.Background(), env)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}

	var sawJmod bool
	for _, r := range records {
		if strings.HasSuffix(strings.ToLower(r.InstallPath), ".jmod") {
			sawJmod = true
			if r.Name != "java.base" {
				t.Errorf("jmod Name: got %q want java.base", r.Name)
			}
			if r.Version != "21.0.3" {
				t.Errorf("jmod Version: got %q want 21.0.3 (from release file)", r.Version)
			}
		}
	}
	if !sawJmod {
		t.Fatalf("expected a .jmod record among %+v", records)
	}
}

// TestReadJDKVersion covers the release-file parsing directly.
// ``release`` files use a key="value" syntax with optional quotes;
// some non-OpenJDK builds (GraalVM, Azul Zulu) omit the quotes.
// Parser must tolerate both.
func TestReadJDKVersion(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"quoted", `JAVA_VERSION="17.0.9"` + "\n" + `OS_NAME="Linux"` + "\n", "17.0.9"},
		{"unquoted", "JAVA_VERSION=21.0.3\nOS_NAME=Linux\n", "21.0.3"},
		{"with-whitespace", "  JAVA_VERSION =  \"11.0.21\"  \n", "11.0.21"},
		{"missing-key", "OS_NAME=\"Linux\"\n", ""},
		{"empty-file", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			if err := os.WriteFile(filepath.Join(tmp, "release"), []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write release: %v", err)
			}
			got := readJDKVersion(tmp)
			if got != tc.want {
				t.Errorf("readJDKVersion: got %q want %q", got, tc.want)
			}
		})
	}
}
