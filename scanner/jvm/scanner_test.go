package jvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScanner_EnvTypeIsJVM is a one-liner guard so a future refactor
// that accidentally renames EnvJVM to something else (``java``,
// ``maven``) breaks this test rather than silently re-namespacing every
// PackageRecord the plugin emits.
func TestScanner_EnvTypeIsJVM(t *testing.T) {
	var s Scanner
	if s.EnvType() != "jvm" {
		t.Fatalf("Scanner.EnvType() = %q, want %q", s.EnvType(), "jvm")
	}
}

// TestScanner_DiscoverAll_MavenAndGradle: populate HOME with both a
// Maven cache and a Gradle cache, assert DiscoverAll finds both.
// Proves the discoverer fan-out in scanner.go works; individual
// discoverers are tested in discovery_{maven,gradle}_test.go.
func TestScanner_DiscoverAll_MavenAndGradle(t *testing.T) {
	tmp := t.TempDir()
	m2 := filepath.Join(tmp, ".m2", "repository")
	gradle := filepath.Join(tmp, ".gradle", "caches", "modules-2", "files-2.1")
	if err := os.MkdirAll(m2, 0o755); err != nil {
		t.Fatalf("mkdir m2: %v", err)
	}
	if err := os.MkdirAll(gradle, 0o755); err != nil {
		t.Fatalf("mkdir gradle: %v", err)
	}
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("MAVEN_HOME", "")
	t.Setenv("GRADLE_USER_HOME", "")

	var s Scanner
	envs, errs := s.DiscoverAll(context.Background())
	if len(errs) > 0 {
		t.Fatalf("unexpected ScanErrors: %+v", errs)
	}
	if len(envs) != 2 {
		t.Fatalf("expected 2 Environments, got %d: %+v", len(envs), envs)
	}
	layouts := map[string]bool{}
	for _, e := range envs {
		layouts[e.Name] = true
	}
	if !layouts[layoutMavenCache] || !layoutsContain(envs, layoutGradleCache) {
		t.Errorf("expected both layouts, got %v", layouts)
	}
}

// TestScanner_Scan_WalksMavenCache: drop a couple of fixture JARs
// inside a synthetic Maven cache, ask Scan() to process it, and
// verify PackageRecords come out with the extractor's identities.
// This is the end-to-end sanity test for Phase B Tasks 4-5.
func TestScanner_Scan_WalksMavenCache(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, ".m2", "repository")
	if err := os.MkdirAll(filepath.Join(repo, "org", "example", "widget", "1.0"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "com", "other", "lib", "2.0"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	jarA := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/org.example/widget/pom.properties": []byte(
			"groupId=org.example\nartifactId=widget\nversion=1.0\n",
		),
	})
	jarB := buildJARBytes(t, map[string][]byte{
		"META-INF/maven/com.other/lib/pom.properties": []byte(
			"groupId=com.other\nartifactId=lib\nversion=2.0\n",
		),
	})
	if err := os.WriteFile(filepath.Join(repo, "org", "example", "widget", "1.0", "widget-1.0.jar"), jarA, 0o644); err != nil {
		t.Fatalf("write jarA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "com", "other", "lib", "2.0", "lib-2.0.jar"), jarB, 0o644); err != nil {
		t.Fatalf("write jarB: %v", err)
	}

	env := scanner.Environment{
		EnvType: EnvJVM,
		Name:    layoutMavenCache,
		Path:    repo,
	}
	var s Scanner
	records, errs := s.Scan(context.Background(), env)
	if len(errs) > 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	names := map[string]bool{}
	for _, r := range records {
		names[r.Name] = true
	}
	if !names["org.example:widget"] || !names["com.other:lib"] {
		t.Errorf("expected both records; got %+v", names)
	}
}

// TestScanner_Scan_UnknownLayoutProducesError: Scan() gets an
// Environment with a layout tag it doesn't recognise — plugin must
// emit a ScanError rather than silently producing an empty result.
// Silent empty is worse than a loud error; it hides wiring bugs.
func TestScanner_Scan_UnknownLayoutProducesError(t *testing.T) {
	var s Scanner
	env := scanner.Environment{
		EnvType: EnvJVM,
		Name:    "weblogic-farm-federation", // not a real layout
		Path:    "/nonexistent",
	}
	records, errs := s.Scan(context.Background(), env)
	if len(records) != 0 {
		t.Errorf("expected 0 records for unknown layout, got %d", len(records))
	}
	if len(errs) == 0 {
		t.Errorf("expected a ScanError for unknown layout, got none")
	}
}

// layoutsContain is a small helper to avoid writing the same range
// loop in two tests.  Declared here rather than in testutil_test.go
// to keep the helper next to its only caller.
func layoutsContain(envs []scanner.Environment, layout string) bool {
	for _, e := range envs {
		if e.Name == layout {
			return true
		}
	}
	return false
}
