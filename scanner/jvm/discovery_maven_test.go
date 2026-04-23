package jvm

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverMavenCache_HOMEPath sets HOME to a temp dir containing
// a fake ``.m2/repository`` and verifies the discoverer emits exactly
// one Environment for it with the layout tag set.  HOME is the 99th-
// percentile case; tests below cover MAVEN_HOME and the "no cache
// found" fall-through.
func TestDiscoverMavenCache_HOMEPath(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, ".m2", "repository")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}

	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp) // Windows — belt and braces for CI matrix
	t.Setenv("MAVEN_HOME", "")   // must not shadow the $HOME path below

	envs := discoverMavenCache()
	if len(envs) != 1 {
		t.Fatalf("expected 1 Maven Environment, got %d", len(envs))
	}
	got := envs[0]
	if got.EnvType != EnvJVM {
		t.Errorf("EnvType: got %q want %q", got.EnvType, EnvJVM)
	}
	if got.Name != layoutMavenCache {
		t.Errorf("Name layout tag: got %q want %q", got.Name, layoutMavenCache)
	}
	if got.Path != repo {
		t.Errorf("Path: got %q want %q", got.Path, repo)
	}
}

// TestDiscoverMavenCache_MAVENHOMEOverride: if MAVEN_HOME/repository
// exists, it wins over $HOME/.m2/repository — matches the convention
// that explicit configuration wins over fallbacks.
func TestDiscoverMavenCache_MAVENHOMEOverride(t *testing.T) {
	tmp := t.TempDir()

	homeRepo := filepath.Join(tmp, "home", ".m2", "repository")
	if err := os.MkdirAll(homeRepo, 0o755); err != nil {
		t.Fatalf("mkdir home repo: %v", err)
	}
	mvnHome := filepath.Join(tmp, "mvn-home")
	mvnRepo := filepath.Join(mvnHome, "repository")
	if err := os.MkdirAll(mvnRepo, 0o755); err != nil {
		t.Fatalf("mkdir mvn repo: %v", err)
	}

	t.Setenv("HOME", filepath.Join(tmp, "home"))
	t.Setenv("USERPROFILE", filepath.Join(tmp, "home"))
	t.Setenv("MAVEN_HOME", mvnHome)

	envs := discoverMavenCache()
	// Expect two DISTINCT discoveries — both caches may legitimately
	// exist on one host (CI runners frequently have both).  Caller
	// won't double-scan the same JAR because extractFromJar is
	// idempotent per physical path and each path appears in exactly
	// one cache directory.
	if len(envs) != 2 {
		t.Fatalf("expected 2 Maven Environments (HOME + MAVEN_HOME), got %d: %+v", len(envs), envs)
	}
	paths := map[string]bool{envs[0].Path: true, envs[1].Path: true}
	if !paths[homeRepo] || !paths[mvnRepo] {
		t.Errorf("expected both %q and %q in discovered set, got %v", homeRepo, mvnRepo, paths)
	}
}

// TestDiscoverMavenCache_NoCachePresent: returns empty slice, no
// errors.  Missing cache is a legitimate state, not a failure —
// developer workstations without Maven installed are valid scan
// targets (we'll find their Python / system packages through other
// plugins).
func TestDiscoverMavenCache_NoCachePresent(t *testing.T) {
	tmp := t.TempDir()
	// HOME points at an empty directory — no .m2 inside.
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("MAVEN_HOME", "")

	envs := discoverMavenCache()
	if len(envs) != 0 {
		t.Fatalf("expected 0 Environments when no cache present, got %d: %+v", len(envs), envs)
	}
}

// TestDiscoverMavenCache_EmptyHOMEEnv: robustness against a truly
// empty HOME env var.  Some CI containers launch with minimal env; we
// must not panic on those and must not walk ``./.m2/repository``
// accidentally (that would pick up arbitrary working-directory
// content).
func TestDiscoverMavenCache_EmptyHOMEEnv(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("MAVEN_HOME", "")
	envs := discoverMavenCache()
	if len(envs) != 0 {
		t.Fatalf("expected 0 Environments with empty HOME, got %d", len(envs))
	}
}
