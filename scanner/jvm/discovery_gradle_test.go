package jvm

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverGradleCache_HOMEPath: the canonical location of the
// Gradle cache is $HOME/.gradle/caches/modules-2/files-2.1.  That
// path holds every artefact Gradle has ever resolved for this user;
// it's the equivalent of ~/.m2/repository for the Maven world.
func TestDiscoverGradleCache_HOMEPath(t *testing.T) {
	tmp := t.TempDir()
	cache := filepath.Join(tmp, ".gradle", "caches", "modules-2", "files-2.1")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}

	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("GRADLE_USER_HOME", "")

	envs := discoverGradleCache()
	if len(envs) != 1 {
		t.Fatalf("expected 1 Gradle Environment, got %d", len(envs))
	}
	got := envs[0]
	if got.EnvType != EnvJVM {
		t.Errorf("EnvType: got %q want %q", got.EnvType, EnvJVM)
	}
	if got.Name != layoutGradleCache {
		t.Errorf("Name layout tag: got %q want %q", got.Name, layoutGradleCache)
	}
	if got.Path != cache {
		t.Errorf("Path: got %q want %q", got.Path, cache)
	}
}

// TestDiscoverGradleCache_GRADLEUserHomeOverride: GRADLE_USER_HOME
// overrides the default $HOME/.gradle — standard Gradle convention
// for shared caches on build agents.
func TestDiscoverGradleCache_GRADLEUserHomeOverride(t *testing.T) {
	tmp := t.TempDir()
	gradleUser := filepath.Join(tmp, "shared-gradle")
	cache := filepath.Join(gradleUser, "caches", "modules-2", "files-2.1")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	// Also create a HOME/.gradle that MUST be ignored when the
	// explicit env var is set.  Proves the override is total.
	shouldNotBeUsed := filepath.Join(tmp, "home", ".gradle", "caches", "modules-2", "files-2.1")
	if err := os.MkdirAll(shouldNotBeUsed, 0o755); err != nil {
		t.Fatalf("mkdir home gradle: %v", err)
	}

	t.Setenv("HOME", filepath.Join(tmp, "home"))
	t.Setenv("USERPROFILE", filepath.Join(tmp, "home"))
	t.Setenv("GRADLE_USER_HOME", gradleUser)

	envs := discoverGradleCache()
	if len(envs) != 1 {
		t.Fatalf("expected 1 Gradle Environment (override wins), got %d: %+v", len(envs), envs)
	}
	if envs[0].Path != cache {
		t.Errorf("expected override cache %q, got %q", cache, envs[0].Path)
	}
}

// TestDiscoverGradleCache_NoCachePresent: no .gradle directory → no
// Environments, no errors.
func TestDiscoverGradleCache_NoCachePresent(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("GRADLE_USER_HOME", "")

	envs := discoverGradleCache()
	if len(envs) != 0 {
		t.Fatalf("expected 0 Environments, got %d: %+v", len(envs), envs)
	}
}

// TestDiscoverGradleCache_DirectoryShapeRequired: some hosts have
// ``~/.gradle`` as a config file rather than a dir (rare, but seen on
// Windows when a user has tinkered).  We must not crash on that case
// — ``Stat`` returns a non-dir; we skip.
func TestDiscoverGradleCache_DirectoryShapeRequired(t *testing.T) {
	tmp := t.TempDir()
	// Create a FILE at the path where we expect a directory.
	badPath := filepath.Join(tmp, ".gradle")
	if err := os.WriteFile(badPath, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("GRADLE_USER_HOME", "")

	envs := discoverGradleCache()
	if len(envs) != 0 {
		t.Fatalf("expected 0 Environments when .gradle is a file, got %d", len(envs))
	}
}
