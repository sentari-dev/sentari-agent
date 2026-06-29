package jvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoverGeneric_OptAndDirect walks a fixture tree redirected at
// /opt, /usr/share/java-style layouts and verifies the discoverer
// emits an Environment for every ``lib`` / ``libs`` subdirectory it
// finds under the parents.  Overrides the package-level root slices
// via t.Cleanup-guarded test hooks so nothing on the CI host's real
// filesystem leaks into the result.
func TestDiscoverGeneric_OptAndDirect(t *testing.T) {
	tmp := t.TempDir()

	// Parent tree: tmp/opt/acme-tool/lib/*.jar  AND  tmp/opt/other/libs/*.jar
	optParent := filepath.Join(tmp, "opt")
	acmeLib := filepath.Join(optParent, "acme-tool", "lib")
	otherLibs := filepath.Join(optParent, "other", "libs")
	for _, d := range []string{acmeLib, otherLibs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", d, err)
		}
	}

	// Direct tree: tmp/share/java (the Debian-style dumping ground).
	directTree := filepath.Join(tmp, "share", "java")
	if err := os.MkdirAll(directTree, 0o755); err != nil {
		t.Fatalf("mkdir direct: %v", err)
	}

	origOpt := genericOptRoots
	origDirect := genericDirectRoots
	t.Cleanup(func() {
		genericOptRoots = origOpt
		genericDirectRoots = origDirect
	})
	genericOptRoots = []string{optParent}
	genericDirectRoots = []string{directTree}

	envs := discoverGeneric(nil)
	if len(envs) != 3 {
		t.Fatalf("expected 3 Environments (acme/lib, other/libs, share/java), got %d: %+v", len(envs), envs)
	}
	paths := map[string]bool{}
	for _, e := range envs {
		if e.Name != layoutGeneric {
			t.Errorf("layout: got %q want %q", e.Name, layoutGeneric)
		}
		paths[e.Path] = true
	}
	for _, want := range []string{acmeLib, otherLibs, directTree} {
		if !paths[want] {
			t.Errorf("missing expected path %q in %+v", want, paths)
		}
	}
}

// TestDiscoverGeneric_ExcludesPathsInsideSpecialisedRoots ensures the
// generic discoverer does NOT re-emit directories that live inside a
// path an app-server discoverer already claimed.  Without the
// exclusion check, Tomcat's /opt/tomcat/lib would be walked twice
// — once via the Tomcat Environment (rooted at /opt/tomcat) and
// once via a generic Environment rooted at /opt/tomcat/lib — and
// every JAR inside would double in the inventory.
func TestDiscoverGeneric_ExcludesPathsInsideSpecialisedRoots(t *testing.T) {
	tmp := t.TempDir()
	optParent := filepath.Join(tmp, "opt")
	// Simulate a Tomcat install that was already emitted by the
	// Tomcat discoverer.
	tomcatHome := filepath.Join(optParent, "tomcat-10")
	tomcatLib := filepath.Join(tomcatHome, "lib")
	// Also an unrelated vendor drop at /opt/acme/lib.
	acmeLib := filepath.Join(optParent, "acme", "lib")
	for _, d := range []string{tomcatLib, acmeLib} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", d, err)
		}
	}

	origOpt := genericOptRoots
	origDirect := genericDirectRoots
	t.Cleanup(func() {
		genericOptRoots = origOpt
		genericDirectRoots = origDirect
	})
	genericOptRoots = []string{optParent}
	genericDirectRoots = nil

	// Generic is called LAST with the already-emitted paths.  Tomcat
	// install root would normally be emitted by discoverTomcat(); we
	// pass it explicitly here.
	envs := discoverGeneric([]string{tomcatHome})

	if len(envs) != 1 {
		t.Fatalf("expected 1 Environment (acme/lib only — tomcat/lib excluded), got %d: %+v",
			len(envs), envs)
	}
	if envs[0].Path != acmeLib {
		t.Errorf("expected %q, got %q", acmeLib, envs[0].Path)
	}
}

// TestScanner_DiscoverAll_GenericAfterSpecialised is the end-to-end
// assertion for the dedup pathway: when both a specialised Tomcat
// install AND an unrelated generic /opt/acme/lib exist, DiscoverAll
// emits EXACTLY one Environment for each with the right layout tag
// — not a duplicate of Tomcat's tree from the generic pass.
func TestScanner_DiscoverAll_GenericAfterSpecialised(t *testing.T) {
	tmp := t.TempDir()
	// Layout the fixture.
	optParent := filepath.Join(tmp, "opt")
	tomcatHome := filepath.Join(optParent, "tomcat-10")
	// Tomcat shape marker.
	if err := os.MkdirAll(filepath.Join(tomcatHome, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir tomcat bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tomcatHome, "bin", "catalina.sh"), []byte(""), 0o755); err != nil {
		t.Fatalf("write catalina.sh: %v", err)
	}
	// Generic vendor-drop.
	acmeLib := filepath.Join(optParent, "acme", "lib")
	if err := os.MkdirAll(acmeLib, 0o755); err != nil {
		t.Fatalf("mkdir acme: %v", err)
	}

	// Wire discoverers at the fixture tree.  Tomcat uses its
	// env-var; generic uses the redirected root.
	clearAllServerEnvs(t)
	t.Setenv("CATALINA_HOME", tomcatHome)

	origOpt := genericOptRoots
	origDirect := genericDirectRoots
	origJDKRoots := jdkWellKnownRoots
	t.Cleanup(func() {
		genericOptRoots = origOpt
		genericDirectRoots = origDirect
		jdkWellKnownRoots = origJDKRoots
	})
	genericOptRoots = []string{optParent}
	genericDirectRoots = nil
	jdkWellKnownRoots = nil // prevent real host JDKs leaking into the result
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)

	var s Scanner
	envs, errs := s.DiscoverAll(context.Background())
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	layouts := map[string]int{}
	for _, e := range envs {
		layouts[e.Name]++
	}
	if layouts[layoutTomcat] != 1 {
		t.Errorf("expected exactly one Tomcat Environment, got %d (all: %v)", layouts[layoutTomcat], layouts)
	}
	if layouts[layoutGeneric] != 1 {
		t.Errorf("expected exactly one Generic Environment (acme/lib), got %d (all: %v)", layouts[layoutGeneric], layouts)
	}
}
