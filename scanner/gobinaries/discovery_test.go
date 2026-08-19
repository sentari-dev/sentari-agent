package gobinaries

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// withRoots swaps the package-level discovery root vars for the duration of a
// test and restores them after.
func withRoots(t *testing.T, direct, optParents []string) {
	t.Helper()
	od, op := systemDirectRoots, optStyleParents
	systemDirectRoots, optStyleParents = direct, optParents
	t.Cleanup(func() { systemDirectRoots, optStyleParents = od, op })
}

func discoverPaths(t *testing.T) map[string]struct{} {
	t.Helper()
	envs, errs := Scanner{}.DiscoverAll(context.Background())
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	m := map[string]struct{}{}
	for _, e := range envs {
		if e.EnvType != EnvGoBinary {
			t.Errorf("env %q env_type = %q, want %q", e.Path, e.EnvType, EnvGoBinary)
		}
		m[e.Path] = struct{}{}
	}
	return m
}

func TestDiscoverAll_EmitsOnlyExistingRoots(t *testing.T) {
	base := t.TempDir()
	exists := filepath.Join(base, "exists")
	missing := filepath.Join(base, "missing")
	if err := os.MkdirAll(exists, 0o755); err != nil {
		t.Fatal(err)
	}
	// Neutralise env-derived roots so only our fixtures are considered.
	t.Setenv("GOPATH", filepath.Join(base, "nogopath"))
	t.Setenv("HOME", filepath.Join(base, "nohome"))
	t.Setenv("USERPROFILE", filepath.Join(base, "nohome"))
	withRoots(t, []string{exists, missing}, nil)

	paths := discoverPaths(t)
	if _, ok := paths[filepath.Clean(exists)]; !ok {
		t.Errorf("existing root should be emitted; got %v", paths)
	}
	if _, ok := paths[filepath.Clean(missing)]; ok {
		t.Errorf("missing root must not be emitted; got %v", paths)
	}
}

func TestDiscoverAll_OptStyleParentEmitsChildBinDirs(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "opt")
	if err := os.MkdirAll(filepath.Join(parent, "a", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(parent, "b", "nobin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(parent, "c", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", filepath.Join(base, "nogopath"))
	t.Setenv("HOME", filepath.Join(base, "nohome"))
	t.Setenv("USERPROFILE", filepath.Join(base, "nohome"))
	withRoots(t, nil, []string{parent})

	paths := discoverPaths(t)
	wantA := filepath.Clean(filepath.Join(parent, "a", "bin"))
	wantC := filepath.Clean(filepath.Join(parent, "c", "bin"))
	if _, ok := paths[wantA]; !ok {
		t.Errorf("a/bin should be emitted; got %v", paths)
	}
	if _, ok := paths[wantC]; !ok {
		t.Errorf("c/bin should be emitted; got %v", paths)
	}
	if len(paths) != 2 {
		t.Errorf("want exactly a/bin and c/bin, got %v", paths)
	}
}

func TestDiscoverAll_GopathBinPreferredOverHomeDefault(t *testing.T) {
	base := t.TempDir()
	gopath := filepath.Join(base, "customgopath")
	gobin := filepath.Join(gopath, "bin")
	home := filepath.Join(base, "home")
	homeGoBin := filepath.Join(home, "go", "bin")
	if err := os.MkdirAll(gobin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(homeGoBin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", gopath)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	withRoots(t, nil, nil)

	paths := discoverPaths(t)
	if _, ok := paths[filepath.Clean(gobin)]; !ok {
		t.Errorf("explicit $GOPATH/bin should be emitted; got %v", paths)
	}
	// With GOPATH set explicitly, the $HOME/go/bin default is not used.
	if _, ok := paths[filepath.Clean(homeGoBin)]; ok {
		t.Errorf("$HOME/go/bin must not be used when GOPATH is set; got %v", paths)
	}
}

func TestDiscoverAll_GopathEqualsHomeDedups(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	homeGoBin := filepath.Join(home, "go", "bin")
	if err := os.MkdirAll(homeGoBin, 0o755); err != nil {
		t.Fatal(err)
	}
	// GOPATH == $HOME/go, so $GOPATH/bin cleans to the same path as the
	// $HOME/go/bin default: exactly one Environment.
	t.Setenv("GOPATH", filepath.Join(home, "go"))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	withRoots(t, nil, nil)

	paths := discoverPaths(t)
	if _, ok := paths[filepath.Clean(homeGoBin)]; !ok {
		t.Fatalf("go bin should be emitted; got %v", paths)
	}
	if len(paths) != 1 {
		t.Errorf("overlapping GOPATH/HOME go bin should dedup to 1, got %v", paths)
	}
}

func TestDiscoverAll_NoHomeNoGopathStillEmitsSystemRoots(t *testing.T) {
	base := t.TempDir()
	sys := filepath.Join(base, "usr-local-bin")
	if err := os.MkdirAll(sys, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	withRoots(t, []string{sys}, nil)

	// Must not panic and must still emit the system root.
	paths := discoverPaths(t)
	if _, ok := paths[filepath.Clean(sys)]; !ok {
		t.Errorf("system root should be emitted even with no HOME/GOPATH; got %v", paths)
	}
}
