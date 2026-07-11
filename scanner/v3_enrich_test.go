package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestDetectWindowsStorePythons proves the Microsoft Store Python
// detector maps a `PythonSoftwareFoundation.Python.<X.Y>_<pub>` package
// dir under %LOCALAPPDATA%\Packages to a python <X.Y> runtime.  It runs
// on any OS: detectWindowsStorePythons takes the LOCALAPPDATA root as a
// parameter and reads only directory names, so a faked layout in a temp
// dir exercises the full path without needing Windows.
func TestDetectWindowsStorePythons(t *testing.T) {
	local := t.TempDir()
	pkgs := filepath.Join(local, "Packages")
	for _, name := range []string{
		// Two real Store interpreters (different series).
		"PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0",
		"PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0",
		// Non-versioned Store sibling — must be ignored (no X.Y).
		"PythonSoftwareFoundation.Python.Launcher_qbz5n2kfra8p0",
		// Unrelated UWP package — ignored.
		"Microsoft.WindowsTerminal_8wekyb3d8bbwe",
	} {
		if err := os.MkdirAll(filepath.Join(pkgs, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A stray regular file matching the prefix must not be emitted
	// (IsDir guard).
	if err := os.WriteFile(filepath.Join(pkgs, "PythonSoftwareFoundation.Python.3.9_x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	rts := detectWindowsStorePythons(local)
	got := make([]string, 0, len(rts))
	for _, r := range rts {
		if r.Name != "python" {
			t.Errorf("runtime name = %q, want python", r.Name)
		}
		got = append(got, r.Version)
	}
	sort.Strings(got)
	want := []string{"3.11", "3.12"}
	if len(got) != len(want) {
		t.Fatalf("versions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestDetectWindowsStorePythons_noPackagesDir proves a host with no
// Packages directory (Store never used) yields no runtimes and no error
// path panic.
func TestDetectWindowsStorePythons_noPackagesDir(t *testing.T) {
	if rts := detectWindowsStorePythons(t.TempDir()); len(rts) != 0 {
		t.Fatalf("expected no runtimes for a host without Packages, got %v", rts)
	}
}

func TestNodeModulesAncestor(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Flat layout: npm classic / yarn / pnpm-hoisted.
		{"/a/b/node_modules/lodash", "/a/b/node_modules"},
		// Scoped: unwinds two levels.
		{"/a/b/node_modules/@scope/pkg", "/a/b/node_modules"},
		// Nested transitive — returns the *nearest* node_modules.
		{"/a/node_modules/foo/node_modules/bar", "/a/node_modules/foo/node_modules"},
		// IDE-extension bundle (the case this fix is for).
		{"/Users/x/.cursor/extensions/ext/dist/node_modules/@aminya/node-gyp-build", "/Users/x/.cursor/extensions/ext/dist/node_modules"},
		// Trailing slash is tolerated (filepath.Clean strips it).
		{"/a/b/node_modules/lodash/", "/a/b/node_modules"},
		// No node_modules ancestor.
		{"/a/b/c", ""},
		// Edge: empty / "/" / ".".
		{"", ""},
		{"/", ""},
		{".", ""},
	}
	for _, c := range cases {
		// nodeModulesAncestor operates on OS-native paths (filepath.Dir/Base),
		// and in production it is fed real install paths from the filesystem
		// walk — '/'-separated on Unix, '\'-separated on Windows. The literals
		// above are written Unix-style for readability; translate them (and the
		// expectations) to the host separator so the test exercises the same
		// shape the product sees on each OS. filepath.FromSlash is a no-op on
		// Unix, so darwin/linux coverage is unchanged.
		in := filepath.FromSlash(c.in)
		want := filepath.FromSlash(c.want)
		if got := nodeModulesAncestor(in); got != want {
			t.Errorf("nodeModulesAncestor(%q) = %q, want %q", in, got, want)
		}
	}
}
