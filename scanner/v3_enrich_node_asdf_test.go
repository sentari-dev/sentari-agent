package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// --- Finding 4: asdf-managed Node binaries in the candidate list -----------

// nodeCandidateBinaries must include ~/.asdf/installs/nodejs/<ver>/bin/node for
// every installed version, mirroring how the python asdf install root is
// picked up.  The ~/.asdf/shims dir holds wrapper scripts (not real binaries)
// and must NOT be probed.
func TestNodeCandidateBinariesAsdf(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Two installed node versions, each with a real bin/node file.
	versions := []string{"18.19.0", "20.11.1"}
	var wantPaths []string
	for _, v := range versions {
		binDir := filepath.Join(home, ".asdf", "installs", "nodejs", v, "bin")
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatal(err)
		}
		nodePath := filepath.Join(binDir, "node")
		if err := os.WriteFile(nodePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		wantPaths = append(wantPaths, nodePath)
	}

	// A shims wrapper that must never be treated as a real interpreter.
	shimDir := filepath.Join(home, ".asdf", "shims")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(shimDir, "node")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := nodeCandidateBinaries()
	set := make(map[string]struct{}, len(got))
	for _, p := range got {
		set[p] = struct{}{}
	}

	for _, want := range wantPaths {
		if _, ok := set[want]; !ok {
			t.Errorf("expected asdf node binary %q in candidates, got %v", want, got)
		}
	}
	if _, ok := set[shimPath]; ok {
		t.Errorf("asdf shims wrapper %q must NOT be a candidate binary", shimPath)
	}
}

// --- fnm and Volta POSIX layouts in the candidate list ---------------------

// writeNodeBin creates dir/... and a real node file, returning its path.
func writeNodeBin(t *testing.T, elems ...string) string {
	t.Helper()
	path := filepath.Join(elems...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func candidateSet(t *testing.T) map[string]struct{} {
	t.Helper()
	got := nodeCandidateBinaries()
	set := make(map[string]struct{}, len(got))
	for _, p := range got {
		set[p] = struct{}{}
	}
	return set
}

// nodeCandidateBinaries must include the fnm default layout
// (~/.local/share/fnm and ~/.fnm)/node-versions/<ver>/installation/bin/node and
// the Volta layout ~/.volta/tools/image/node/<ver>/bin/node, mirroring the
// Windows fnm glob.
func TestNodeCandidateBinariesFnmAndVolta(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Ensure no FNM_DIR override leaks in from the host environment.
	t.Setenv("FNM_DIR", "")

	fnmLocalShare := writeNodeBin(t, home, ".local", "share", "fnm", "node-versions", "v20.11.1", "installation", "bin", "node")
	fnmDotFnm := writeNodeBin(t, home, ".fnm", "node-versions", "v18.19.0", "installation", "bin", "node")
	volta := writeNodeBin(t, home, ".volta", "tools", "image", "node", "20.11.1", "bin", "node")

	set := candidateSet(t)
	for _, want := range []string{fnmLocalShare, fnmDotFnm, volta} {
		if _, ok := set[want]; !ok {
			t.Errorf("expected node binary %q in candidates, got set %v", want, set)
		}
	}
}

// When $FNM_DIR is set it is authoritative: only that root is probed, and the
// default ~/.local/share/fnm / ~/.fnm roots are ignored.
func TestNodeCandidateBinariesFnmDirOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	fnmDir := filepath.Join(home, "custom-fnm")
	t.Setenv("FNM_DIR", fnmDir)

	overridden := writeNodeBin(t, fnmDir, "node-versions", "v22.0.0", "installation", "bin", "node")
	// A node under the default root must be ignored while FNM_DIR is set.
	defaultRoot := writeNodeBin(t, home, ".local", "share", "fnm", "node-versions", "v20.11.1", "installation", "bin", "node")

	set := candidateSet(t)
	if _, ok := set[overridden]; !ok {
		t.Errorf("expected $FNM_DIR node binary %q in candidates, got set %v", overridden, set)
	}
	if _, ok := set[defaultRoot]; ok {
		t.Errorf("default fnm root %q must be ignored when $FNM_DIR is set", defaultRoot)
	}
}
