package containers

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

// layerFixture builds a synthetic layer directory tree for a single
// MergedTree layer.  ``entries`` maps relative path (using forward
// slashes) → file content.  An entry whose content is nil creates an
// empty directory.  Callers use this helper to express "layer 0 has
// these paths, layer 1 has those" without boilerplate.
//
// Returns the absolute path of the layer root.  All layers use
// ``t.TempDir()`` so the OS cleans up when the test exits.
func layerFixture(t *testing.T, entries map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range entries {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if content == "" && hasTrailingSep(rel) {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("mkdir %q: %v", full, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir parent %q: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %q: %v", full, err)
		}
	}
	return root
}

func hasTrailingSep(s string) bool {
	return len(s) > 0 && (s[len(s)-1] == '/' || s[len(s)-1] == os.PathSeparator)
}

// collect walks a MergedTree and returns the list of paths it
// emitted, sorted for deterministic assertion.  Keeps the test
// bodies tight.
func collect(t *testing.T, m *MergedTree) []MergedEntry {
	t.Helper()
	var got []MergedEntry
	if err := m.Walk(func(e MergedEntry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Path < got[j].Path })
	return got
}

// TestMergedTree_TwoLayersNoConflict — Task 1 Step 1.  Disjoint
// layer contents merge into the union.  This is the base case: if
// this breaks every other test is meaningless.
func TestMergedTree_TwoLayersNoConflict(t *testing.T) {
	l0 := layerFixture(t, map[string]string{"a/1.txt": "one"})
	l1 := layerFixture(t, map[string]string{"b/2.txt": "two"})

	m := &MergedTree{Layers: []string{l0, l1}}
	got := collect(t, m)

	wantPaths := []string{"a", "a/1.txt", "b", "b/2.txt"}
	if len(got) != len(wantPaths) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(wantPaths), got)
	}
	for i, p := range wantPaths {
		if got[i].Path != p {
			t.Errorf("entry %d: path %q, want %q", i, got[i].Path, p)
		}
	}
}

// TestMergedTree_TopLayerOverrides — Task 1 Step 2.  When both
// layers have the same path, the top (higher-index) layer wins.
// This is the core overlay semantic; without it we'd emit duplicate
// records with stale content.
func TestMergedTree_TopLayerOverrides(t *testing.T) {
	l0 := layerFixture(t, map[string]string{"a/1.txt": "old-content"})
	l1 := layerFixture(t, map[string]string{"a/1.txt": "new-content"})

	m := &MergedTree{Layers: []string{l0, l1}}
	got := collect(t, m)

	// Exactly one ``a/1.txt`` entry.
	count := 0
	var winner MergedEntry
	for _, e := range got {
		if e.Path == "a/1.txt" {
			count++
			winner = e
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 a/1.txt entry, got %d (full: %+v)", count, got)
	}
	// The winning entry must point at layer 1's file.
	if winner.LayerIdx != 1 {
		t.Errorf("LayerIdx: got %d, want 1", winner.LayerIdx)
	}
	body, err := os.ReadFile(winner.Abs)
	if err != nil {
		t.Fatalf("read winner: %v", err)
	}
	if string(body) != "new-content" {
		t.Errorf("winning file content: got %q, want %q", body, "new-content")
	}
}

// TestMergedTree_WhiteoutHidesFile — Task 1 Step 3.  A ``.wh.<name>``
// marker in an upper layer removes the same-named entry from every
// lower layer.  Without this, a container that explicitly deleted a
// file would still appear to contain it.
func TestMergedTree_WhiteoutHidesFile(t *testing.T) {
	l0 := layerFixture(t, map[string]string{"a/1.txt": "content"})
	l1 := layerFixture(t, map[string]string{"a/.wh.1.txt": ""})

	m := &MergedTree{Layers: []string{l0, l1}}
	got := collect(t, m)

	for _, e := range got {
		if e.Path == "a/1.txt" {
			t.Errorf("expected a/1.txt to be hidden by whiteout; got emitted: %+v", e)
		}
		if filepath.Base(e.Path) == ".wh.1.txt" {
			t.Errorf("whiteout marker should not be emitted; got %+v", e)
		}
	}
}

// TestMergedTree_OpaqueDirDropsSubtree — Task 1 Step 4.  A
// ``.wh..wh..opq`` marker inside directory ``d`` wipes ``d``'s
// lower-layer contents even though the dir itself still exists.
// Upper-layer entries under ``d`` survive.
func TestMergedTree_OpaqueDirDropsSubtree(t *testing.T) {
	l0 := layerFixture(t, map[string]string{
		"a/old-1.txt":     "gone",
		"a/old-2.txt":     "gone",
		"a/sub/deeper.txt": "gone",
	})
	l1 := layerFixture(t, map[string]string{
		"a/.wh..wh..opq": "",
		"a/new.txt":      "survives",
	})

	m := &MergedTree{Layers: []string{l0, l1}}
	got := collect(t, m)

	paths := make(map[string]bool)
	for _, e := range got {
		paths[e.Path] = true
	}

	// Every layer-0 path under ``a/`` is gone.
	forbidden := []string{"a/old-1.txt", "a/old-2.txt", "a/sub", "a/sub/deeper.txt"}
	for _, p := range forbidden {
		if paths[p] {
			t.Errorf("path %q should be dropped by opaque-dir marker; got emitted", p)
		}
	}
	// Layer-1's own additions under ``a/`` survive.
	if !paths["a/new.txt"] {
		t.Errorf("a/new.txt should survive (added by top layer); not in merged view: %+v", got)
	}
	// ``a/`` itself still exists (layer 1 contributes it).
	if !paths["a"] {
		t.Errorf("a/ dir should still be present; not in merged view: %+v", got)
	}
}

// TestMergedTree_SymlinkRefusalAcrossLayers — Task 1 Step 5.  A
// symlink planted in a layer (pointing at the host's /etc/shadow, or
// anywhere else outside the layer root) must NOT be emitted in the
// merged view.  The escape vector is: "attacker builds an image
// whose upper layer has a symlink ``/etc/passwd → /etc/passwd``;
// when the agent later reads the merged view, safeio reads from the
// host's /etc/passwd and tags it as container inventory."  We block
// this by refusing to emit symlinks at all.
//
// Windows filesystems need admin rights to create symlinks in tests,
// so the test skips there — the production safeguard is identical
// on Windows (os.Lstat reports ModeSymlink the same way) but we
// can't exercise it from a standard test runner.
func TestMergedTree_SymlinkRefusalAcrossLayers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevation on Windows test runners")
	}
	l0 := layerFixture(t, map[string]string{"safe/file.txt": "ok"})

	l1 := t.TempDir()
	// Planted: layer 1 has a symlink at ``etc/passwd`` that points
	// at the host's real /etc/passwd.  If the merged walker followed
	// it, the abs path would leak /etc/passwd into a container scan.
	if err := os.MkdirAll(filepath.Join(l1, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(l1, "etc", "passwd")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	m := &MergedTree{Layers: []string{l0, l1}}
	got := collect(t, m)

	for _, e := range got {
		if e.Path == "etc/passwd" {
			t.Errorf("symlink etc/passwd should NOT be emitted; got %+v", e)
		}
	}
	// Safe content from layer 0 still flows through.
	found := false
	for _, e := range got {
		if e.Path == "safe/file.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("layer-0 safe/file.txt lost; merged walk should include it: %+v", got)
	}
}

// TestMergedTree_NoLayers — degenerate but easy-to-hit: zero layers
// produces an empty walk (no error, no callback invocations).
// Guards the "runtime returned no images" path.
func TestMergedTree_NoLayers(t *testing.T) {
	m := &MergedTree{}
	calls := 0
	err := m.Walk(func(MergedEntry) error { calls++; return nil })
	if err != nil {
		t.Errorf("unexpected error on empty tree: %v", err)
	}
	if calls != 0 {
		t.Errorf("expected 0 callbacks on empty tree, got %d", calls)
	}
}

// TestMergedTree_LayerIdxAttribution — when emitting, the LayerIdx
// of each entry must be the highest-index layer that contributed
// it.  This is what downstream "which layer introduced this CVE-
// bearing package?" queries rely on.
func TestMergedTree_LayerIdxAttribution(t *testing.T) {
	l0 := layerFixture(t, map[string]string{"onlyL0.txt": "a", "shared.txt": "old"})
	l1 := layerFixture(t, map[string]string{"onlyL1.txt": "b", "shared.txt": "new"})

	m := &MergedTree{Layers: []string{l0, l1}}
	got := collect(t, m)

	byPath := map[string]MergedEntry{}
	for _, e := range got {
		byPath[e.Path] = e
	}
	if byPath["onlyL0.txt"].LayerIdx != 0 {
		t.Errorf("onlyL0.txt LayerIdx: got %d, want 0", byPath["onlyL0.txt"].LayerIdx)
	}
	if byPath["onlyL1.txt"].LayerIdx != 1 {
		t.Errorf("onlyL1.txt LayerIdx: got %d, want 1", byPath["onlyL1.txt"].LayerIdx)
	}
	if byPath["shared.txt"].LayerIdx != 1 {
		t.Errorf("shared.txt LayerIdx: got %d, want 1 (top wins)", byPath["shared.txt"].LayerIdx)
	}
}
