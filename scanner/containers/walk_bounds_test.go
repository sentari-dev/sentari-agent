package containers

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestWalkLayer_DepthCap — Fix #1.  walkLayer must stop descending
// past a finite depth cap so a hostile image with a pathologically
// deep directory chain can't exhaust CPU/memory.  We build a chain
// ``d0/d1/.../dN/leaf.txt`` deeper than the cap and assert that
// entries beyond the cap are NOT emitted, while shallow entries are.
func TestWalkLayer_DepthCap(t *testing.T) {
	root := t.TempDir()

	// Build a directory chain deeper than walkLayerMaxDepth, with a
	// marker file at every level so we can tell exactly how far the
	// walk descended.
	depth := walkLayerMaxDepth + 10
	cur := root
	for i := 0; i < depth; i++ {
		cur = filepath.Join(cur, "d"+strconv.Itoa(i))
		if err := os.MkdirAll(cur, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", cur, err)
		}
		// Marker file inside this directory.  Relative depth of this
		// file (separators in its rel path) is i+1 (i dirs above it
		// plus its own dir component).
		if err := os.WriteFile(filepath.Join(cur, "leaf.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write leaf: %v", err)
		}
	}

	var maxRelDepth int
	emitted := map[string]bool{}
	err := walkLayer(root, func(relPath string, d fs.DirEntry) error {
		emitted[relPath] = true
		seps := 0
		for _, c := range relPath {
			if c == '/' {
				seps++
			}
		}
		if seps > maxRelDepth {
			maxRelDepth = seps
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkLayer: %v", err)
	}

	// Shallow content must be emitted (sanity: the walk ran at all).
	if !emitted["d0"] {
		t.Fatalf("expected shallow dir d0 to be emitted; emitted=%v", len(emitted))
	}

	// A file at depth beyond the cap must NOT have been emitted.
	// Relative depth (slash count) of the deepest leaf is depth.
	if maxRelDepth > walkLayerMaxDepth {
		t.Errorf("walk descended to rel-depth %d, exceeding cap %d", maxRelDepth, walkLayerMaxDepth)
	}

	// Concretely: a leaf two levels past the cap must be absent.
	tooDeep := ""
	parts := make([]string, 0, walkLayerMaxDepth+2)
	for i := 0; i < walkLayerMaxDepth+2; i++ {
		parts = append(parts, "d"+strconv.Itoa(i))
	}
	tooDeep = filepath.ToSlash(filepath.Join(append(parts, "leaf.txt")...))
	if emitted[tooDeep] {
		t.Errorf("entry past depth cap was emitted: %q", tooDeep)
	}
}
