package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
)

// TestDiscoverEnvironments_PathfilterSkipsSubtree proves the primary
// discovery walk consults pathfilter.ShouldSkipDir and never descends
// into a matched subtree.  We plant an identical venv marker in a
// "keep" subtree and a "skipme" subtree, install a test-only skip hook
// that matches "skipme", and assert only the keep venv is discovered.
//
// The hook is the injection seam pathfilter offers for exactly this —
// cloud prefixes are OS-specific and the network classifier needs a
// real remote mount, so neither is portable inside a unit test.
func TestDiscoverEnvironments_PathfilterSkipsSubtree(t *testing.T) {
	root := t.TempDir()

	// Two sibling venvs (each a dir containing pyvenv.cfg).
	for _, name := range []string{"keep", "skipme"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pyvenv.cfg"),
			[]byte("home = /usr/bin\nversion = 3.11.0\n"), 0o644); err != nil {
			t.Fatalf("write pyvenv.cfg in %s: %v", name, err)
		}
	}

	// Install the skip hook: prune any directory named "skipme".
	restore := pathfilter.SetSkipDirHookForTest(func(path string) bool {
		return filepath.Base(path) == "skipme"
	})
	defer restore()

	cfg := Config{ScanRoot: root, MaxDepth: 4, MaxWorkers: 2}
	s := NewRunner(cfg)
	envs, _ := s.discoverEnvironments(context.Background())

	var keepFound, skipFound bool
	for _, env := range envs {
		switch filepath.Base(env.Path) {
		case "keep":
			keepFound = true
		case "skipme":
			skipFound = true
		}
	}
	if !keepFound {
		t.Errorf("expected the 'keep' venv to be discovered; envs=%+v", envs)
	}
	if skipFound {
		t.Errorf("'skipme' venv was discovered but pathfilter should have pruned it; envs=%+v", envs)
	}
}
