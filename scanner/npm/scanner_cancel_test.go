package npm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScan_cancelledContextStopsWalk: an npm Scan whose context is
// already cancelled must stop within one directory step — it emits a
// cancellation ScanError and never reads the package planted under
// node_modules.  Before the fix, scanNodeModules ignored ctx (`_ = ctx`)
// and would descend an entire deep node_modules tree.
func TestScan_cancelledContextStopsWalk(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "left-pad")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"left-pad","version":"1.3.0"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := scanner.Environment{EnvType: EnvNpm, Name: layoutNodeModules, Path: root}
	recs, errs := Scanner{}.Scan(ctx, env)

	if len(recs) != 0 {
		t.Errorf("expected no records after immediate cancel, got %d: %+v", len(recs), recs)
	}
	foundCancel := false
	for _, e := range errs {
		if strings.Contains(strings.ToLower(e.Error), "cancel") {
			foundCancel = true
		}
	}
	if !foundCancel {
		t.Errorf("expected a cancellation ScanError, got %+v", errs)
	}
}
