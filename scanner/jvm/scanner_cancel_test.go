package jvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScan_cancelledContextStopsWalk: a JVM Scan whose context is
// already cancelled must stop within one directory step — it emits a
// cancellation ScanError and never descends to the JAR planted deep in
// the tree.  Before the fix, scanDirTree ignored ctx (`_ = ctx`) and
// would walk a multi-GB ~/.m2 or app-server tree to completion.
func TestScan_cancelledContextStopsWalk(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A file named like a JAR; the walk must never reach it, so its
	// contents are irrelevant.
	if err := os.WriteFile(filepath.Join(deep, "deep.jar"), []byte("PK\x03\x04"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := scanner.Environment{EnvType: EnvJVM, Name: layoutGeneric, Path: root}
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
