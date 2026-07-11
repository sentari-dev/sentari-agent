package scanner

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// captureSlog swaps the default slog logger for one writing to a buffer and
// restores the original when the test ends.  Returns the buffer so callers can
// assert on the emitted records.  safeCall routes recovered panics through
// slog.Warn, so this is how we prove the "degrade to a warning" path was taken.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestSafeCall_RecoversPanic pins the core protective guarantee: safeCall
// absorbs a panic from fn, RETURNS to its caller (no re-panic), and logs the
// panic as a warning tagged with the module label.  This is the guard that
// every v3 enrichment module in enrichWithV3 is wrapped in — a refactor that
// drops the recover() would make this test panic-crash and fail.
func TestSafeCall_RecoversPanic(t *testing.T) {
	buf := captureSlog(t)

	sideEffectRan := false
	returned := false

	safeCall("test.module", func() {
		// Work performed before the panic must persist — this models a
		// parser that appends partial results and then blows up.
		sideEffectRan = true
		panic("kaboom: hostile lockfile")
	})
	// Reaching this line at all proves safeCall did not re-panic.
	returned = true

	if !sideEffectRan {
		t.Fatal("fn body did not run before the panic")
	}
	if !returned {
		t.Fatal("safeCall re-panicked instead of returning")
	}

	out := buf.String()
	if !strings.Contains(out, "v3 enrichment panicked") {
		t.Errorf("expected a warning about the panic, got: %q", out)
	}
	if !strings.Contains(out, "test.module") {
		t.Errorf("expected the module label in the warning, got: %q", out)
	}
	if !strings.Contains(out, "kaboom") {
		t.Errorf("expected the recovered panic value in the warning, got: %q", out)
	}
}

// TestSafeCall_NoWarnOnSuccess is the negative control: a non-panicking fn
// runs to completion and emits no panic warning.
func TestSafeCall_NoWarnOnSuccess(t *testing.T) {
	buf := captureSlog(t)

	ran := false
	safeCall("test.ok", func() { ran = true })

	if !ran {
		t.Fatal("safeCall did not invoke fn")
	}
	if strings.Contains(buf.String(), "v3 enrichment panicked") {
		t.Errorf("unexpected panic warning for a clean call: %q", buf.String())
	}
}

// TestSafeCall_PanicInOneStepDoesNotStopNext models enrichWithV3's exact
// dispatch shape: a sequence of safeCall-wrapped steps, each populating a
// different result array.  A panic in the middle step must not prevent the
// later step from running, and the earlier step's already-appended results
// must survive.  This pins the "the scan degrades to 'v3 sections empty for
// that one module' rather than aborting" guarantee at the dispatch boundary.
func TestSafeCall_PanicInOneStepDoesNotStopNext(t *testing.T) {
	_ = captureSlog(t)

	result := &ScanResult{}

	// Step 1: succeeds, populates Lockfiles.
	safeCall("step.lockfiles", func() {
		result.Lockfiles = append(result.Lockfiles, deptree.LockfileMeta{Path: "/x/requirements.txt", Ecosystem: "pypi"})
	})
	// Step 2: panics mid-way after a partial append — must be contained.
	safeCall("step.depedges", func() {
		result.DepEdges = append(result.DepEdges, deptree.DepEdge{})
		panic("parser bug on hostile input")
	})
	// Step 3: must still run despite step 2's panic.
	step3Ran := false
	safeCall("step.runtimes", func() {
		step3Ran = true
	})

	if len(result.Lockfiles) != 1 {
		t.Errorf("step 1 result lost: Lockfiles len = %d, want 1", len(result.Lockfiles))
	}
	if len(result.DepEdges) != 1 {
		t.Errorf("step 2 partial result before panic lost: DepEdges len = %d, want 1", len(result.DepEdges))
	}
	if !step3Ran {
		t.Error("step 3 did not run — a panic in step 2 aborted the dispatch sequence")
	}
}

// TestEnrichWithV3_completesAndPopulatesArrays is the end-to-end companion:
// a real (valid) lockfile flows through enrichWithV3's safeCall-wrapped
// dispatch and populates the v3 arrays, confirming the guard does not
// suppress the normal success path.
func TestEnrichWithV3_completesAndPopulatesArrays(t *testing.T) {
	root := t.TempDir()
	reqs := "requests==2.31.0\nflask==3.0.0\n"
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte(reqs), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	result := &ScanResult{}
	enrichWithV3(context.Background(), result, []string{root}, root)

	if len(result.Lockfiles) == 0 {
		t.Fatalf("expected requirements.txt to be discovered as a lockfile, got none")
	}
}
