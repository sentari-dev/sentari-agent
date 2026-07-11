package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// buildLargeLockfileTree plants many nested directories each carrying a
// requirements.txt, giving the v3 enrichment walkers (lockfile discovery
// in particular) a non-trivial tree to traverse so a cancellation lands
// mid-walk rather than on an empty root.
func buildLargeLockfileTree(t *testing.T, dirs int) string {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < dirs; i++ {
		d := filepath.Join(root, fmt.Sprintf("proj%03d", i), "src", "pkg")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

// waitNoGoroutineLeak polls the goroutine count back down to the
// baseline (with a small tolerance for scheduler/GC noise) and fails if
// it never settles.  A surviving walker goroutine — the pre-fix
// detach-and-abandon behaviour — would keep the count elevated.
func waitNoGoroutineLeak(t *testing.T, baseline int) {
	t.Helper()
	const tolerance = 2
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		got := runtime.NumGoroutine()
		if got <= baseline+tolerance {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: baseline=%d, still %d after settle window", baseline, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestEnrichWithV3_cancelledContextStopsPromptly: a context cancelled
// before enrichment starts must make enrichWithV3 return immediately
// without walking, producing no v3 sections.
func TestEnrichWithV3_cancelledContextStopsPromptly(t *testing.T) {
	root := buildLargeLockfileTree(t, 200)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the first phase runs

	result := &ScanResult{}
	done := make(chan struct{})
	go func() {
		enrichWithV3(ctx, result, []string{root}, root)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("enrichWithV3 did not return promptly on a cancelled context")
	}

	if len(result.Lockfiles) != 0 {
		t.Errorf("expected no lockfiles from cancelled enrichment, got %d", len(result.Lockfiles))
	}
	if len(result.InstalledRuntimes) != 0 {
		t.Errorf("expected no runtimes from cancelled enrichment, got %d", len(result.InstalledRuntimes))
	}
}

// TestEnrichWithV3_cancelMidWalkNoGoroutineLeak: cancelling the context
// while enrichment is in flight must stop the walk promptly and leave no
// walker goroutine behind.
func TestEnrichWithV3_cancelMidWalkNoGoroutineLeak(t *testing.T) {
	root := buildLargeLockfileTree(t, 400)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	result := &ScanResult{}
	done := make(chan struct{})
	go func() {
		enrichWithV3(ctx, result, []string{root}, root)
		close(done)
	}()
	// Cancel right away so the phase-1 walk is interrupted in flight.
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("enrichWithV3 did not return promptly after mid-walk cancel")
	}
	waitNoGoroutineLeak(t, baseline)
}

// TestRun_cancelReturnsPromptlyAndJoinsEnrichment: Run must return
// promptly on cancellation and must not leave a detached enrichment
// walker running (the pre-fix discard-and-detach behaviour). With
// enrichment joined inline, no walker goroutine survives Run's return.
func TestRun_cancelReturnsPromptlyAndJoinsEnrichment(t *testing.T) {
	root := buildLargeLockfileTree(t, 400)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	r := NewRunner(Config{ScanRoot: root, MaxDepth: 6})

	errCh := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx)
		errCh <- err
	}()
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a cancellation error from Run, got nil")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return promptly after cancellation")
	}
	waitNoGoroutineLeak(t, baseline)
}
