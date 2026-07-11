package containers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScanOneTarget_timeoutNoLeakNoRace exercises the interaction the
// P0-12 fix hardened: a per-container sub-scan runs under a short
// deadline against a large materialised tree, and the deferred
// os.RemoveAll of that tree must not race a still-live enrichment
// walker.  Because Runner.Run now joins the enrichment walk inline
// (rather than detaching it), scanOneTarget only returns — and only
// then removes the tree — once every walker has stopped.
//
// Run under `-race`: a surviving walker touching the tree while
// RemoveAll deletes it would trip the race detector or leak a
// goroutine.  We also assert the goroutine count settles back to
// baseline.
func TestScanOneTarget_timeoutNoLeakNoRace(t *testing.T) {
	// A large single layer so the sub-Runner's walk + enrichment have
	// real work to do before the deadline fires.
	layer := t.TempDir()
	for i := 0; i < 400; i++ {
		d := filepath.Join(layer, "usr", "lib", fmt.Sprintf("pkg%03d", i), "sub")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(d, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	target := ContainerTarget{
		Runtime:      RuntimeDocker,
		ImageID:      "sha256:test",
		MergedRootFS: MergedTree{Layers: []string{layer}},
	}

	runtime.GC()
	baseline := runtime.NumGoroutine()

	res := &scanner.ScanResult{}
	done := make(chan struct{})
	go func() {
		// A tiny per-container timeout forces the sub-scan to be
		// cancelled mid-flight on a tree this size.
		scanOneTarget(context.Background(), target, scanner.Config{MaxDepth: 8, MaxWorkers: 2}, 1*time.Millisecond, res)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("scanOneTarget did not return promptly under a short timeout")
	}

	// No walker goroutine may survive the RemoveAll.
	const tolerance = 2
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+tolerance {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak after container sub-scan: baseline=%d, now=%d", baseline, runtime.NumGoroutine())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
