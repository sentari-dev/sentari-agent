package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAcquireApplyLock_excludesConcurrentHolder verifies the
// cross-process advisory lock: while one holder owns the lock, a second
// acquire fails rather than racing it. After release, acquire succeeds.
func TestAcquireApplyLock_excludesConcurrentHolder(t *testing.T) {
	stateDir := t.TempDir()

	release, err := acquireApplyLock(stateDir)
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	if _, err := acquireApplyLock(stateDir); err == nil {
		t.Fatal("second acquire succeeded while lock was held; expected contention error")
	}

	release()

	release2, err := acquireApplyLock(stateDir)
	if err != nil {
		t.Fatalf("acquire after release failed: %v", err)
	}
	release2()
}

// TestAcquireApplyLock_reclaimsStaleLock verifies that a lockfile left
// behind by a crashed process (older than applyLockStale) is reclaimed,
// so a crash can't deadlock all future self-updates.
func TestAcquireApplyLock_reclaimsStaleLock(t *testing.T) {
	stateDir := t.TempDir()
	lockPath := filepath.Join(stateDir, applyLockFile)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("seed lockfile: %v", err)
	}
	// Backdate well past the stale threshold.
	old := time.Now().Add(-applyLockStale - time.Hour)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatalf("backdate lockfile: %v", err)
	}

	release, err := acquireApplyLock(stateDir)
	if err != nil {
		t.Fatalf("expected stale lock to be reclaimed, got: %v", err)
	}
	release()
}

// TestApply_singleFlightPreservesRollbackBinary drives two concurrent
// Apply calls against the same install/state dirs and asserts that:
//   - the install path is never left empty, and
//   - a rollback (.prev) binary survives.
//
// Before the single-flight guard, two applies could interleave the
// dst→dst.prev moves and clobber the only rollback binary. With the
// guard the second apply is refused as a replay (it sees the first's
// advanced high-water mark) and never runs the destructive swap.
func TestApply_singleFlightPreservesRollbackBinary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("binary-0.3.0")
	srv := signedManifestServer(t, "primary", priv, "0.3.0", "0.1.0", "2026-05-22T12:00:00Z", body)
	defer srv.Close()

	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	stagedDir := filepath.Join(tmp, "staged")
	stateDir := filepath.Join(tmp, "state")

	// Seed an existing install so a .prev can be produced on swap.
	if err := os.WriteFile(installPath, []byte("old-binary-0.2.0"), 0o755); err != nil {
		t.Fatalf("seed install: %v", err)
	}

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	c.StateDir = stateDir

	mkPlan := func() *Plan {
		plan, err := c.Check()
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		plan.UpgradeAvailable = true
		plan.LatestVersion = "0.3.0"
		plan.ServedAt = "2026-05-22T12:00:00Z"
		plan.Platform.URL = "/api/v1/agent/release/binary/" + runtime.GOOS + "/" + runtime.GOARCH
		sum := sha256.Sum256(body)
		plan.Platform.SHA256 = hex.EncodeToString(sum[:])
		return plan
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = c.Apply(mkPlan(), installPath, stagedDir)
		}(i)
	}
	wg.Wait()

	// Install path must never be empty after concurrent applies.
	if _, err := os.Stat(installPath); err != nil {
		t.Fatalf("install path missing after concurrent applies: %v", err)
	}
	// The previous binary must survive for rollback.
	prev, err := os.ReadFile(installPath + ".prev")
	if err != nil {
		t.Fatalf("rollback (.prev) binary destroyed by concurrent applies: %v", err)
	}
	if string(prev) != "old-binary-0.2.0" {
		t.Errorf("rollback binary content corrupted: got %q", string(prev))
	}

	// Exactly one apply should reach the swap; the loser is rejected
	// (replay refused or restart-only warning on the winner). At least one
	// must not be a hard pre-swap failure.
	swapped := 0
	for _, e := range errs {
		if e == nil || strings.Contains(e.Error(), "service restart") {
			swapped++
		}
	}
	if swapped == 0 {
		t.Fatalf("expected at least one apply to complete the swap, got errors: %v", errs)
	}
}
