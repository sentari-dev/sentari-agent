package cache

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

func newScan(host string) *scanner.ScanResult {
	return &scanner.ScanResult{
		Hostname:  host,
		ScannedAt: time.Now().UTC(),
		Packages:  nil,
	}
}

func TestCacheDSNIncludesBusyTimeout(t *testing.T) {
	dsn := cacheDSN("/tmp/whatever.db")
	if !strings.Contains(dsn, "busy_timeout") {
		t.Fatalf("cache DSN should set busy_timeout, got %q", dsn)
	}
}

func TestEnqueueEvictsOldestPendingPastCap(t *testing.T) {
	// Shrink the cap so the test is fast and deterministic.
	orig := maxPendingScans
	maxPendingScans = 10
	defer func() { maxPendingScans = orig }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Enqueue well past the cap.  scanned_at must be monotonically
	// increasing so "oldest" is well-defined for eviction.
	base := time.Now().UTC()
	const total = 25
	for i := 0; i < total; i++ {
		r := newScan("host")
		r.ScannedAt = base.Add(time.Duration(i) * time.Second)
		if err := c.EnqueueScan(r); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}

	// Count must be clamped at the cap.
	count, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != maxPendingScans {
		t.Fatalf("pending count: want %d (cap), got %d", maxPendingScans, count)
	}

	// The retained rows must be the NEWEST ones: the oldest scanned_at
	// remaining should be from index total-cap.
	pending, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending: %v", err)
	}
	if len(pending) != maxPendingScans {
		t.Fatalf("dequeued: want %d, got %d", maxPendingScans, len(pending))
	}
	wantOldest := base.Add(time.Duration(total-maxPendingScans) * time.Second)
	gotOldest := pending[0].Result.ScannedAt.UTC()
	if !gotOldest.Equal(wantOldest) {
		t.Fatalf("oldest retained scanned_at: want %v, got %v", wantOldest, gotOldest)
	}
}

func TestConcurrentEnqueueNoBusyError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	const writers = 8
	const each = 25
	var wg sync.WaitGroup
	errCh := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := c.EnqueueScan(newScan("host")); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent EnqueueScan errored (busy?): %v", err)
	}
}

// TestWALJournalModeApplied verifies that WAL is actually in effect after
// opening the cache.  The `_journal_mode=WAL` DSN parameter is silently
// ignored by modernc.org/sqlite, so WAL must be applied via PRAGMA exec.
func TestWALJournalModeApplied(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	var mode string
	if err := c.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Fatalf("journal_mode: want %q, got %q", "wal", mode)
	}
}

// TestDequeuePendingBatchCapsAndPreservesOrder verifies that the bounded
// dequeue returns at most maxRows rows in FIFO (oldest-first) order.
func TestDequeuePendingBatchCapsAndPreservesOrder(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	base := time.Now().UTC()
	const total = 20
	for i := 0; i < total; i++ {
		r := newScan("host")
		r.ScannedAt = base.Add(time.Duration(i) * time.Second)
		if err := c.EnqueueScan(r); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}

	const batch = 5
	got, err := c.DequeuePendingBatch(batch)
	if err != nil {
		t.Fatalf("DequeuePendingBatch: %v", err)
	}
	if len(got) != batch {
		t.Fatalf("batch size: want %d, got %d", batch, len(got))
	}
	// FIFO: the batch must be the oldest `batch` rows in ascending order.
	for i := 0; i < batch; i++ {
		want := base.Add(time.Duration(i) * time.Second)
		if g := got[i].Result.ScannedAt.UTC(); !g.Equal(want) {
			t.Fatalf("row %d scanned_at: want %v, got %v", i, want, g)
		}
	}
}

// TestDequeuePendingBatchNonPositiveReturnsAll verifies that a non-positive
// cap dequeues the full pending backlog (unbounded), matching the legacy
// DequeuePending contract.
func TestDequeuePendingBatchNonPositiveReturnsAll(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	const total = 7
	for i := 0; i < total; i++ {
		if err := c.EnqueueScan(newScan("host")); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}
	got, err := c.DequeuePendingBatch(0)
	if err != nil {
		t.Fatalf("DequeuePendingBatch(0): %v", err)
	}
	if len(got) != total {
		t.Fatalf("unbounded dequeue: want %d, got %d", total, len(got))
	}
}
