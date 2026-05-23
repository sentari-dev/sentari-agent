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
