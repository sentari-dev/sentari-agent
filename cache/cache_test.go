package cache

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// base3339 formats a time as RFC3339, matching the scanned_at column format.
func base3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// writeFile is a thin os.WriteFile wrapper for test setup.
func writeFile(path string, data []byte) error { return os.WriteFile(path, data, 0600) }

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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

// TestCacheDSNIncludesTxLockImmediate verifies the cache DSN carries
// _txlock=immediate so BeginTx starts every transaction with BEGIN IMMEDIATE,
// taking the write lock up front.  This is what serialises the eviction
// read-modify-write across PROCESSES (SetMaxOpenConns(1) only covers one
// process).  Mirrors the audit package's DSN threat model.
func TestCacheDSNIncludesTxLockImmediate(t *testing.T) {
	dsn := cacheDSN("/tmp/whatever.db")
	if !strings.Contains(dsn, "_txlock=immediate") {
		t.Fatalf("cache DSN should set _txlock=immediate, got %q", dsn)
	}
	// _txlock=immediate must not have regressed the WAL/busy_timeout settings:
	// the busy_timeout pragma must still be present alongside it.
	if !strings.Contains(dsn, "busy_timeout") {
		t.Fatalf("cache DSN must keep busy_timeout alongside _txlock, got %q", dsn)
	}
}

// TestCacheTxLockImmediateHonoredByDriver proves the modernc.org/sqlite driver
// actually honours _txlock=immediate: a BEGIN IMMEDIATE takes the reserved
// write lock, so a concurrent write from a SECOND connection to the same file
// blocks and (with busy_timeout exhausted) surfaces SQLITE_BUSY rather than
// silently interleaving.  A second cache handle mimics a second agent process.
func TestCacheTxLockImmediateHonoredByDriver(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()
	if _, err := c.EnqueueScan(newScan("seed")); err != nil {
		t.Fatalf("seed EnqueueScan: %v", err)
	}

	// A second connection to the same file with a SHORT busy_timeout so the
	// test does not wait the full 5s.  This stands in for a second process.
	other, err := sql.Open("sqlite", dbPath+"?_txlock=immediate&_pragma=busy_timeout(50)")
	if err != nil {
		t.Fatalf("open second handle: %v", err)
	}
	other.SetMaxOpenConns(1)
	defer other.Close()

	// Hold an IMMEDIATE transaction open on the first connection: it owns the
	// write lock until Commit/Rollback.
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin holding tx: %v", err)
	}
	if _, err := tx.Exec("INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
		"{}", base3339(time.Now())); err != nil {
		_ = tx.Rollback()
		t.Fatalf("write inside holding tx: %v", err)
	}

	// The second connection's IMMEDIATE begin must fail to acquire the write
	// lock (busy_timeout(50) exhausted) while the first holds it — proof the
	// lock is real and _txlock=immediate is honoured.
	otherTx, err := other.Begin()
	if err == nil {
		_ = otherTx.Rollback()
		_ = tx.Rollback()
		t.Fatal("second BEGIN IMMEDIATE should have blocked on the held write lock, but it succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "busy") &&
		!strings.Contains(strings.ToLower(err.Error()), "locked") {
		_ = tx.Rollback()
		t.Fatalf("second BEGIN IMMEDIATE should fail with SQLITE_BUSY/locked, got %v", err)
	}

	// Release the lock; the second connection can now take it.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback holding tx: %v", err)
	}
	otherTx, err = other.Begin()
	if err != nil {
		t.Fatalf("second BEGIN IMMEDIATE after release should succeed, got %v", err)
	}
	_ = otherTx.Rollback()
}

// TestSetMaxPendingScans verifies the operator-config setter overrides the cap
// for non-negative values and ignores negatives (the config layer rejects them,
// but the setter is defensive).
func TestSetMaxPendingScans(t *testing.T) {
	orig := maxPendingScans
	defer func() { maxPendingScans = orig }()

	SetMaxPendingScans(1234)
	if maxPendingScans != 1234 {
		t.Fatalf("after SetMaxPendingScans(1234): got %d, want 1234", maxPendingScans)
	}
	SetMaxPendingScans(0)
	if maxPendingScans != 0 {
		t.Fatalf("after SetMaxPendingScans(0): got %d, want 0", maxPendingScans)
	}
	SetMaxPendingScans(-1)
	if maxPendingScans != 0 {
		t.Fatalf("SetMaxPendingScans(-1) must be ignored: got %d, want 0", maxPendingScans)
	}
	if DefaultMaxPendingScans != 500 {
		t.Fatalf("DefaultMaxPendingScans = %d, want 500", DefaultMaxPendingScans)
	}
}

// TestSetMaxPendingBytes verifies the byte-cap setter mirrors the scans setter:
// non-negative values apply, negatives are ignored, 0 is honoured.
func TestSetMaxPendingBytes(t *testing.T) {
	orig := maxPendingBytes
	defer func() { maxPendingBytes = orig }()

	SetMaxPendingBytes(4096)
	if maxPendingBytes != 4096 {
		t.Fatalf("after SetMaxPendingBytes(4096): got %d, want 4096", maxPendingBytes)
	}
	SetMaxPendingBytes(0)
	if maxPendingBytes != 0 {
		t.Fatalf("after SetMaxPendingBytes(0): got %d, want 0", maxPendingBytes)
	}
	SetMaxPendingBytes(-1)
	if maxPendingBytes != 0 {
		t.Fatalf("SetMaxPendingBytes(-1) must be ignored: got %d, want 0", maxPendingBytes)
	}
	if DefaultMaxPendingBytes != 512<<20 {
		t.Fatalf("DefaultMaxPendingBytes = %d, want %d", DefaultMaxPendingBytes, 512<<20)
	}
}

// TestEvictExcessPendingByByteCap drives eviction on the BYTE cap while the ROW
// cap is deliberately left slack: 10 rows (far under a 1000-row cap) whose
// cumulative scan_json blows past a 1000-byte cap.  The oldest rows must be
// evicted until the remaining pending bytes fall under the byte cap, the newest
// rows are retained, and the EvictionResult reports reason "bytes" (the row cap
// never fired).
func TestEvictExcessPendingByByteCap(t *testing.T) {
	origScans, origBytes := maxPendingScans, maxPendingBytes
	maxPendingScans = 1000 // slack: must NOT be the trigger
	maxPendingBytes = 1000 // the binding cap
	defer func() { maxPendingScans, maxPendingBytes = origScans, origBytes }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Each blob is a fixed 298 ASCII bytes; 10 rows = 2980 bytes total, ~3x the
	// 1000-byte cap.  Insert directly so a single evictExcessPending call must
	// prune on bytes alone.
	blob := `{"h":"` + strings.Repeat("x", 290) + `"}`
	if len(blob) != 298 {
		t.Fatalf("blob length = %d, want 298", len(blob))
	}
	base := time.Now().UTC()
	const total = 10
	for i := 0; i < total; i++ {
		if _, err := c.db.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
			blob, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339),
		); err != nil {
			t.Fatalf("direct insert %d: %v", i, err)
		}
	}

	ev, err := c.evictExcessPending()
	if err != nil {
		t.Fatalf("evictExcessPending: %v", err)
	}
	if ev.Count == 0 {
		t.Fatal("expected a byte-cap eviction, got Count 0")
	}
	if ev.Reason != "bytes" {
		t.Fatalf("eviction reason = %q, want %q (row cap was slack)", ev.Reason, "bytes")
	}

	// Remaining pending bytes must now be under the cap; keep-newest means the
	// retained blobs are 298 bytes each, so at most floor(1000/298) = 3 survive.
	var remRows int
	var remBytes int64
	if err := c.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(length(CAST(scan_json AS BLOB))), 0)
		 FROM scan_queue WHERE uploaded = 0`,
	).Scan(&remRows, &remBytes); err != nil {
		t.Fatalf("post-evict aggregate: %v", err)
	}
	if remBytes > int64(maxPendingBytes) {
		t.Fatalf("remaining bytes %d exceed cap %d", remBytes, maxPendingBytes)
	}
	if remRows != 3 {
		t.Fatalf("retained rows = %d, want 3 (3*298=894 <= 1000 < 4*298)", remRows)
	}
	if ev.Count != total-remRows {
		t.Fatalf("evicted Count = %d, want %d", ev.Count, total-remRows)
	}

	// The retained rows must be the NEWEST: the oldest remaining scanned_at
	// column value is the row at index total-remRows.  (Assert against the
	// scanned_at COLUMN rather than the parsed scan_json, since these synthetic
	// blobs carry no scanned_at field.)
	var gotOldest string
	if err := c.db.QueryRow(
		"SELECT MIN(scanned_at) FROM scan_queue WHERE uploaded = 0",
	).Scan(&gotOldest); err != nil {
		t.Fatalf("min scanned_at: %v", err)
	}
	wantOldest := base.Add(time.Duration(total-remRows) * time.Second).Format(time.RFC3339)
	if gotOldest != wantOldest {
		t.Fatalf("oldest retained scanned_at: want %s, got %s", wantOldest, gotOldest)
	}
}

// TestByteCapAlwaysRetainsFreshestRow proves the keep-at-least-one invariant:
// when a single pending scan alone exceeds the byte cap, eviction retains it
// (so it can still drain over later cycles) rather than discarding the freshest
// inventory the instant it is written.
func TestByteCapAlwaysRetainsFreshestRow(t *testing.T) {
	origScans, origBytes := maxPendingScans, maxPendingBytes
	maxPendingScans = 1000
	maxPendingBytes = 100 // smaller than one blob
	defer func() { maxPendingScans, maxPendingBytes = origScans, origBytes }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Two 298-byte blobs; each alone exceeds the 100-byte cap.
	blob := `{"h":"` + strings.Repeat("x", 290) + `"}`
	base := time.Now().UTC()
	for i := 0; i < 2; i++ {
		if _, err := c.db.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
			blob, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339),
		); err != nil {
			t.Fatalf("direct insert %d: %v", i, err)
		}
	}
	if _, err := c.evictExcessPending(); err != nil {
		t.Fatalf("evictExcessPending: %v", err)
	}
	count, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("keep-one invariant: want 1 retained, got %d", count)
	}
}

// TestEvictionReasonRows confirms an eviction driven purely by the ROW cap
// (byte cap slack) reports reason "rows".
func TestEvictionReasonRows(t *testing.T) {
	origScans, origBytes := maxPendingScans, maxPendingBytes
	maxPendingScans = 5
	maxPendingBytes = DefaultMaxPendingBytes // slack
	defer func() { maxPendingScans, maxPendingBytes = origScans, origBytes }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	base := time.Now().UTC()
	for i := 0; i < 8; i++ {
		if _, err := c.db.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
			"{}", base.Add(time.Duration(i)*time.Second).Format(time.RFC3339),
		); err != nil {
			t.Fatalf("direct insert %d: %v", i, err)
		}
	}
	ev, err := c.evictExcessPending()
	if err != nil {
		t.Fatalf("evictExcessPending: %v", err)
	}
	if ev.Count != 3 || ev.Reason != "rows" {
		t.Fatalf("row-cap evict: got Count=%d Reason=%q, want Count=3 Reason=rows", ev.Count, ev.Reason)
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
		if _, err := c.EnqueueScan(r); err != nil {
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
	pending, _, err := c.DequeuePending()
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

// TestEvictionResultCountAndRangeWhenEvictionFires drives the transactional
// eviction path and asserts the returned EvictionResult reports the exact count
// AND scanned_at range of the rows that were dropped — the forensic data the
// caller writes into the `cache.evicted` audit entry.  With cap=10 and 13 rows,
// the first two enqueues past the cap each drop exactly one oldest row; the
// enqueue that first crosses the cap reports the single oldest snapshot.
func TestEvictionResultCountAndRangeWhenEvictionFires(t *testing.T) {
	orig := maxPendingScans
	maxPendingScans = 10
	defer func() { maxPendingScans = orig }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	base := time.Now().UTC()
	// Fill exactly to the cap: no eviction yet.
	for i := 0; i < maxPendingScans; i++ {
		r := newScan("host")
		r.ScannedAt = base.Add(time.Duration(i) * time.Second)
		ev, err := c.EnqueueScan(r)
		if err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
		if ev.Count != 0 {
			t.Fatalf("enqueue %d (still under cap): want Count 0, got %+v", i, ev)
		}
	}

	// The next enqueue crosses the cap and must evict exactly the single
	// oldest row (index 0, scanned_at == base).
	r := newScan("host")
	r.ScannedAt = base.Add(time.Duration(maxPendingScans) * time.Second)
	ev, err := c.EnqueueScan(r)
	if err != nil {
		t.Fatalf("EnqueueScan crossing cap: %v", err)
	}
	if ev.Count != 1 {
		t.Fatalf("crossing cap: want Count 1, got %d", ev.Count)
	}
	wantOldest := base.UTC().Format(time.RFC3339)
	if ev.OldestScannedAt != wantOldest || ev.NewestScannedAt != wantOldest {
		t.Fatalf("single-row eviction range: want [%s, %s], got [%s, %s]",
			wantOldest, wantOldest, ev.OldestScannedAt, ev.NewestScannedAt)
	}

	// Pending count stays clamped at the cap after the transactional evict.
	count, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if count != maxPendingScans {
		t.Fatalf("pending after evict: want %d, got %d", maxPendingScans, count)
	}
}

// TestEvictionResultRangeSpansMultipleRows verifies the range spans the full
// set of evicted rows when more than one is dropped at once.  Enqueuing 3 rows
// past a cap of 10 in a single burst (by pre-seeding above the cap) forces a
// multi-row evict whose range must run from the oldest to the newest dropped
// snapshot.
func TestEvictionResultRangeSpansMultipleRows(t *testing.T) {
	orig := maxPendingScans
	maxPendingScans = 10
	defer func() { maxPendingScans = orig }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	base := time.Now().UTC()
	// Insert 13 pending rows directly (bypassing per-insert eviction) so a
	// single evictExcessPending call must drop the 3 oldest at once.
	const total = 13
	for i := 0; i < total; i++ {
		if _, err := c.db.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
			"{}", base.Add(time.Duration(i)*time.Second).Format(time.RFC3339),
		); err != nil {
			t.Fatalf("direct insert %d: %v", i, err)
		}
	}

	ev, err := c.evictExcessPending()
	if err != nil {
		t.Fatalf("evictExcessPending: %v", err)
	}
	if ev.Count != total-maxPendingScans {
		t.Fatalf("multi-row evict: want Count %d, got %d", total-maxPendingScans, ev.Count)
	}
	// The 3 oldest rows are indices 0,1,2 -> scanned_at base .. base+2s.
	wantOldest := base.Format(time.RFC3339)
	wantNewest := base.Add(2 * time.Second).Format(time.RFC3339)
	if ev.OldestScannedAt != wantOldest || ev.NewestScannedAt != wantNewest {
		t.Fatalf("multi-row range: want [%s, %s], got [%s, %s]",
			wantOldest, wantNewest, ev.OldestScannedAt, ev.NewestScannedAt)
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
				if _, err := c.EnqueueScan(newScan("host")); err != nil {
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
		if _, err := c.EnqueueScan(r); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}

	const batch = 5
	got, _, err := c.DequeuePendingBatch(batch)
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
		if _, err := c.EnqueueScan(newScan("host")); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}
	got, _, err := c.DequeuePendingBatch(0)
	if err != nil {
		t.Fatalf("DequeuePendingBatch(0): %v", err)
	}
	if len(got) != total {
		t.Fatalf("unbounded dequeue: want %d, got %d", total, len(got))
	}
}

// uploadedState returns the tri-state uploaded value for a row.
func uploadedState(t *testing.T, c *Cache, id int64) int {
	t.Helper()
	var state int
	if err := c.db.QueryRow("SELECT uploaded FROM scan_queue WHERE id = ?", id).Scan(&state); err != nil {
		t.Fatalf("read uploaded state for id=%d: %v", id, err)
	}
	return state
}

// TestMarkFailedPermanentSkipsRowAndNextDrains proves the head-of-line-block
// fix: a permanently-rejected row (marked dead) is skipped by the pending
// dequeue while the rows behind it still drain.  This is the cache-level
// analogue of "a 413 row is marked dead and the NEXT row drains in the same
// cycle".
func TestMarkFailedPermanentSkipsRowAndNextDrains(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	base := time.Now().UTC()
	for i := 0; i < 3; i++ {
		r := newScan("host")
		r.ScannedAt = base.Add(time.Duration(i) * time.Second)
		if _, err := c.EnqueueScan(r); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}

	pending, _, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("want 3 pending, got %d", len(pending))
	}

	// The head row is permanently rejected by the server.
	head := pending[0].QueueID
	if err := c.MarkFailedPermanent(head); err != nil {
		t.Fatalf("MarkFailedPermanent: %v", err)
	}
	if got := uploadedState(t, c, head); got != 2 {
		t.Fatalf("dead row uploaded state: want 2, got %d", got)
	}

	// Next dequeue must skip the dead head and return the two rows behind it.
	next, _, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending after mark dead: %v", err)
	}
	if len(next) != 2 {
		t.Fatalf("after marking head dead: want 2 pending, got %d", len(next))
	}
	if next[0].QueueID == head {
		t.Fatalf("dead head must not reappear in pending dequeue")
	}
}

// TestDequeueQuarantinesCorruptRowOnce inserts an undecodable blob directly,
// then verifies DequeuePending skips it AND flips it to dead (uploaded = 2) so
// it never re-consumes a LIMIT slot on the next cycle.
func TestDequeueQuarantinesCorruptRowOnce(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// A valid row, then a corrupt row (non-JSON), then another valid row.
	if _, err := c.EnqueueScan(newScan("good-1")); err != nil {
		t.Fatalf("EnqueueScan good-1: %v", err)
	}
	res, err := c.db.Exec(
		"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
		"{ this is not valid json", base3339(time.Now()),
	)
	if err != nil {
		t.Fatalf("insert corrupt row: %v", err)
	}
	corruptID, _ := res.LastInsertId()
	if _, err := c.EnqueueScan(newScan("good-2")); err != nil {
		t.Fatalf("EnqueueScan good-2: %v", err)
	}

	got, quarantined, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 decodable rows, got %d", len(got))
	}
	// The dequeue must report the one corrupt row it flipped to dead — this is
	// the signal the drain loop uses to keep going past an all-corrupt batch.
	if quarantined != 1 {
		t.Fatalf("quarantined count: want 1, got %d", quarantined)
	}
	// The corrupt row must have been quarantined (uploaded = 2), not left pending.
	if state := uploadedState(t, c, corruptID); state != 2 {
		t.Fatalf("corrupt row uploaded state: want 2 (dead), got %d", state)
	}

	// Second dequeue must not surface the corrupt row again and it stays dead.
	again, _, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending (2nd): %v", err)
	}
	if len(again) != 2 {
		t.Fatalf("2nd dequeue: want 2 decodable rows, got %d", len(again))
	}
	if state := uploadedState(t, c, corruptID); state != 2 {
		t.Fatalf("corrupt row must stay dead, got state %d", state)
	}
}

// TestDequeueAllCorruptBatchReportsQuarantinedAndNextAdvances proves the
// finding offline-1 building block at the cache layer: when a bounded batch
// window is ENTIRELY corrupt, DequeuePendingBatch returns zero usable rows but a
// non-zero quarantined count, and the NEXT batch skips the now-dead rows and
// returns the good rows behind them.  The drain loop relies on exactly this
// (quarantined > 0 ⇒ keep draining; the next batch advances past the dead rows).
func TestDequeueAllCorruptBatchReportsQuarantinedAndNextAdvances(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Two corrupt (non-JSON) rows first, then two good rows.  A bounded batch of
	// 2 therefore reads a window that is entirely corrupt.
	for i := 0; i < 2; i++ {
		if _, err := c.db.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
			"{ not valid json", base3339(time.Now()),
		); err != nil {
			t.Fatalf("insert corrupt row %d: %v", i, err)
		}
	}
	if _, err := c.EnqueueScan(newScan("good-1")); err != nil {
		t.Fatalf("EnqueueScan good-1: %v", err)
	}
	if _, err := c.EnqueueScan(newScan("good-2")); err != nil {
		t.Fatalf("EnqueueScan good-2: %v", err)
	}

	// First batch: the 2-row window is all corrupt → no usable rows, but both
	// were quarantined.
	first, quarantined, err := c.DequeuePendingBatch(2)
	if err != nil {
		t.Fatalf("DequeuePendingBatch(2) first: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("all-corrupt batch: want 0 usable rows, got %d", len(first))
	}
	if quarantined != 2 {
		t.Fatalf("all-corrupt batch: want quarantined=2, got %d", quarantined)
	}

	// Next batch advances past the now-dead rows and drains the good ones.
	second, quarantined2, err := c.DequeuePendingBatch(2)
	if err != nil {
		t.Fatalf("DequeuePendingBatch(2) second: %v", err)
	}
	if quarantined2 != 0 {
		t.Fatalf("second batch should quarantine nothing, got %d", quarantined2)
	}
	if len(second) != 2 || second[0].Result.Hostname != "good-1" || second[1].Result.Hostname != "good-2" {
		t.Fatalf("second batch must return the good rows in order, got %+v", second)
	}
}

// TestPurgeUploadedReapsUploadedAndDeadNotPending verifies PurgeUploaded
// deletes both uploaded (1) and dead (2) terminal rows but never pending (0).
func TestPurgeUploadedReapsUploadedAndDeadNotPending(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Three rows: one pending, one uploaded, one dead.  Terminal rows carry an
	// old uploaded_at (delivery time) so they fall past the purge window; the
	// pending row has a NULL uploaded_at (it never left the pending set) and an
	// old created_at, proving the purge keys on uploaded_at, not created_at.
	old := "2000-01-01 00:00:00"
	var ids [3]int64
	for i := 0; i < 3; i++ {
		var uploadedAt any // NULL for the pending row, old delivery time otherwise
		if i > 0 {
			uploadedAt = old
		}
		res, err := c.db.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at, uploaded, created_at, uploaded_at) VALUES (?, ?, ?, ?, ?)",
			"{}", base3339(time.Now()), i, old, uploadedAt, // uploaded = 0, 1, 2 respectively
		)
		if err != nil {
			t.Fatalf("insert row %d: %v", i, err)
		}
		ids[i], _ = res.LastInsertId()
	}

	purged, err := c.PurgeUploaded(24 * time.Hour)
	if err != nil {
		t.Fatalf("PurgeUploaded: %v", err)
	}
	if purged != 2 {
		t.Fatalf("purged: want 2 (uploaded + dead), got %d", purged)
	}
	// Pending row must survive.
	var remaining int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE id = ?", ids[0]).Scan(&remaining); err != nil {
		t.Fatalf("count pending survivor: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("pending row must survive purge; found %d", remaining)
	}
}

// TestDequeuePendingBatchRespectsByteBudget verifies the byte budget bounds a
// batch of oversized rows to a single row (always at least one) rather than
// pulling the whole backlog into memory.
func TestDequeuePendingBatchRespectsByteBudget(t *testing.T) {
	orig := maxDequeueBytes
	maxDequeueBytes = 1 // any non-empty row already exceeds this
	defer func() { maxDequeueBytes = orig }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		r := newScan("host")
		r.ScannedAt = base.Add(time.Duration(i) * time.Second)
		if _, err := c.EnqueueScan(r); err != nil {
			t.Fatalf("EnqueueScan %d: %v", i, err)
		}
	}

	got, _, err := c.DequeuePendingBatch(100)
	if err != nil {
		t.Fatalf("DequeuePendingBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("byte budget: want exactly 1 row (always at least one), got %d", len(got))
	}

	// With a generous budget the same backlog dequeues fully.
	maxDequeueBytes = 64 << 20
	all, _, err := c.DequeuePendingBatch(100)
	if err != nil {
		t.Fatalf("DequeuePendingBatch (generous): %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("generous budget: want 5 rows, got %d", len(all))
	}
}

// TestOpenResilientRecoversFromGarbageFile verifies a corrupt cache DB file is
// quarantined aside and an empty cache recreated in its place, rather than
// bricking the daemon.
func TestOpenResilientRecoversFromGarbageFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")

	// Write non-SQLite garbage where the cache DB is expected.
	if err := writeFile(dbPath, []byte("this is definitely not a sqlite database")); err != nil {
		t.Fatalf("seed garbage db: %v", err)
	}

	c, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer c.Close()
	if !recovered {
		t.Fatal("expected recovered=true for a garbage db file")
	}
	if quarantinedPath == "" {
		t.Fatal("expected a non-empty quarantinedPath")
	}
	if !fileExists(quarantinedPath) {
		t.Fatalf("corrupt file should be preserved at %s", quarantinedPath)
	}
	// The fresh cache must be usable and empty.
	count, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount on recovered cache: %v", err)
	}
	if count != 0 {
		t.Fatalf("recovered cache should be empty, got %d pending", count)
	}
	if _, err := c.EnqueueScan(newScan("post-recovery")); err != nil {
		t.Fatalf("EnqueueScan on recovered cache: %v", err)
	}
}

// TestEvictionAndDrainUseIDOrderNotWallClock proves both the backlog-cap
// eviction and the FIFO drain order by the AUTOINCREMENT id (true enqueue
// order), NOT by the wall-clock scanned_at — so a backward clock correction
// (NTP resync after a long air-gap outage, or a VM snapshot restore) cannot make
// eviction drop the freshest inventory or the drain reorder catch-up
// (finding offline-3).
func TestEvictionAndDrainUseIDOrderNotWallClock(t *testing.T) {
	orig := maxPendingScans
	maxPendingScans = 3
	defer func() { maxPendingScans = orig }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Enqueue 5 rows whose scanned_at goes BACKWARD as id increases: the lowest
	// id has the NEWEST wall-clock time, the highest id the OLDEST.  Inserted
	// directly so scanned_at is decoupled from insert order and a single
	// evictExcessPending call drops multiple rows at once.
	base := time.Now().UTC()
	var ids []int64
	for i := 0; i < 5; i++ {
		scannedAt := base.Add(time.Duration(-i) * time.Minute).Format(time.RFC3339)
		res, err := c.db.Exec("INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)", "{}", scannedAt)
		if err != nil {
			t.Fatalf("direct insert %d: %v", i, err)
		}
		id, _ := res.LastInsertId()
		ids = append(ids, id)
	}

	// cap=3, 5 rows → evict the 2 lowest-id (oldest-ENQUEUED) rows.
	ev, err := c.evictExcessPending()
	if err != nil {
		t.Fatalf("evictExcessPending: %v", err)
	}
	if ev.Count != 2 {
		t.Fatalf("evicted count = %d, want 2", ev.Count)
	}

	// The evicted rows must be the two LOWEST ids (ids[0], ids[1]) — NOT the two
	// earliest wall-clock rows (ids[4], ids[3]) that scanned_at ordering would drop.
	var lowestSurvivors int
	if err := c.db.QueryRow(
		"SELECT COUNT(*) FROM scan_queue WHERE id IN (?, ?)", ids[0], ids[1],
	).Scan(&lowestSurvivors); err != nil {
		t.Fatalf("count lowest-id survivors: %v", err)
	}
	if lowestSurvivors != 0 {
		t.Fatalf("lowest-id (oldest-enqueued) rows must be evicted, %d survived", lowestSurvivors)
	}

	// The scanned_at range report still describes the evicted rows: ids[0]
	// (base) and ids[1] (base-1m), so MIN=base-1m, MAX=base.
	wantOldest := base.Add(-time.Minute).Format(time.RFC3339)
	wantNewest := base.Format(time.RFC3339)
	if ev.OldestScannedAt != wantOldest || ev.NewestScannedAt != wantNewest {
		t.Fatalf("eviction range = [%s, %s], want [%s, %s]",
			ev.OldestScannedAt, ev.NewestScannedAt, wantOldest, wantNewest)
	}

	// The drain returns the survivors in id-ASC (enqueue) order: ids[2..4].
	pending, _, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("pending = %d, want 3", len(pending))
	}
	for i, want := range []int64{ids[2], ids[3], ids[4]} {
		if pending[i].QueueID != want {
			t.Fatalf("drain[%d] QueueID = %d, want %d (id order, not wall-clock)", i, pending[i].QueueID, want)
		}
	}
}

// TestReopenQuarantinesAndRecreatesCorruptCache exercises Cache.Reopen — the hook
// upload_drain uses when SQLite surfaces on-disk corruption LAZILY at read time.
// A clobbered cache file is quarantined aside and a fresh empty queue takes its
// place, and the same *Cache handle keeps working afterwards (finding offline-1).
func TestReopenQuarantinesAndRecreatesCorruptCache(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, err := c.EnqueueScan(newScan("before-corruption")); err != nil {
		t.Fatalf("EnqueueScan: %v", err)
	}
	// Close cleanly (checkpoints and drops the WAL/SHM sidecars) so the on-disk
	// bytes are self-contained, then clobber the main file to mimic a torn page
	// surfacing on a later read.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := writeFile(dbPath, []byte("this is definitely not a sqlite database")); err != nil {
		t.Fatalf("clobber db: %v", err)
	}

	recovered, quarantinedPath, err := c.Reopen()
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	defer c.Close()
	if !recovered {
		t.Fatal("expected recovered=true after clobbering the cache file")
	}
	if quarantinedPath == "" || !fileExists(quarantinedPath) {
		t.Fatalf("corrupt file must be quarantined and preserved, got %q", quarantinedPath)
	}
	// The fresh queue is empty and immediately usable.
	count, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount after Reopen: %v", err)
	}
	if count != 0 {
		t.Fatalf("recovered cache should be empty, got %d pending", count)
	}
	if _, err := c.EnqueueScan(newScan("after-recovery")); err != nil {
		t.Fatalf("EnqueueScan after Reopen: %v", err)
	}
}

// TestOpenResilientHappyPathNoRecovery verifies a healthy db opens without
// quarantine.
func TestOpenResilientHappyPathNoRecovery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer c.Close()
	if recovered {
		t.Fatal("healthy db must not trigger recovery")
	}
	if quarantinedPath != "" {
		t.Fatalf("healthy db must not report a quarantine path, got %q", quarantinedPath)
	}
}

// TestOpenResilientDoesNotQuarantineOnTransientError verifies that a NON-
// corruption open failure (a permission-denied parent directory, which surfaces
// as SQLITE_CANTOPEN — NOT SQLITE_CORRUPT/SQLITE_NOTADB) is returned as an error
// WITHOUT quarantining anything.  Quarantining a healthy queue on a transient
// error would orphan weeks of pending offline scans the first time the disk
// fills or a permission bit is wrong (finding offline-1).
func TestOpenResilientDoesNotQuarantineOnTransientError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}
	dir := t.TempDir()
	// A directory the process cannot open files under — SQLite fails to create
	// the db with a CANTOPEN result code, which is transient, not corruption.
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	dbPath := filepath.Join(locked, "cache.db")

	c, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err == nil {
		if c != nil {
			c.Close()
		}
		t.Fatal("expected a transient open error, got nil")
	}
	if recovered {
		t.Fatal("a transient (permission-denied) failure must NOT trigger recovery")
	}
	if quarantinedPath != "" {
		t.Fatalf("a transient failure must not quarantine, got path %q", quarantinedPath)
	}
	// No .corrupt-* file may have been created under the parent dir.
	corrupt, _ := filepath.Glob(filepath.Join(dir, "*.corrupt-*"))
	if len(corrupt) != 0 {
		t.Fatalf("no quarantine file should exist for a transient error, found %v", corrupt)
	}
}

// TestOpenResilientPrunesOldCorruptQuarantines verifies that when more than
// keepCorruptQuarantines ".corrupt-*" sets already exist, a fresh corruption
// recovery prunes them down to the newest few (including the just-created one)
// and removes their -wal/-shm sidecars — so a device that repeatedly corrupts
// its cache (failing disk) cannot accumulate quarantine copies without bound
// (finding offline-1).
func TestOpenResilientPrunesOldCorruptQuarantines(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")

	// Seed 4 pre-existing quarantine sets with distinct, clearly-old unix-second
	// timestamps, each with its -wal/-shm sidecars.  keepCorruptQuarantines is 3,
	// so after recovery only the newest 3 sets (the 2 newest of these + the new
	// one) may survive; the 2 oldest must be pruned.
	old := []int64{1000, 1001, 1002, 1003}
	for _, ts := range old {
		base := fmt.Sprintf("%s.corrupt-%d", dbPath, ts)
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if err := writeFile(p, []byte("old quarantine")); err != nil {
				t.Fatalf("seed quarantine %s: %v", p, err)
			}
		}
	}

	// Trigger a fresh corruption recovery: garbage where the live cache is.
	if err := writeFile(dbPath, []byte("this is definitely not a sqlite database")); err != nil {
		t.Fatalf("seed garbage db: %v", err)
	}
	c, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer c.Close()
	if !recovered {
		t.Fatal("expected recovered=true for a garbage db file")
	}

	// Exactly keepCorruptQuarantines base sets must remain (glob excludes the
	// live cache.db, whose name has no .corrupt- infix).
	bases, _ := filepath.Glob(dbPath + ".corrupt-*")
	var remaining []string
	for _, m := range bases {
		if strings.HasSuffix(m, "-wal") || strings.HasSuffix(m, "-shm") {
			continue
		}
		remaining = append(remaining, m)
	}
	if len(remaining) != keepCorruptQuarantines {
		t.Fatalf("want %d quarantine sets after prune, got %d: %v",
			keepCorruptQuarantines, len(remaining), remaining)
	}

	// The just-created quarantine must survive, and its sidecars too.
	if !fileExists(quarantinedPath) {
		t.Fatalf("just-created quarantine must not be pruned: %s", quarantinedPath)
	}

	// The two OLDEST seeded sets (1000, 1001) and their sidecars must be gone.
	for _, ts := range []int64{1000, 1001} {
		base := fmt.Sprintf("%s.corrupt-%d", dbPath, ts)
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if fileExists(p) {
				t.Fatalf("stale quarantine file must be pruned, still present: %s", p)
			}
		}
	}
	// The two NEWEST seeded sets (1002, 1003) must survive with their sidecars.
	for _, ts := range []int64{1002, 1003} {
		base := fmt.Sprintf("%s.corrupt-%d", dbPath, ts)
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if !fileExists(p) {
				t.Fatalf("recent quarantine file must survive prune, missing: %s", p)
			}
		}
	}
}

// TestMarkUploadedRemovesFromPendingThenPurges exercises Cache.MarkUploaded —
// the terminal-state write the drain loop issues after a successful upload —
// end to end: an uploaded row leaves the pending set, then PurgeUploaded reaps
// the uploaded row while a still-pending row survives (finding tests-1).
func TestMarkUploadedRemovesFromPendingThenPurges(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Two pending rows.
	if _, err := c.EnqueueScan(newScan("to-upload")); err != nil {
		t.Fatalf("EnqueueScan (to-upload): %v", err)
	}
	if _, err := c.EnqueueScan(newScan("stays-pending")); err != nil {
		t.Fatalf("EnqueueScan (stays-pending): %v", err)
	}

	batch, _, err := c.DequeuePending()
	if err != nil {
		t.Fatalf("DequeuePending: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("want 2 pending rows, got %d", len(batch))
	}
	uploadID := batch[0].QueueID  // oldest-enqueued, drained first
	pendingID := batch[1].QueueID // left untouched

	// Mark the first row uploaded.  It must leave the pending set and land in
	// the uploaded (1) terminal state.
	if err := c.MarkUploaded(uploadID); err != nil {
		t.Fatalf("MarkUploaded: %v", err)
	}
	if state := uploadedState(t, c, uploadID); state != 1 {
		t.Fatalf("uploaded row state: want 1 (uploaded), got %d", state)
	}
	pending, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 1 {
		t.Fatalf("after MarkUploaded want 1 pending, got %d", pending)
	}

	// Age the uploaded row's DELIVERY time past the purge window so
	// PurgeUploaded reaps it, and prove the still-pending row is never touched
	// regardless of age.  The window keys on uploaded_at, not created_at.
	if _, err := c.db.Exec(
		"UPDATE scan_queue SET uploaded_at = ? WHERE id = ?", "2000-01-01 00:00:00", uploadID,
	); err != nil {
		t.Fatalf("age uploaded row: %v", err)
	}
	purged, err := c.PurgeUploaded(24 * time.Hour)
	if err != nil {
		t.Fatalf("PurgeUploaded: %v", err)
	}
	if purged != 1 {
		t.Fatalf("want 1 purged (the uploaded row), got %d", purged)
	}
	// The uploaded row is gone; the pending row survives.
	var uploadedRows int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE id = ?", uploadID).Scan(&uploadedRows); err != nil {
		t.Fatalf("count uploaded survivor: %v", err)
	}
	if uploadedRows != 0 {
		t.Fatalf("uploaded row must be purged, %d remain", uploadedRows)
	}
	if state := uploadedState(t, c, pendingID); state != 0 {
		t.Fatalf("pending row must survive purge in pending state, got %d", state)
	}
	if pending, err := c.PendingCount(); err != nil || pending != 1 {
		t.Fatalf("pending row must survive: count=%d err=%v", pending, err)
	}
}

// TestPurgeWindowKeysOnDeliveryNotScanTime is the regression guard for finding
// offline-1: after a long air-gap outage the catch-up drain uploads scans whose
// created_at (scan time) is days old.  The retention window must measure from
// uploaded_at (delivery time), so such a freshly-delivered row is NOT purged
// within the window — while a row delivered long ago IS.
func TestPurgeWindowKeysOnDeliveryNotScanTime(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Row A: OLD scan time (created days ago during the outage) but RECENT
	// delivery (just drained on reconnect).  Must survive the 24h window.
	resA, err := c.db.Exec(
		"INSERT INTO scan_queue (scan_json, scanned_at, uploaded, created_at, uploaded_at) VALUES (?, ?, 1, ?, ?)",
		"{}", base3339(time.Now()), "2000-01-01 00:00:00", // ancient scan time
		time.Now().UTC().Format("2006-01-02 15:04:05"), // fresh delivery
	)
	if err != nil {
		t.Fatalf("insert row A: %v", err)
	}
	idA, _ := resA.LastInsertId()

	// Row B: delivered long ago.  Must be reaped by the 24h window.
	resB, err := c.db.Exec(
		"INSERT INTO scan_queue (scan_json, scanned_at, uploaded, created_at, uploaded_at) VALUES (?, ?, 1, ?, ?)",
		"{}", base3339(time.Now()), base3339(time.Now()), // recent scan time
		"2000-01-01 00:00:00", // ancient delivery time
	)
	if err != nil {
		t.Fatalf("insert row B: %v", err)
	}
	idB, _ := resB.LastInsertId()

	purged, err := c.PurgeUploaded(24 * time.Hour)
	if err != nil {
		t.Fatalf("PurgeUploaded: %v", err)
	}
	if purged != 1 {
		t.Fatalf("want 1 purged (only the long-ago-delivered row), got %d", purged)
	}
	// Row A (old scan, fresh delivery) survives.
	var aRows int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE id = ?", idA).Scan(&aRows); err != nil {
		t.Fatalf("count row A: %v", err)
	}
	if aRows != 1 {
		t.Fatalf("row A (fresh delivery) must survive the window, %d remain", aRows)
	}
	// Row B (old delivery) is reaped.
	var bRows int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE id = ?", idB).Scan(&bRows); err != nil {
		t.Fatalf("count row B: %v", err)
	}
	if bRows != 0 {
		t.Fatalf("row B (old delivery) must be purged, %d remain", bRows)
	}
}

// TestUploadedAtMigrationOnLegacyDB proves the additive ALTER migration runs on
// a pre-existing cache created before the uploaded_at column existed: the column
// is added, legacy terminal rows are backfilled to created_at, and pending rows
// keep a NULL uploaded_at.  Regression guard for finding offline-1's migration.
func TestUploadedAtMigrationOnLegacyDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")

	// Build a LEGACY database by hand: the pre-migration schema with no
	// uploaded_at column, seeded with a pending, an uploaded, and a dead row.
	legacy, err := sql.Open("sqlite", cacheDSN(dbPath))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	legacy.SetMaxOpenConns(1)
	if _, err := legacy.Exec(`
		CREATE TABLE scan_queue (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_json  TEXT    NOT NULL,
			scanned_at TEXT    NOT NULL,
			uploaded   INTEGER NOT NULL DEFAULT 0,
			created_at TEXT    NOT NULL DEFAULT (datetime('now'))
		);`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	legacyCreated := "2001-02-03 04:05:06"
	for i := 0; i < 3; i++ {
		if _, err := legacy.Exec(
			"INSERT INTO scan_queue (scan_json, scanned_at, uploaded, created_at) VALUES (?, ?, ?, ?)",
			"{}", base3339(time.Now()), i, legacyCreated,
		); err != nil {
			t.Fatalf("seed legacy row %d: %v", i, err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	// Re-open through NewCache — initSchema must ALTER-add uploaded_at and
	// backfill the terminal rows.  This must not error on the existing DB.
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache on legacy db: %v", err)
	}
	defer c.Close()

	// The column now exists.
	var hasCol bool
	rows, err := c.db.Query("PRAGMA table_info(scan_queue)")
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			rows.Close()
			t.Fatalf("scan table_info: %v", err)
		}
		if name == "uploaded_at" {
			hasCol = true
		}
	}
	rows.Close()
	if !hasCol {
		t.Fatal("migration did not add uploaded_at column")
	}

	// Terminal rows (uploaded IN (1,2)) are backfilled to created_at; the
	// pending row (uploaded = 0) keeps a NULL uploaded_at.
	assertUploadedAt := func(uploaded int, want sql.NullString) {
		var got sql.NullString
		if err := c.db.QueryRow(
			"SELECT uploaded_at FROM scan_queue WHERE uploaded = ?", uploaded,
		).Scan(&got); err != nil {
			t.Fatalf("read uploaded_at for uploaded=%d: %v", uploaded, err)
		}
		if got != want {
			t.Fatalf("uploaded=%d uploaded_at: want %+v, got %+v", uploaded, want, got)
		}
	}
	assertUploadedAt(0, sql.NullString{}) // pending → NULL
	assertUploadedAt(1, sql.NullString{String: legacyCreated, Valid: true})
	assertUploadedAt(2, sql.NullString{String: legacyCreated, Valid: true})

	// And the backfilled window is honored: with created_at far in the past,
	// the terminal rows purge; the pending row survives.
	purged, err := c.PurgeUploaded(24 * time.Hour)
	if err != nil {
		t.Fatalf("PurgeUploaded after migration: %v", err)
	}
	if purged != 2 {
		t.Fatalf("want 2 purged (backfilled terminal rows), got %d", purged)
	}
	if pending, err := c.PendingCount(); err != nil || pending != 1 {
		t.Fatalf("pending row must survive: count=%d err=%v", pending, err)
	}
}

// TestEnqueueScanSucceedsWhenEvictionFails proves the durability contract of
// EnqueueScan (finding offline-1): the autocommitted INSERT is the durability
// point.  Once a row is durably queued, a failure in the best-effort
// backlog-cap eviction (its own BEGIN IMMEDIATE txn) must NOT be reported to
// the caller as an enqueue failure — otherwise the caller would treat the
// already-queued scan as lost and write a duplicate to a fallback file plus a
// misleading cache.fallback audit entry.  The eviction failure is induced
// deterministically with a BEFORE DELETE trigger that aborts every DELETE on
// scan_queue: the INSERT still succeeds, only the eviction's DELETE fails.
func TestEnqueueScanSucceedsWhenEvictionFails(t *testing.T) {
	orig := maxPendingScans
	maxPendingScans = 1 // force an eviction on the second row
	defer func() { maxPendingScans = orig }()

	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Seed one pending row directly so the next EnqueueScan pushes pending to 2,
	// over the cap of 1, and eviction must DELETE the oldest.
	if _, err := c.db.Exec(
		"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
		`{"seed":1}`, base3339(time.Now().Add(-time.Minute)),
	); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// Make every DELETE on scan_queue fail — this fails ONLY the eviction txn's
	// DELETE, not the INSERT.
	if _, err := c.db.Exec(
		`CREATE TRIGGER block_delete BEFORE DELETE ON scan_queue
		 BEGIN SELECT RAISE(ABORT, 'delete blocked for test'); END;`,
	); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	ev, err := c.EnqueueScan(newScan("host-evict-fail"))
	if err != nil {
		t.Fatalf("EnqueueScan must return nil after a committed insert even when eviction fails, got: %v", err)
	}
	if ev.Count != 0 {
		t.Fatalf("eviction failed, so EvictionResult.Count must be 0, got %d", ev.Count)
	}

	// The just-inserted row IS durably queued: pending must be 2 (the seed +
	// the new scan), because the failed eviction rolled back its own DELETE.
	pending, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 2 {
		t.Fatalf("both rows must remain queued (insert committed, eviction rolled back): got %d, want 2", pending)
	}
}

// TestEnqueueScanErrorsOnInsertFailure proves the other half of the contract:
// a genuine INSERT failure (before commit — here, a closed DB) is still
// reported as an error so the caller's last-resort fallback path fires and the
// scan is not silently lost.
func TestEnqueueScanErrorsOnInsertFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	// Close so the INSERT itself fails before any row is durably queued.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := c.EnqueueScan(newScan("host-insert-fail")); err == nil {
		t.Fatal("EnqueueScan must return an error when the INSERT fails on a closed DB")
	}
}

// TestReopenTransientFailureIsRetryableNotPermanentlyDead is the core self-heal
// guarantee for findings offline-1/2: when Reopen closes the old handle but
// OpenResilient then fails for a TRANSIENT reason (here, the parent directory is
// made unwritable → SQLITE_CANTOPEN, exactly like a full/locked disk), the cache
// must NOT be left permanently dead.  It flags NeedsReopen, and a LATER Reopen —
// after the fault clears — succeeds WITHOUT a process restart and with the
// pending backlog INTACT (the healthy on-disk file was never quarantined).
func TestReopenTransientFailureIsRetryableNotPermanentlyDead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Queue a scan so we can prove the backlog survives the transient fault.
	if _, err := c.EnqueueScan(newScan("survives-transient-reopen")); err != nil {
		t.Fatalf("EnqueueScan: %v", err)
	}
	if c.NeedsReopen() {
		t.Fatal("a healthy cache must not report NeedsReopen")
	}

	// Inject the fault: make the parent dir unwritable so Reopen's OpenResilient
	// (NewCache) fails with a transient CANTOPEN, NOT a corruption code.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod dir 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	recovered, quarantinedPath, err := c.Reopen()
	if err == nil {
		t.Fatal("Reopen must return the transient open error")
	}
	if recovered {
		t.Fatal("a transient failure must NOT report recovered (no quarantine happened)")
	}
	if quarantinedPath != "" {
		t.Fatalf("a transient failure must not quarantine, got %q", quarantinedPath)
	}
	// The daemon-critical invariant: the cache is flagged for retry, NOT dead.
	if !c.NeedsReopen() {
		t.Fatal("after a transient Reopen failure the cache must report NeedsReopen so a later cycle retries")
	}
	// No .corrupt-* file may have been created — the healthy queue was preserved.
	_ = os.Chmod(dir, 0o755)
	if corrupt, _ := filepath.Glob(dbPath + ".corrupt-*"); len(corrupt) != 0 {
		t.Fatalf("a transient failure must not quarantine the healthy db, found %v", corrupt)
	}

	// Fault cleared (dir writable again): a later Reopen must succeed IN-PROCESS.
	recovered, _, err = c.Reopen()
	if err != nil {
		t.Fatalf("Reopen after the fault cleared must succeed, got %v", err)
	}
	if recovered {
		t.Fatal("re-opening the healthy file must not report recovered (backlog intact, no quarantine)")
	}
	if c.NeedsReopen() {
		t.Fatal("a successful Reopen must clear NeedsReopen")
	}

	// The backlog survived: the queued scan is still pending and the queue works.
	count, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount after self-heal: %v", err)
	}
	if count != 1 {
		t.Fatalf("backlog must survive a transient reopen fault, got %d pending (want 1)", count)
	}
	if _, err := c.EnqueueScan(newScan("post-self-heal")); err != nil {
		t.Fatalf("EnqueueScan after self-heal: %v", err)
	}
}

// TestReopenSuccessClearsNeedsReopenViaCorruptPath verifies the round-8/14
// corrupt→Reopen success path still works AND leaves NeedsReopen false: a
// clobbered file is quarantined + recreated and the handle is immediately usable.
func TestReopenSuccessClearsNeedsReopenViaCorruptPath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	c, err := NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, err := c.EnqueueScan(newScan("before-corruption")); err != nil {
		t.Fatalf("EnqueueScan: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := writeFile(dbPath, []byte("this is definitely not a sqlite database")); err != nil {
		t.Fatalf("clobber db: %v", err)
	}

	recovered, quarantinedPath, err := c.Reopen()
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	defer c.Close()
	if !recovered || quarantinedPath == "" {
		t.Fatalf("corrupt Reopen must recover+quarantine, got recovered=%v path=%q", recovered, quarantinedPath)
	}
	if c.NeedsReopen() {
		t.Fatal("a successful corrupt Reopen must leave NeedsReopen false")
	}
	if _, err := c.EnqueueScan(newScan("after-recovery")); err != nil {
		t.Fatalf("EnqueueScan after Reopen: %v", err)
	}
}
