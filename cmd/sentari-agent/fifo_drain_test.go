//go:build enterprise

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// recordingUploader is a scanUploader stub that records the hostname of every
// accepted upload in call order, optionally failing transiently on the Nth call.
type recordingUploader struct {
	got    []string
	calls  int
	failAt int // 1-based call index to fail on; 0 = never fail
}

func (r *recordingUploader) UploadScan(_ context.Context, result *scanner.ScanResult) error {
	r.calls++
	if r.failAt > 0 && r.calls == r.failAt {
		return errors.New("transient network failure")
	}
	r.got = append(r.got, result.Hostname)
	return nil
}

func newTestScan(host string, scannedAt time.Time) *scanner.ScanResult {
	return &scanner.ScanResult{Hostname: host, ScannedAt: scannedAt}
}

func openTestCacheAudit(t *testing.T) (*cache.Cache, *audit.AuditLog) {
	t.Helper()
	dir := t.TempDir()
	c, err := cache.NewCache(filepath.Join(dir, "cache.db"))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	a, err := audit.NewAuditLog(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return c, a
}

// TestDrainThenFreshUploadIsFIFO verifies that with a backlog of 3 queued scans
// and a working server, the drain empties the queue oldest-first and reports
// backlogEmpty=true, after which the fresh scan is uploaded directly — so the
// server sees all 4 uploads in strict chronological order (finding offline-5).
func TestDrainThenFreshUploadIsFIFO(t *testing.T) {
	c, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, host := range []string{"scan-a", "scan-b", "scan-c"} {
		if _, err := c.EnqueueScan(newTestScan(host, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("EnqueueScan %s: %v", host, err)
		}
	}

	up := &recordingUploader{}
	backlogEmpty := drainCachedScans(context.Background(), up, c, a, slog.Default())
	if !backlogEmpty {
		t.Fatal("backlogEmpty=false after a fully-successful drain")
	}
	wantDrain := []string{"scan-a", "scan-b", "scan-c"}
	if !equalStrings(up.got, wantDrain) {
		t.Fatalf("drain order = %v, want FIFO %v", up.got, wantDrain)
	}

	// backlogEmpty ⇒ runUpload uploads the fresh scan directly.
	fresh := newTestScan("scan-d", base.Add(3*time.Minute))
	if err := up.UploadScan(context.Background(), fresh); err != nil {
		t.Fatalf("fresh direct upload: %v", err)
	}
	wantAll := []string{"scan-a", "scan-b", "scan-c", "scan-d"}
	if !equalStrings(up.got, wantAll) {
		t.Fatalf("server upload order = %v, want FIFO %v", up.got, wantAll)
	}
}

// TestTransientMidDrainEnqueuesFreshScan verifies that when a transient failure
// interrupts the drain, backlogEmpty=false and the fresh scan is ENQUEUED behind
// the remaining backlog rather than uploaded ahead of it — preserving FIFO order
// on the next cycle (finding offline-5).
func TestTransientMidDrainEnqueuesFreshScan(t *testing.T) {
	c, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, host := range []string{"scan-a", "scan-b", "scan-c"} {
		if _, err := c.EnqueueScan(newTestScan(host, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("EnqueueScan %s: %v", host, err)
		}
	}

	// Fail on the 2nd upload: scan-a succeeds, scan-b fails transiently, drain stops.
	up := &recordingUploader{failAt: 2}
	backlogEmpty := drainCachedScans(context.Background(), up, c, a, slog.Default())
	if backlogEmpty {
		t.Fatal("backlogEmpty=true despite a transient failure mid-drain")
	}
	if !equalStrings(up.got, []string{"scan-a"}) {
		t.Fatalf("only scan-a should have uploaded before the transient failure, got %v", up.got)
	}

	// runUpload's FIFO branch: enqueue the fresh scan, do NOT upload it.
	fresh := newTestScan("scan-d", base.Add(3*time.Minute))
	enqueueScanWithFallback(fresh, c, a, t.TempDir())

	// scan-d must not have reached the server.
	for _, h := range up.got {
		if h == "scan-d" {
			t.Fatal("fresh scan-d was uploaded ahead of the backlog — FIFO violated")
		}
	}
	// Pending queue now holds scan-b, scan-c (undrained) + scan-d (freshly enqueued).
	n, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if n != 3 {
		t.Fatalf("pending count = %d, want 3 (scan-b, scan-c, scan-d)", n)
	}
}

// statusUploader fails the upload for specific hostnames with a given HTTP
// status (surfaced as *comms.HTTPStatusError, wrapped as the real client does),
// and records the hostnames it accepted in call order.
type statusUploader struct {
	failCode map[string]int
	got      []string
}

func (s *statusUploader) UploadScan(_ context.Context, result *scanner.ScanResult) error {
	if code, ok := s.failCode[result.Hostname]; ok {
		return fmt.Errorf("upload: %w", &comms.HTTPStatusError{Op: "scan upload", StatusCode: code})
	}
	s.got = append(s.got, result.Hostname)
	return nil
}

// TestDrainMarksPayloadPermanentDeadAndContinues proves a payload-permanent 413
// row is marked dead and the drain continues past it (finding offline-1: the
// head-of-line-block fix is preserved for genuinely poison payloads).
func TestDrainMarksPayloadPermanentDeadAndContinues(t *testing.T) {
	c, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, host := range []string{"poison", "good-1", "good-2"} {
		if _, err := c.EnqueueScan(newTestScan(host, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("EnqueueScan %s: %v", host, err)
		}
	}

	up := &statusUploader{failCode: map[string]int{"poison": 413}}
	backlogEmpty := drainCachedScans(context.Background(), up, c, a, slog.Default())
	if !backlogEmpty {
		t.Fatal("backlogEmpty=false: a 413 poison row should be marked dead and the rest drained")
	}
	if !equalStrings(up.got, []string{"good-1", "good-2"}) {
		t.Fatalf("drain order = %v, want [good-1 good-2] (poison marked dead, skipped)", up.got)
	}
	n, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if n != 0 {
		t.Fatalf("pending after drain = %d, want 0 (poison dead, others uploaded)", n)
	}
}

// TestDrainStopsOnAuthStateAndKeepsBacklog proves a recoverable auth-STATE 403
// stops the drain WITHOUT marking anything dead — the whole offline backlog is
// preserved for a later cycle once the auth/proxy misconfiguration is fixed
// (finding offline-1 regression: 401/403/407 must NOT nuke the backlog).
func TestDrainStopsOnAuthStateAndKeepsBacklog(t *testing.T) {
	c, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, host := range []string{"auth-fail", "behind-1"} {
		if _, err := c.EnqueueScan(newTestScan(host, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("EnqueueScan %s: %v", host, err)
		}
	}

	up := &statusUploader{failCode: map[string]int{"auth-fail": 403}}
	backlogEmpty := drainCachedScans(context.Background(), up, c, a, slog.Default())
	if backlogEmpty {
		t.Fatal("backlogEmpty=true on a 403: a recoverable auth error must keep the backlog queued")
	}
	if len(up.got) != 0 {
		t.Fatalf("no rows should have uploaded before the 403 head, got %v", up.got)
	}
	n, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if n != 2 {
		t.Fatalf("pending after 403 = %d, want 2 (both rows stay pending; nothing marked dead)", n)
	}
}

// TestEnqueueEvictionWritesCacheEvictedAudit proves a backlog-cap eviction is
// recorded in the tamper-evident audit chain via enqueueScanWithFallback
// (finding offline-3: silent inventory loss must leave a trace).
func TestEnqueueEvictionWritesCacheEvictedAudit(t *testing.T) {
	c, a := openTestCacheAudit(t)
	cache.SetMaxPendingScans(3)
	defer cache.SetMaxPendingScans(cache.DefaultMaxPendingScans)

	base := time.Now().UTC().Add(-time.Hour)
	// Enqueue 5 scans through the production path; cap is 3, so 2 evictions fire.
	for i, host := range []string{"s-a", "s-b", "s-c", "s-d", "s-e"} {
		enqueueScanWithFallback(newTestScan(host, base.Add(time.Duration(i)*time.Minute)), c, a, t.TempDir())
	}

	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	evictedCount := 0
	var lastDetail string
	for _, e := range entries {
		if e["event_type"] == "cache.evicted" {
			evictedCount++
			lastDetail = e["detail"]
		}
	}
	if evictedCount == 0 {
		t.Fatal("no cache.evicted audit entry written after a backlog-cap eviction")
	}
	if !strings.Contains(lastDetail, "evicted=1") {
		t.Fatalf("cache.evicted detail = %q, want it to report evicted=1", lastDetail)
	}
	if !strings.Contains(lastDetail, "oldest_scanned_at=") || !strings.Contains(lastDetail, "newest_scanned_at=") {
		t.Fatalf("cache.evicted detail = %q, want scanned_at range fields", lastDetail)
	}
}

// scriptedDrainCache is a drainCache stub that replays a fixed sequence of
// DequeuePending results (rows + quarantined count), then reports an empty queue
// once the script is exhausted.  It models the batch-by-batch view the drain loop
// sees so the loop's "continue past an all-corrupt batch" logic can be tested in
// isolation — a real all-corrupt FIRST batch needs ≥ defaultDequeueBatch (100)
// corrupt rows AND cross-package access to the private scan_queue, so the batch
// mechanics are covered at the cache layer instead
// (TestDequeueAllCorruptBatchReportsQuarantinedAndNextAdvances).
type scriptedDrainCache struct {
	batches  []scriptedBatch
	uploaded []int64
}

type scriptedBatch struct {
	rows        []cache.CachedScan
	quarantined int
}

func (s *scriptedDrainCache) DequeuePending() ([]cache.CachedScan, int, error) {
	if len(s.batches) == 0 {
		return nil, 0, nil // script exhausted → genuinely empty queue
	}
	b := s.batches[0]
	s.batches = s.batches[1:]
	return b.rows, b.quarantined, nil
}
func (s *scriptedDrainCache) MarkUploaded(id int64) error {
	s.uploaded = append(s.uploaded, id)
	return nil
}
func (s *scriptedDrainCache) MarkFailedPermanent(int64) error            { return nil }
func (s *scriptedDrainCache) PendingCount() (int, error)                 { return 0, nil }
func (s *scriptedDrainCache) PurgeUploaded(time.Duration) (int64, error) { return 0, nil }
func (s *scriptedDrainCache) Reopen() (bool, string, error)              { return false, "", nil }

// TestDrainContinuesPastAllCorruptBatch is the finding offline-1 regression: when
// the first dequeued batch is ENTIRELY corrupt (0 usable rows, quarantined > 0),
// the drain must NOT read that as "backlog empty" and stop — it must keep going so
// the good rows sitting behind the just-quarantined ones still drain.  A genuinely
// empty batch (0 usable, 0 quarantined) is what stops the loop, so the script
// terminates cleanly (no infinite loop).
func TestDrainContinuesPastAllCorruptBatch(t *testing.T) {
	_, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	good := []cache.CachedScan{
		{QueueID: 101, Result: newTestScan("good-1", base.Add(time.Minute))},
		{QueueID: 102, Result: newTestScan("good-2", base.Add(2*time.Minute))},
	}
	sc := &scriptedDrainCache{batches: []scriptedBatch{
		{rows: nil, quarantined: 3},  // first batch: all-corrupt, 3 rows quarantined
		{rows: good, quarantined: 0}, // good rows behind them
		// third DequeuePending returns (nil, 0, nil) → loop stops.
	}}

	up := &recordingUploader{}
	backlogEmpty := drainCachedScans(context.Background(), up, sc, a, slog.Default())

	if !backlogEmpty {
		t.Fatal("backlogEmpty=false despite a fully-drained queue")
	}
	if !equalStrings(up.got, []string{"good-1", "good-2"}) {
		t.Fatalf("good rows must drain after an all-corrupt first batch; got %v", up.got)
	}
	if !equalInt64s(sc.uploaded, []int64{101, 102}) {
		t.Fatalf("both good rows must be marked uploaded; got %v", sc.uploaded)
	}

	// The all-corrupt batch must leave a tamper-evident trace.
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e["event_type"] == "cache.drain.quarantined" {
			found = true
		}
	}
	if !found {
		t.Fatal("an all-corrupt batch must write a cache.drain.quarantined audit entry")
	}
}

// TestDrainStopsOnGenuinelyEmptyBatch is the negative companion: a batch with no
// usable rows AND nothing quarantined means the queue is genuinely empty, so the
// drain stops immediately without spinning.
func TestDrainStopsOnGenuinelyEmptyBatch(t *testing.T) {
	_, a := openTestCacheAudit(t)
	sc := &scriptedDrainCache{batches: []scriptedBatch{
		{rows: nil, quarantined: 0}, // empty → stop
	}}
	up := &recordingUploader{}
	backlogEmpty := drainCachedScans(context.Background(), up, sc, a, slog.Default())
	if !backlogEmpty {
		t.Fatal("an empty queue must report backlogEmpty=true")
	}
	if len(up.got) != 0 {
		t.Fatalf("nothing should upload from an empty queue, got %v", up.got)
	}
}

// markUploadedFailCache is a drainCache whose UploadScan-succeeds/MarkUploaded-
// fails combination models the at-least-once window (finding offline-3): the
// scan reaches the server but the local "uploaded" mark write errors, so the row
// stays pending and re-delivers next cycle.  DequeuePending replays the SAME rows
// until MarkUploaded succeeds, mirroring the real cache where a failed mark leaves
// uploaded = 0.
type markUploadedFailCache struct {
	rows        []cache.CachedScan
	markErr     error // returned by MarkUploaded while non-nil
	marked      []int64
	pending     int
	dequeueCall int
}

func (m *markUploadedFailCache) DequeuePending() ([]cache.CachedScan, int, error) {
	m.dequeueCall++
	// Once a row is durably marked, it drops out of the pending set.
	if len(m.marked) > 0 {
		return nil, 0, nil
	}
	return m.rows, 0, nil
}
func (m *markUploadedFailCache) MarkUploaded(id int64) error {
	if m.markErr != nil {
		return m.markErr
	}
	m.marked = append(m.marked, id)
	return nil
}
func (m *markUploadedFailCache) MarkFailedPermanent(int64) error { return nil }
func (m *markUploadedFailCache) PendingCount() (int, error)      { return m.pending, nil }
func (m *markUploadedFailCache) PurgeUploaded(time.Duration) (int64, error) {
	return 0, nil
}
func (m *markUploadedFailCache) Reopen() (bool, string, error) { return false, "", nil }

// TestMarkUploadedFailureReDeliversWithStableScannedAt is the finding offline-3
// regression: when a scan uploads successfully but the local MarkUploaded write
// fails, the row must stay pending (backlogEmpty=false → it re-delivers next
// cycle), a clear warning + audit entry must record the intentional duplicate,
// and — critically — the re-delivered payload must carry the IDENTICAL scanned_at
// so the server's (device_id, scanned_at, content-hash) dedup collapses it to the
// original.  This is the agent side of the documented at-least-once contract.
func TestMarkUploadedFailureReDeliversWithStableScannedAt(t *testing.T) {
	_, a := openTestCacheAudit(t)
	scannedAt := time.Date(2026, 7, 9, 10, 30, 0, 0, time.UTC)
	stub := &markUploadedFailCache{
		rows:    []cache.CachedScan{{QueueID: 42, Result: newTestScan("host-x", scannedAt)}},
		markErr: errors.New("disk I/O error writing uploaded flag"),
		pending: 1, // row is still pending after the failed mark
	}

	up := &recordingUploader{}
	backlogEmpty := drainCachedScans(context.Background(), up, stub, a, slog.Default())

	// The upload reached the server exactly once this cycle...
	if !equalStrings(up.got, []string{"host-x"}) {
		t.Fatalf("upload should have succeeded once, got %v", up.got)
	}
	// ...but the mark failed, so nothing was durably marked uploaded...
	if len(stub.marked) != 0 {
		t.Fatalf("MarkUploaded must not have durably marked any row, got %v", stub.marked)
	}
	// ...and the queue is reported non-empty so the scan re-delivers next cycle.
	if backlogEmpty {
		t.Fatal("backlogEmpty=true despite a failed MarkUploaded — the scan would not re-deliver")
	}

	// The re-delivered payload must carry the identical scanned_at (stable dedup
	// key).  DequeuePending replays the same row, so simulate the next cycle's
	// re-upload and assert the timestamp is byte-for-byte preserved.
	reRows, _, err := stub.DequeuePending()
	if err != nil {
		t.Fatalf("re-dequeue: %v", err)
	}
	if len(reRows) != 1 {
		t.Fatalf("re-delivery should replay the single pending row, got %d", len(reRows))
	}
	if !reRows[0].Result.ScannedAt.Equal(scannedAt) {
		t.Fatalf("re-delivered scanned_at = %s, want identical %s (server dedup would miss it otherwise)",
			reRows[0].Result.ScannedAt, scannedAt)
	}

	// The intentional at-least-once duplicate must leave a tamper-evident trace.
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	var detail string
	for _, e := range entries {
		if e["event_type"] == "cache.drain.mark_uploaded_failed" {
			detail = e["detail"]
		}
	}
	if detail == "" {
		t.Fatal("a failed MarkUploaded-after-upload must write a cache.drain.mark_uploaded_failed audit entry")
	}
	if !strings.Contains(detail, "queued=42") {
		t.Fatalf("audit detail = %q, want it to reference the queue id", detail)
	}
	if !strings.Contains(detail, scannedAt.Format(time.RFC3339)) {
		t.Fatalf("audit detail = %q, want it to record the stable scanned_at dedup key", detail)
	}
	if !strings.Contains(detail, "re-deliver") {
		t.Fatalf("audit detail = %q, want it to explain the re-delivery", detail)
	}
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
