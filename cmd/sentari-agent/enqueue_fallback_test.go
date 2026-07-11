//go:build enterprise

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/cache"
)

// TestEnqueueScanWithFallback_WritesJSONWhenCacheFails proves the last-resort
// path: when the SQLite enqueue itself fails, the scan is written to a
// scan-fallback-*.json file under the data dir (filepath.Dir(certDir)) so the
// inventory snapshot is never silently lost, and a cache.fallback audit entry is
// recorded.  The failure is induced by closing the cache DB before enqueueing.
func TestEnqueueScanWithFallback_WritesJSONWhenCacheFails(t *testing.T) {
	dir := t.TempDir()
	c, err := cache.NewCache(filepath.Join(dir, "cache.db"))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	// Close so the subsequent EnqueueScan Exec fails, forcing the fallback path.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a, err := audit.NewAuditLog(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	// certDir's PARENT is where fallback files land; use a nested dir so
	// filepath.Dir(certDir) is a real, writable directory we can scan.
	dataDir := t.TempDir()
	certDir := filepath.Join(dataDir, "certs")

	enqueueScanWithFallback(newTestScan("host-x", time.Now().UTC()), c, a, certDir)

	matches, err := filepath.Glob(filepath.Join(dataDir, "scan-fallback-*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("want exactly 1 fallback file, got %d (%v)", len(matches), matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read fallback: %v", err)
	}
	if !strings.Contains(string(data), "host-x") {
		t.Fatalf("fallback file does not contain the scan payload: %s", data)
	}

	if !hasAuditType(auditEntryTypes(t, a), "cache.fallback") {
		t.Fatal("expected a cache.fallback audit entry when the fallback file is written")
	}
}

// TestEnqueueScanWithFallback_NoFallbackWhenOnlyEvictionFails proves the
// offline-1 fix at the production caller: when the INSERT commits (the scan is
// durably queued) but the best-effort backlog-cap eviction fails, EnqueueScan
// reports success, so enqueueScanWithFallback must NOT write a duplicate to a
// fallback file and must NOT emit a misleading cache.fallback audit entry.  The
// eviction failure is induced with a BEFORE DELETE trigger installed on the
// cache DB via a second connection (triggers are schema objects persisted in
// the file, so the cache's own connection fires it): the INSERT still succeeds,
// only the eviction's DELETE aborts.
func TestEnqueueScanWithFallback_NoFallbackWhenOnlyEvictionFails(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")
	c, err := cache.NewCache(dbPath)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer c.Close()

	// Install a DELETE-aborting trigger via a separate connection to the same
	// file (busy_timeout so it never races the idle cache connection's lock).
	raw, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(
		`CREATE TRIGGER block_delete BEFORE DELETE ON scan_queue
		 BEGIN SELECT RAISE(ABORT, 'delete blocked for test'); END;`,
	); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	// Cap of 1: the second enqueue pushes pending to 2, forcing an eviction
	// DELETE that the trigger aborts.
	cache.SetMaxPendingScans(1)
	defer cache.SetMaxPendingScans(cache.DefaultMaxPendingScans)

	a, err := audit.NewAuditLog(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	dataDir := t.TempDir()
	certDir := filepath.Join(dataDir, "certs")

	base := time.Now().UTC()
	enqueueScanWithFallback(newTestScan("host-1", base), c, a, certDir)                  // no eviction (pending 1 == cap)
	enqueueScanWithFallback(newTestScan("host-2", base.Add(time.Minute)), c, a, certDir) // eviction DELETE aborts

	// No fallback file: the insert committed, so the scan was NOT lost.
	matches, err := filepath.Glob(filepath.Join(dataDir, "scan-fallback-*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("no fallback file expected when only eviction fails, got %d (%v)", len(matches), matches)
	}

	// No misleading cache.fallback audit entry asserting a failure that never happened.
	if hasAuditType(auditEntryTypes(t, a), "cache.fallback") {
		t.Fatal("no cache.fallback audit entry expected: the insert committed, only eviction failed")
	}

	// Both scans are durably queued (eviction rolled back its DELETE).
	pending, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if pending != 2 {
		t.Fatalf("both scans must remain queued: got %d, want 2", pending)
	}
}
