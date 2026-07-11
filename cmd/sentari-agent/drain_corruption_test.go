//go:build enterprise

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/cache"
	"github.com/sentari-dev/sentari-agent/common/dbhealth"
)

// genuineSQLiteCorruptionErr returns a real modernc.org/sqlite corruption-class
// error (SQLITE_NOTADB) by opening a non-database file and forcing a read.  Used
// to inject a corruption error into the drain-cache stub, so the recovery path is
// exercised with an error dbhealth.IsCorruption genuinely classifies — no
// fabricated struct-poking.
func genuineSQLiteCorruptionErr(t *testing.T) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "garbage.db")
	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database"), 0o600); err != nil {
		t.Fatalf("seed garbage db: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	_, qerr := db.Exec("SELECT count(*) FROM sqlite_master")
	if qerr == nil {
		t.Fatal("expected a corruption error querying a non-database file")
	}
	return qerr
}

// lazyCorruptCache is a drainCache stub whose DequeuePending returns a
// corruption error until Reopen is called, after which it behaves as a fresh
// empty queue.  It stands in for a cache that hit a torn scan_queue page at
// drain time without having to provoke a real torn SQLite page in the loop.
type lazyCorruptCache struct {
	err      error
	reopened bool
}

func (c *lazyCorruptCache) DequeuePending() ([]cache.CachedScan, int, error) {
	if c.reopened {
		return nil, 0, nil // fresh empty queue after recovery
	}
	return nil, 0, c.err
}
func (c *lazyCorruptCache) MarkUploaded(int64) error                   { return nil }
func (c *lazyCorruptCache) MarkFailedPermanent(int64) error            { return nil }
func (c *lazyCorruptCache) PendingCount() (int, error)                 { return 0, nil }
func (c *lazyCorruptCache) PurgeUploaded(time.Duration) (int64, error) { return 0, nil }
func (c *lazyCorruptCache) Reopen() (bool, string, error) {
	c.reopened = true
	return true, "/data/cache.db.corrupt-1700000000", nil
}

// TestDrainRecoversFromLazyCacheCorruption verifies the drain path reacts to a
// corruption-class DequeuePending error by triggering Cache.Reopen
// (quarantine+recreate) and writing a cache.recreated audit entry, then reporting
// an empty backlog so the cycle proceeds — instead of erroring on the same torn
// page every cycle forever (finding offline-1).
func TestDrainRecoversFromLazyCacheCorruption(t *testing.T) {
	_, a := openTestCacheAudit(t)

	stub := &lazyCorruptCache{err: genuineSQLiteCorruptionErr(t)}
	if !dbhealth.IsCorruption(stub.err) {
		t.Fatalf("test setup: injected error must be corruption-class, got %v", stub.err)
	}

	up := &recordingUploader{}
	backlogEmpty := drainCachedScans(context.Background(), up, stub, a, slog.Default())

	if !stub.reopened {
		t.Fatal("a corruption error from DequeuePending must trigger Cache.Reopen (quarantine+recreate)")
	}
	if len(up.got) != 0 {
		t.Fatalf("no upload should occur when the queue read fails, got %v", up.got)
	}
	// After the recreate the queue is empty, so the drain reports an empty backlog
	// and the fresh scan uploads directly on this cycle.
	if !backlogEmpty {
		t.Fatal("after recreate the backlog is empty; drain must report backlogEmpty=true")
	}

	// The recovery must be recorded in the tamper-evident audit chain.
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e["event_type"] == "cache.recreated" {
			found = true
			if !strings.Contains(e["detail"], "corrupt_db_quarantined=") {
				t.Fatalf("cache.recreated detail = %q, want a quarantined path", e["detail"])
			}
		}
	}
	if !found {
		t.Fatal("drain corruption recovery must write a cache.recreated audit entry")
	}
}

// TestDrainNonCorruptionReadErrorDoesNotReopen verifies the negative case: a
// plain (transient) read error from DequeuePending must NOT trigger a
// quarantine+recreate — the backlog is preserved for the next cycle.
func TestDrainNonCorruptionReadErrorDoesNotReopen(t *testing.T) {
	_, a := openTestCacheAudit(t)

	stub := &lazyCorruptCache{err: context.DeadlineExceeded} // non-sqlite, non-corruption
	if dbhealth.IsCorruption(stub.err) {
		t.Fatal("test setup: injected error must NOT be corruption-class")
	}

	up := &recordingUploader{}
	_ = drainCachedScans(context.Background(), up, stub, a, slog.Default())

	if stub.reopened {
		t.Fatal("a transient (non-corruption) read error must NOT quarantine+recreate the cache")
	}
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	for _, e := range entries {
		if e["event_type"] == "cache.recreated" {
			t.Fatal("no cache.recreated entry should be written for a transient read error")
		}
	}
}

// failingReopenCache is a drainCache stub whose DequeuePending returns a
// corruption error and whose Reopen FAILS (transient — e.g. the post-quarantine
// open hit ENOSPC).  It models a cache whose in-drain recovery did not complete.
type failingReopenCache struct {
	err         error
	reopenErr   error
	reopenCalls int
}

func (c *failingReopenCache) DequeuePending() ([]cache.CachedScan, int, error) {
	return nil, 0, c.err
}
func (c *failingReopenCache) MarkUploaded(int64) error                   { return nil }
func (c *failingReopenCache) MarkFailedPermanent(int64) error            { return nil }
func (c *failingReopenCache) PendingCount() (int, error)                 { return 0, c.err }
func (c *failingReopenCache) PurgeUploaded(time.Duration) (int64, error) { return 0, nil }
func (c *failingReopenCache) Reopen() (bool, string, error) {
	c.reopenCalls++
	return false, "", c.reopenErr
}

// TestDrainFailedRecoveryIsNonTerminal verifies that when the in-drain
// corruption recovery (Cache.Reopen) FAILS, drainCachedScans does not panic,
// writes NO cache.recreated entry (recovery did not complete), and simply stops
// for this cycle — the failure is retryable next cycle (the cycle-start health
// hook re-attempts the re-open), not terminal (findings offline-1/2).
func TestDrainFailedRecoveryIsNonTerminal(t *testing.T) {
	_, a := openTestCacheAudit(t)

	stub := &failingReopenCache{
		err:       genuineSQLiteCorruptionErr(t),
		reopenErr: context.DeadlineExceeded, // transient reopen failure
	}
	up := &recordingUploader{}
	backlogEmpty := drainCachedScans(context.Background(), up, stub, a, slog.Default())

	if stub.reopenCalls == 0 {
		t.Fatal("a corruption error must trigger a Reopen attempt")
	}
	if backlogEmpty {
		t.Fatal("a failed recovery must conservatively report a non-empty backlog")
	}
	for _, et := range auditEventList(t, a) {
		if et == "cache.recreated" {
			t.Fatal("a FAILED recovery must not write cache.recreated (recovery did not complete)")
		}
	}
}
