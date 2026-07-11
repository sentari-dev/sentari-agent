//go:build enterprise

package main

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/sentari-dev/sentari-agent/audit"
)

// stubReopener is a cacheReopener stub for the cycle-start health hook so
// ensureCacheOpen can be exercised without provoking a real transient SQLite
// open failure.  needsReopen drives NeedsReopen; reopenErr / reopenRecovered
// shape the Reopen outcome; reopenCalls counts invocations.
type stubReopener struct {
	needsReopen     bool
	reopenErr       error
	reopenRecovered bool
	reopenPath      string
	reopenCalls     int
}

func (s *stubReopener) NeedsReopen() bool { return s.needsReopen }
func (s *stubReopener) Reopen() (bool, string, error) {
	s.reopenCalls++
	if s.reopenErr != nil {
		return false, "", s.reopenErr
	}
	// A successful reopen clears the needs-reopen state, mirroring *cache.Cache.
	s.needsReopen = false
	return s.reopenRecovered, s.reopenPath, nil
}

// auditEventList returns the event_type of every unshipped audit entry (in
// order, duplicates preserved) so a test can assert which health-hook events
// landed in the tamper-evident chain and how many times.
func auditEventList(t *testing.T, a *audit.AuditLog) []string {
	t.Helper()
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e["event_type"])
	}
	return out
}

func countEvent(events []string, want string) int {
	n := 0
	for _, e := range events {
		if e == want {
			n++
		}
	}
	return n
}

// TestEnsureCacheOpenHealthyIsNoOp verifies a cache that does not need reopening
// is left untouched: no Reopen call, no audit entry, reports healthy.
func TestEnsureCacheOpenHealthyIsNoOp(t *testing.T) {
	_, a := openTestCacheAudit(t)
	s := &stubReopener{needsReopen: false}

	if healthy := ensureCacheOpen(s, a, slog.Default()); !healthy {
		t.Fatal("a healthy cache must report healthy=true")
	}
	if s.reopenCalls != 0 {
		t.Fatalf("a healthy cache must not be re-opened, got %d Reopen calls", s.reopenCalls)
	}
	if events := auditEventList(t, a); len(events) != 0 {
		t.Fatalf("a healthy cache must write no audit entry, got %v", events)
	}
}

// TestEnsureCacheOpenWedgedEmitsLoudAuditEachCycle verifies that while the
// re-open keeps failing (disk still full), the hook emits a cache.wedged audit
// entry EVERY cycle so the degraded, scan-losing state is visible in the
// tamper-evident trail rather than silent (findings offline-1/2).
func TestEnsureCacheOpenWedgedEmitsLoudAuditEachCycle(t *testing.T) {
	_, a := openTestCacheAudit(t)
	s := &stubReopener{needsReopen: true, reopenErr: errors.New("no space left on device")}

	const cycles = 3
	for i := 0; i < cycles; i++ {
		if healthy := ensureCacheOpen(s, a, slog.Default()); healthy {
			t.Fatalf("cycle %d: a still-failing re-open must report healthy=false", i)
		}
	}
	if s.reopenCalls != cycles {
		t.Fatalf("the hook must retry Reopen every cycle, got %d calls over %d cycles", s.reopenCalls, cycles)
	}
	events := auditEventList(t, a)
	if got := countEvent(events, "cache.wedged"); got != cycles {
		t.Fatalf("want a cache.wedged audit entry each cycle (%d), got %d in %v", cycles, got, events)
	}
	if got := countEvent(events, "cache.reopened"); got != 0 {
		t.Fatalf("a wedged cache must not write cache.reopened, got %d", got)
	}
}

// TestEnsureCacheOpenReopenSuccessAudits verifies the recovery path: once the
// fault clears, Reopen succeeds and the hook writes exactly one cache.reopened
// audit entry (with the quarantined path when the corrupt file was recreated)
// and reports healthy.
func TestEnsureCacheOpenReopenSuccessAudits(t *testing.T) {
	_, a := openTestCacheAudit(t)
	s := &stubReopener{needsReopen: true, reopenRecovered: true, reopenPath: "/data/cache.db.corrupt-1700000000"}

	if healthy := ensureCacheOpen(s, a, slog.Default()); !healthy {
		t.Fatal("a successful re-open must report healthy=true")
	}
	if s.reopenCalls != 1 {
		t.Fatalf("Reopen must be called exactly once, got %d", s.reopenCalls)
	}
	events := auditEventList(t, a)
	if got := countEvent(events, "cache.reopened"); got != 1 {
		t.Fatalf("a successful re-open must write exactly one cache.reopened entry, got %d in %v", got, events)
	}
	if got := countEvent(events, "cache.wedged"); got != 0 {
		t.Fatalf("a successful re-open must not write cache.wedged, got %d", got)
	}

	// A subsequent cycle is a no-op — the stub cleared needsReopen on success.
	if healthy := ensureCacheOpen(s, a, slog.Default()); !healthy {
		t.Fatal("after recovery the cache must stay healthy")
	}
	if s.reopenCalls != 1 {
		t.Fatalf("no further Reopen after recovery, got %d calls", s.reopenCalls)
	}
}
