package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestAuditDSNIncludesBusyTimeout(t *testing.T) {
	dsn := auditDSN("/tmp/whatever.db")
	if !strings.Contains(dsn, "busy_timeout") {
		t.Fatalf("audit DSN should set busy_timeout, got %q", dsn)
	}
}

// TestWALJournalModeApplied verifies that WAL is actually in effect after
// opening the audit log.  The `_journal_mode=WAL` DSN parameter is silently
// ignored by modernc.org/sqlite, so WAL must be applied via PRAGMA exec in
// NewAuditLog.
func TestWALJournalModeApplied(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	var mode string
	if err := a.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Fatalf("journal_mode: want %q, got %q", "wal", mode)
	}
}

func TestConcurrentLogNoBusyError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	const writers = 8
	const each = 25
	var wg sync.WaitGroup
	errCh := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := a.Log("test.event", "detail"); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent Log errored (busy?): %v", err)
	}
}

// TestConcurrentMultiInstanceChainStaysLinear simulates two separate agent
// PROCESSES appending to the same audit database file at the same time.  Each
// process is modelled by its own *AuditLog instance: a distinct *sql.DB
// connection AND a distinct in-memory lastHash.  This is the case the in-process
// mutex + SetMaxOpenConns(1) cannot protect against — two writers can read the
// same head, both insert, and the hash chain forks permanently (two rows claim
// the same predecessor).  The fix must serialise "read head + insert" at the DB
// level so the chain stays linear regardless of how many processes append.
func TestConcurrentMultiInstanceChainStaysLinear(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	const instances = 4
	const each = 30

	logs := make([]*AuditLog, instances)
	for i := range logs {
		a, err := NewAuditLog(dbPath)
		if err != nil {
			t.Fatalf("NewAuditLog instance %d: %v", i, err)
		}
		logs[i] = a
		defer a.Close()
	}

	var wg sync.WaitGroup
	errCh := make(chan error, instances*each)
	for _, a := range logs {
		wg.Add(1)
		go func(a *AuditLog) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := a.Log("multi.proc", "detail"); err != nil {
					errCh <- err
					return
				}
			}
		}(a)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent multi-instance Log errored: %v", err)
	}

	// Read every row back in id order and assert the chain is strictly linear:
	// each row's prev_hash equals the previous row's content_hash, and no two
	// rows share the same prev_hash (a fork).
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, content_hash, prev_hash FROM audit_log ORDER BY id ASC")
	if err != nil {
		t.Fatalf("query rows: %v", err)
	}
	defer rows.Close()

	seenPrev := make(map[string]int)
	expectedPrev := ""
	count := 0
	for rows.Next() {
		var id int
		var contentHash, prevHash string
		if err := rows.Scan(&id, &contentHash, &prevHash); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if prevHash != expectedPrev {
			t.Fatalf("chain forked at row %d: prev_hash=%q expected=%q", id, prevHash, expectedPrev)
		}
		if prior, dup := seenPrev[prevHash]; dup {
			t.Fatalf("chain forked: rows %d and %d both claim prev_hash=%q", prior, id, prevHash)
		}
		seenPrev[prevHash] = id
		expectedPrev = contentHash
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iterate: %v", err)
	}

	if want := instances * each; count != want {
		t.Fatalf("expected %d rows, got %d", want, count)
	}

	// And the canonical verifier must agree the chain is clean.
	if err := logs[0].VerifyChain(); err != nil {
		t.Fatalf("VerifyChain after concurrent multi-instance writes: %v", err)
	}
}

func TestVerifyChainCleanWhenUntampered(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	for i := 0; i < 5; i++ {
		if err := a.Log("test.event", "detail-"+string(rune('a'+i))); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	if err := a.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain on untampered log: want nil, got %v", err)
	}
}

func TestVerifyChainDetectsTamperedDetail(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := a.Log("test.event", "detail-"+string(rune('a'+i))); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	a.Close()

	// Tamper a row's detail directly via SQL, simulating a local-root
	// attacker who DROPped the append-only triggers first.  We bypass the
	// triggers by dropping them, then mutate row id=3.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS audit_no_update;`); err != nil {
		t.Fatalf("drop update trigger: %v", err)
	}
	if _, err := db.Exec(`UPDATE audit_log SET detail = 'TAMPERED' WHERE id = 3`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	db.Close()

	// Reopen and verify the chain detects the tamper at row 3.
	a2, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("reopen NewAuditLog: %v", err)
	}
	defer a2.Close()

	err = a2.VerifyChain()
	if err == nil {
		t.Fatalf("VerifyChain on tampered log: want error, got nil")
	}
	if !strings.Contains(err.Error(), "3") {
		t.Fatalf("VerifyChain error should identify row 3, got: %v", err)
	}
}

// TestLogWritesSchemeV2 proves new rows are stamped hash_version=2 and their
// content_hash is the length-prefixed v2 encoding (not the legacy v1 concat).
func TestLogWritesSchemeV2(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	if err := a.Log("scan_started", "envs=3"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	var hv int
	var et, detail, prev, createdAt, contentHash string
	if err := a.db.QueryRow(
		"SELECT hash_version, event_type, detail, prev_hash, created_at, content_hash FROM audit_log WHERE id = 1",
	).Scan(&hv, &et, &detail, &prev, &createdAt, &contentHash); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if hv != hashSchemeV2 {
		t.Fatalf("hash_version = %d, want %d", hv, hashSchemeV2)
	}
	if want := computeHashV2(et, detail, prev, createdAt); contentHash != want {
		t.Fatalf("content_hash not v2-encoded: got %s want %s", contentHash, want)
	}
}

// TestUnshippedEntriesIncludesHashVersion proves the shipped map carries the
// per-entry scheme so the server can recompute with the right recipe.
func TestUnshippedEntriesIncludesHashVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	if err := a.Log("e", "d"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if entries[0]["hash_version"] != "2" {
		t.Fatalf("hash_version in shipped entry = %q, want \"2\"", entries[0]["hash_version"])
	}
}

// TestVerifyChainMixedV1ThenV2Verifies builds a chain whose genesis row was
// written by an old agent (scheme v1) and whose successor is a new v2 row that
// links onto it.  A mixed chain must verify: linkage is scheme-independent and
// each row is recomputed with its own encoding.
func TestVerifyChainMixedV1ThenV2Verifies(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	// Bootstrap the schema, then close so we can insert legacy rows directly.
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	a.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	et1, d1, ts1 := "scan_started", "envs=3", "2026-05-23T10:00:00.000000001Z"
	h1 := computeHashV1(et1, d1, "", ts1)
	if _, err := db.Exec(
		"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at, hash_version) VALUES (?, ?, ?, ?, ?, ?)",
		et1, d1, h1, "", ts1, hashSchemeV1,
	); err != nil {
		t.Fatalf("insert v1 genesis: %v", err)
	}
	et2, d2, ts2 := "scan_completed", "pkgs=42", "2026-05-23T10:00:01.000000002Z"
	h2 := computeHashV2(et2, d2, h1, ts2)
	if _, err := db.Exec(
		"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at, hash_version) VALUES (?, ?, ?, ?, ?, ?)",
		et2, d2, h2, h1, ts2, hashSchemeV2,
	); err != nil {
		t.Fatalf("insert v2 successor: %v", err)
	}
	db.Close()

	a2, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("reopen NewAuditLog: %v", err)
	}
	defer a2.Close()
	if err := a2.VerifyChain(); err != nil {
		t.Fatalf("mixed v1->v2 chain should verify, got: %v", err)
	}
}

// TestVerifyChainV1RowsStillVerify proves a legacy all-v1 chain (every row
// written by an old agent) still validates under the scheme-aware verifier.
func TestVerifyChainV1RowsStillVerify(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	a.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	events := [][3]string{
		{"scan_started", "envs=3", "2026-05-23T10:00:00.000000001Z"},
		{"scan_completed", "pkgs=42", "2026-05-23T10:00:01.000000002Z"},
		{"upload_ok", "scan_id=abc", "2026-05-23T10:00:02.000000003Z"},
	}
	prev := ""
	for _, ev := range events {
		h := computeHashV1(ev[0], ev[1], prev, ev[2])
		if _, err := db.Exec(
			"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at, hash_version) VALUES (?, ?, ?, ?, ?, ?)",
			ev[0], ev[1], h, prev, ev[2], hashSchemeV1,
		); err != nil {
			t.Fatalf("insert v1 row: %v", err)
		}
		prev = h
	}
	db.Close()

	a2, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("reopen NewAuditLog: %v", err)
	}
	defer a2.Close()
	if err := a2.VerifyChain(); err != nil {
		t.Fatalf("all-v1 chain should verify, got: %v", err)
	}
}

// TestVerifyChainDetectsV2FieldBoundaryShiftForgery constructs the exact
// forgery scheme v2 exists to defeat: move trailing bytes of event_type into
// the front of detail while leaving content_hash unchanged.  Under the old v1
// encoding that shift is a hash-EQUAL forgery (asserted as a precondition);
// under v2 the length prefixes make it detectable, so VerifyChain must fail.
func TestVerifyChainDetectsV2FieldBoundaryShiftForgery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	// A genuine v2 row whose field split ("scan" | "started") is ambiguous
	// under plain concatenation.
	if err := a.Log("scan", "started"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	a.Close()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	var prev, createdAt string
	if err := db.QueryRow(
		"SELECT prev_hash, created_at FROM audit_log WHERE id = 1",
	).Scan(&prev, &createdAt); err != nil {
		t.Fatalf("read row: %v", err)
	}

	// Precondition: the shift IS a hash-equal forgery under v1 ...
	if computeHashV1("scan", "started", prev, createdAt) != computeHashV1("sca", "nstarted", prev, createdAt) {
		t.Fatal("precondition failed: v1 must be forgeable by a field-boundary shift")
	}
	// ... but NOT under v2 (length prefixes disambiguate the boundary).
	if computeHashV2("scan", "started", prev, createdAt) == computeHashV2("sca", "nstarted", prev, createdAt) {
		t.Fatal("v2 must not collide under a field-boundary shift")
	}

	// Apply the forgery: shift the boundary, keep content_hash unchanged.
	// Bypass the append-only trigger the way a local-root attacker would.
	if _, err := db.Exec("DROP TRIGGER IF EXISTS audit_no_update"); err != nil {
		t.Fatalf("drop update trigger: %v", err)
	}
	if _, err := db.Exec("UPDATE audit_log SET event_type = 'sca', detail = 'nstarted' WHERE id = 1"); err != nil {
		t.Fatalf("apply forgery: %v", err)
	}
	db.Close()

	a2, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("reopen NewAuditLog: %v", err)
	}
	defer a2.Close()
	if err := a2.VerifyChain(); err == nil {
		t.Fatal("VerifyChain must reject a v2 field-boundary-shift forgery, got nil")
	}
}

// TestEnsureHashVersionColumnMigratesLegacyDB proves an audit_log created
// before scheme v2 (no hash_version column) is migrated in place: the ALTER
// runs, existing rows backfill to hash_version=1 and verify as v1, and a new
// Log appends a linking v2 row.
func TestEnsureHashVersionColumnMigratesLegacyDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	// A pre-v2 schema: audit_log WITHOUT hash_version.
	if _, err := db.Exec(`
		CREATE TABLE audit_log (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type   TEXT    NOT NULL,
			detail       TEXT    NOT NULL,
			content_hash TEXT    NOT NULL,
			prev_hash    TEXT    NOT NULL DEFAULT '',
			created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
			shipped      INTEGER NOT NULL DEFAULT 0
		);`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	et, d, ts := "legacy_event", "legacy=1", "2026-01-01T00:00:00.000000001Z"
	h := computeHashV1(et, d, "", ts)
	if _, err := db.Exec(
		"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		et, d, h, "", ts,
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	db.Close()

	// Opening via NewAuditLog must run ensureHashVersionColumn (ALTER + backfill).
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer a.Close()

	var hv int
	if err := a.db.QueryRow("SELECT hash_version FROM audit_log WHERE id = 1").Scan(&hv); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if hv != hashSchemeV1 {
		t.Fatalf("legacy row hash_version = %d, want %d", hv, hashSchemeV1)
	}
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("legacy row must verify as v1 after migration: %v", err)
	}
	// A new append is v2 and still links onto the migrated v1 genesis.
	if err := a.Log("new_event", "new=1"); err != nil {
		t.Fatalf("Log after migration: %v", err)
	}
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("mixed chain after migration must verify: %v", err)
	}
}

// seedChain bulk-inserts n valid v2 rows in a single transaction so tests that
// need a large backlog do not pay one BEGIN IMMEDIATE per row.  The chain is
// well-formed (each prev_hash links the prior content_hash) so VerifyChain stays
// clean and the append-only triggers are untouched (INSERT is always allowed).
func seedChain(t *testing.T, a *AuditLog, n int) {
	t.Helper()
	tx, err := a.db.Begin()
	if err != nil {
		t.Fatalf("begin seed tx: %v", err)
	}
	prev := ""
	const ts = "2026-01-01T00:00:00.000000000Z"
	for i := 0; i < n; i++ {
		et, d := "seed.event", fmt.Sprintf("d=%d", i)
		h := computeHashV2(et, d, prev, ts)
		if _, err := tx.Exec(
			"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at, hash_version) VALUES (?, ?, ?, ?, ?, ?)",
			et, d, h, prev, ts, hashSchemeV2,
		); err != nil {
			tx.Rollback()
			t.Fatalf("seed insert %d: %v", i, err)
		}
		prev = h
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed tx: %v", err)
	}
}

// TestUnshippedEntriesRespectsLimit proves the new limit parameter bounds the
// fetch (oldest-first) and that a non-positive limit returns the whole backlog.
func TestUnshippedEntriesRespectsLimit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	const total = 25
	seedChain(t, a, total)

	got, err := a.UnshippedEntries(10)
	if err != nil {
		t.Fatalf("UnshippedEntries(10): %v", err)
	}
	if len(got) != 10 {
		t.Fatalf("limit 10: want 10 rows, got %d", len(got))
	}
	// Oldest first: ids must be 1..10 in order.
	for i, e := range got {
		if want := strconv.Itoa(i + 1); e["id"] != want {
			t.Fatalf("row %d: id = %q, want %q (oldest-first)", i, e["id"], want)
		}
	}

	for _, lim := range []int{0, -1} {
		all, err := a.UnshippedEntries(lim)
		if err != nil {
			t.Fatalf("UnshippedEntries(%d): %v", lim, err)
		}
		if len(all) != total {
			t.Fatalf("non-positive limit %d: want %d rows (all), got %d", lim, total, len(all))
		}
	}
}

// TestMarkShippedCursorAndIdempotence proves MarkShipped(maxID) advances the
// shipped cursor to id<=maxID, that re-marking the same or a lower id is a
// harmless no-op, and that a full drain leaves nothing unshipped.
func TestMarkShippedCursorAndIdempotence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	const total = 5
	for i := 0; i < total; i++ {
		if err := a.Log("e", fmt.Sprintf("d=%d", i)); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	if err := a.MarkShipped(3); err != nil {
		t.Fatalf("MarkShipped(3): %v", err)
	}
	remaining, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(remaining) != 2 || remaining[0]["id"] != "4" || remaining[1]["id"] != "5" {
		t.Fatalf("after MarkShipped(3): want ids [4 5], got %v", idsOf(remaining))
	}

	// Idempotent: re-marking id<=3 (already shipped) changes nothing.
	if err := a.MarkShipped(3); err != nil {
		t.Fatalf("MarkShipped(3) again: %v", err)
	}
	again, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(again) != 2 {
		t.Fatalf("idempotent re-mark changed state: want 2 remaining, got %d", len(again))
	}

	// Drain the rest.
	if err := a.MarkShipped(5); err != nil {
		t.Fatalf("MarkShipped(5): %v", err)
	}
	empty, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("after full drain: want 0 remaining, got %d", len(empty))
	}
}

func idsOf(entries []map[string]string) []string {
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e["id"]
	}
	return ids
}

// TestUnshippedDrainsInBatches proves a 25k-entry backlog ships over multiple
// bounded fetches: each UnshippedEntries(batch) returns at most `batch` rows (so
// peak allocation is capped by the batch, not the backlog), the fetch→
// MarkShipped(maxID) cursor advances without dropping or duplicating rows, and
// the loop terminates after ceil(total/batch) iterations with nothing unshipped.
// The `batch` local is the seam: the loop count is a function of it, so we can
// assert batching happened rather than one giant read.
func TestUnshippedDrainsInBatches(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	const total = 25000
	seedChain(t, a, total)

	const batch = 10000
	iterations := 0
	shipped := 0
	for {
		entries, err := a.UnshippedEntries(batch)
		if err != nil {
			t.Fatalf("UnshippedEntries(%d): %v", batch, err)
		}
		if len(entries) == 0 {
			break
		}
		if len(entries) > batch {
			t.Fatalf("fetch exceeded batch cap: got %d, want <= %d (giant allocation)", len(entries), batch)
		}
		iterations++
		maxID := 0
		for _, e := range entries {
			id, convErr := strconv.Atoi(e["id"])
			if convErr != nil {
				t.Fatalf("bad id %q: %v", e["id"], convErr)
			}
			if id > maxID {
				maxID = id
			}
		}
		if err := a.MarkShipped(maxID); err != nil {
			t.Fatalf("MarkShipped(%d): %v", maxID, err)
		}
		shipped += len(entries)
		if len(entries) < batch {
			break
		}
	}

	if want := (total + batch - 1) / batch; iterations != want {
		t.Fatalf("iterations = %d, want %d (ceil(%d/%d))", iterations, want, total, batch)
	}
	if shipped != total {
		t.Fatalf("shipped = %d, want %d", shipped, total)
	}
	leftover, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(leftover) != 0 {
		t.Fatalf("after full drain: want 0 unshipped, got %d", len(leftover))
	}
}

// TestAppendOnlyTriggersOnFreshDB exercises the append-only triggers as they
// are installed by initAuditSchema on a brand-new database — NOT by dropping and
// re-creating them.  Every content column must reject UPDATE, DELETE must be
// refused entirely, and the `shipped` cursor carve-out must succeed.
func TestAppendOnlyTriggersOnFreshDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	if err := a.Log("scan_started", "envs=3"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// UPDATE of any content column (all six listed on audit_no_update) must abort.
	contentCols := []string{"event_type", "detail", "content_hash", "prev_hash", "created_at", "hash_version"}
	for _, col := range contentCols {
		_, err := a.db.Exec(fmt.Sprintf("UPDATE audit_log SET %s = 'x' WHERE id = 1", col))
		if err == nil {
			t.Fatalf("UPDATE of %s succeeded; append-only trigger did not fire", col)
		}
		if !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("UPDATE of %s: want append-only abort, got %v", col, err)
		}
	}

	// DELETE must be refused.
	if _, err := a.db.Exec("DELETE FROM audit_log WHERE id = 1"); err == nil {
		t.Fatalf("DELETE succeeded; append-only trigger did not fire")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("DELETE: want append-only abort, got %v", err)
	}

	// The shipped-flag carve-out must succeed (this is the MarkShipped path).
	if _, err := a.db.Exec("UPDATE audit_log SET shipped = 1 WHERE id = 1"); err != nil {
		t.Fatalf("UPDATE shipped should be allowed (cursor carve-out), got %v", err)
	}
	var shipped int
	if err := a.db.QueryRow("SELECT shipped FROM audit_log WHERE id = 1").Scan(&shipped); err != nil {
		t.Fatalf("read shipped: %v", err)
	}
	if shipped != 1 {
		t.Fatalf("shipped flag not persisted: got %d, want 1", shipped)
	}

	// The row's content must be untouched after all the rejected mutations.
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain after rejected mutations: %v", err)
	}
}

// TestOpenResilientSeedsIdsAboveHighWaterMark proves the finding offline-2 fix:
// after a corrupt-recreate the fresh chain's ids are seeded ABOVE the highest id
// ever assigned in the prior (now-quarantined) chain, rather than restarting at
// 1.  This is what keeps the server from treating the reused ids as an
// id-collision (`prior is not None` → 'local tampering' + drop the whole
// post-recovery history); with the seed, every new id is unseen so the server
// stores them.  The test also simulates the server-side (device_id, entry_id)
// keying to assert no post-recovery entry collides with an already-witnessed id.
func TestOpenResilientSeedsIdsAboveHighWaterMark(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	// Build a chain of n entries so ids 1..n are assigned and the high-water-mark
	// sidecar records the max.  These stand in for entries the server witnessed.
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	const n = 5
	for i := 0; i < n; i++ {
		if err := a.Log("scan.started", fmt.Sprintf("d=%d", i)); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	a.Close()

	// The sidecar must persist the max id and survive the db-file corruption.
	if hwm := readHighWaterMark(dbPath); hwm != n {
		t.Fatalf("high-water-mark sidecar = %d, want %d", hwm, n)
	}

	// Corrupt the db file (and drop its WAL/SHM sidecars) so OpenResilient
	// quarantines it and recreates a fresh chain.
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")
	if err := os.WriteFile(dbPath, []byte("this is definitely not a sqlite database"), 0600); err != nil {
		t.Fatalf("corrupt db: %v", err)
	}

	a2, recovered, quarantined, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer a2.Close()
	if !recovered {
		t.Fatal("expected recovered=true for a corrupt db")
	}
	if quarantined == "" {
		t.Fatal("expected a non-empty quarantine path")
	}

	// The fresh chain's genesis is the audit.recreated marker; its id must be
	// ABOVE the old max (n), not restart at 1.
	var markerID int
	var markerEvent string
	if err := a2.db.QueryRow(
		"SELECT id, event_type FROM audit_log ORDER BY id ASC LIMIT 1",
	).Scan(&markerID, &markerEvent); err != nil {
		t.Fatalf("read genesis: %v", err)
	}
	if markerEvent != "audit.recreated" {
		t.Fatalf("genesis event = %q, want audit.recreated", markerEvent)
	}
	if markerID <= n {
		t.Fatalf("fresh genesis id = %d, want > old max %d (ids must not collide with shipped entries)", markerID, n)
	}

	// A subsequent write continues above the seed too.
	if err := a2.Log("post.recovery", "x"); err != nil {
		t.Fatalf("Log post-recovery: %v", err)
	}

	// Simulate the server-side (device_id, agent_entry_id) keying: the server
	// already witnessed ids 1..n.  Every fresh entry must carry an id > n so
	// `prior is None` server-side and the entries are stored (not flagged as an
	// id-collision 'local tampering' and dropped).
	witnessed := make(map[int]bool, n)
	for i := 1; i <= n; i++ {
		witnessed[i] = true
	}
	entries, err := a2.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("want >= 2 post-recovery entries (marker + post.recovery), got %d", len(entries))
	}
	for _, e := range entries {
		id, convErr := strconv.Atoi(e["id"])
		if convErr != nil {
			t.Fatalf("bad id %q: %v", e["id"], convErr)
		}
		if witnessed[id] {
			t.Fatalf("post-recovery entry id %d collides with an already-witnessed id; the server would flag tampering and drop the batch", id)
		}
	}

	// The fresh chain must itself verify cleanly.
	if err := a2.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain on recreated chain: %v", err)
	}
}

// TestWriteHighWaterMarkFsyncsBeforeRename proves the finding offline-1 fix: the
// durable-write path fsyncs the temp file's contents BEFORE the atomic rename,
// so a power loss after the rename cannot expose a torn/empty sidecar that
// regresses the HWM below already-shipped ids.  The fsync seam is what makes the
// durability observable — a silently-dropped Sync would pass the round-trip
// assertion below yet still leave the power-loss hole open.
func TestWriteHighWaterMarkFsyncsBeforeRename(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	orig := fsyncFile
	var synced int
	fsyncFile = func(f *os.File) error {
		synced++
		return orig(f) // still perform the real fsync
	}
	defer func() { fsyncFile = orig }()

	if err := writeHighWaterMark(dbPath, 42); err != nil {
		t.Fatalf("writeHighWaterMark: %v", err)
	}
	if synced != 1 {
		t.Fatalf("expected the durable-write path to fsync exactly once, got %d", synced)
	}

	// Round-trip: the value persisted and reads back.
	if got := readHighWaterMark(dbPath); got != 42 {
		t.Fatalf("readHighWaterMark = %d, want 42", got)
	}

	// A no-op advance (id <= stored) must not touch the file and not fsync.
	synced = 0
	if err := writeHighWaterMark(dbPath, 10); err != nil {
		t.Fatalf("writeHighWaterMark no-op: %v", err)
	}
	if synced != 0 {
		t.Fatalf("no-op advance must not fsync, got %d", synced)
	}
	if got := readHighWaterMark(dbPath); got != 42 {
		t.Fatalf("readHighWaterMark after no-op = %d, want 42", got)
	}
}

// TestWriteHighWaterMarkSyncErrorSurfaces proves a Sync failure is not silently
// swallowed on the write path: the error propagates (so callers can log it) and
// no torn sidecar is left behind.
func TestWriteHighWaterMarkSyncErrorSurfaces(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	orig := fsyncFile
	fsyncFile = func(f *os.File) error { return fmt.Errorf("simulated fsync failure") }
	defer func() { fsyncFile = orig }()

	err := writeHighWaterMark(dbPath, 7)
	if err == nil {
		t.Fatal("expected fsync error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("want an fsync-labelled error, got %v", err)
	}
	// The failed write must not leave a partial sidecar behind.
	if got := readHighWaterMark(dbPath); got != 0 {
		t.Fatalf("failed write must leave no sidecar, readHighWaterMark = %d", got)
	}
	if entries, _ := filepath.Glob(dbPath + ".hwm*"); len(entries) != 0 {
		t.Fatalf("failed write left temp/sidecar files behind: %v", entries)
	}
}

// TestWriteHighWaterMarkMonotonicDoesNotRegress proves the offline-3 fix: after
// a higher value is persisted, a later write of a LOWER value must not lower the
// sidecar.  This is the anti-collision guarantee — a stale writer must never
// seed a recreated chain below an id the server already witnessed.
func TestWriteHighWaterMarkMonotonicDoesNotRegress(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	if err := writeHighWaterMark(dbPath, 100); err != nil {
		t.Fatalf("writeHighWaterMark(100): %v", err)
	}
	if got := readHighWaterMark(dbPath); got != 100 {
		t.Fatalf("readHighWaterMark = %d, want 100", got)
	}
	// A lower value must be a no-op — the higher value stays persisted.
	if err := writeHighWaterMark(dbPath, 5); err != nil {
		t.Fatalf("writeHighWaterMark(5): %v", err)
	}
	if got := readHighWaterMark(dbPath); got != 100 {
		t.Fatalf("regression: readHighWaterMark = %d, want 100", got)
	}
}

// TestWriteHighWaterMarkLockFileLifecycle proves the read-max-write-rename runs
// under the <sidecar>.lock file and that the lock is created for the duration of
// the critical section and removed afterwards, and that a normal write still
// round-trips the value.
func TestWriteHighWaterMarkLockFileLifecycle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	lockPath := highWaterMarkPath(dbPath) + ".lock"

	var lockSeenDuringWrite bool
	hwmLockHeldHook = func(lp string) {
		if lp != lockPath {
			t.Errorf("hook lock path = %q, want %q", lp, lockPath)
		}
		if _, err := os.Stat(lp); err == nil {
			lockSeenDuringWrite = true
		}
	}
	defer func() { hwmLockHeldHook = nil }()

	if err := writeHighWaterMark(dbPath, 42); err != nil {
		t.Fatalf("writeHighWaterMark: %v", err)
	}
	if !lockSeenDuringWrite {
		t.Fatal("lock file was not held during the write critical section")
	}
	// Round-trip: the value persisted and reads back.
	if got := readHighWaterMark(dbPath); got != 42 {
		t.Fatalf("readHighWaterMark = %d, want 42", got)
	}
	// The lock file must be removed after the write.
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock file not removed after write (stat err = %v)", err)
	}
}

// TestWriteHighWaterMarkStaleWriterCannotRegress simulates a stale writer racing
// a fresh one: a high value is persisted, then a low ("stale") value is written.
// The persisted HWM must stay at the high value.  This is the cross-process
// TOCTOU the monotonic max-on-write guards against.
func TestWriteHighWaterMarkStaleWriterCannotRegress(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	// Fresh writer persists a high id.
	if err := writeHighWaterMark(dbPath, 1000); err != nil {
		t.Fatalf("writeHighWaterMark(1000): %v", err)
	}
	// Stale writer, still holding an old low id, tries to write it.  Even racing
	// (concurrent goroutines here) the persisted value must never drop below the
	// max any writer contributed.
	var wg sync.WaitGroup
	for _, id := range []int64{1, 7, 42, 999} {
		wg.Add(1)
		go func(v int64) {
			defer wg.Done()
			_ = writeHighWaterMark(dbPath, v)
		}(id)
	}
	wg.Wait()
	if got := readHighWaterMark(dbPath); got != 1000 {
		t.Fatalf("stale writers regressed HWM to %d, want 1000", got)
	}
	// And a genuinely higher value still advances it.
	if err := writeHighWaterMark(dbPath, 2000); err != nil {
		t.Fatalf("writeHighWaterMark(2000): %v", err)
	}
	if got := readHighWaterMark(dbPath); got != 2000 {
		t.Fatalf("readHighWaterMark = %d, want 2000", got)
	}
	// No lock file left behind.
	if _, err := os.Stat(highWaterMarkPath(dbPath) + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lock file leaked after concurrent writes (stat err = %v)", err)
	}
}

// auditRowCount returns the number of rows currently in audit_log.
func auditRowCount(t *testing.T, a *AuditLog) int {
	t.Helper()
	var n int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

// auditMinMaxID returns the smallest and largest ids present in audit_log.
func auditMinMaxID(t *testing.T, a *AuditLog) (min, max int64) {
	t.Helper()
	if err := a.db.QueryRow("SELECT COALESCE(MIN(id),0), COALESCE(MAX(id),0) FROM audit_log").Scan(&min, &max); err != nil {
		t.Fatalf("min/max id: %v", err)
	}
	return min, max
}

// TestMarkShippedEnforcesRetentionCap is the regression guard for the
// offline-audit-growth finding: once MaxAuditBytes is set, MarkShipped purges
// the OLDEST already-shipped rows to bound the log, while proving the four
// preservation guarantees hold:
//
//	(a) no UNSHIPPED row is ever dropped (undelivered evidence is preserved),
//	(b) VerifyChain still passes on the retained (mid-life) chain,
//	(c) the id high-water-mark stays unchanged/monotonic, and
//	    sqlite_sequence is untouched so the next id does NOT collide with an
//	    already-shipped id,
//	(d) a recent shipped tail is retained.
func TestMarkShippedEnforcesRetentionCap(t *testing.T) {
	origCap, origTail := MaxAuditBytes, keepShippedTailRows
	defer func() { MaxAuditBytes, keepShippedTailRows = origCap, origTail }()

	// Small tail so the arithmetic below is easy to reason about.
	keepShippedTailRows = 2
	// Disabled while we seed rows: purging must not run until we opt in.
	MaxAuditBytes = 0

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	// 15 rows: ids 1..15.  Big detail so each row comfortably exceeds any tiny
	// cap and the purge is forced.
	const total = 15
	bigDetail := strings.Repeat("x", 512)
	for i := 0; i < total; i++ {
		if err := a.Log("evt.retention", bigDetail); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	hwmBefore := readHighWaterMark(dbPath)
	if hwmBefore != total {
		t.Fatalf("high-water-mark before purge = %d, want %d", hwmBefore, total)
	}

	// Ship ids 1..10 (shipped prefix); ids 11..15 stay UNSHIPPED.  Set a cap of 1
	// byte so the purge wants to reclaim everything it safely can: all shipped
	// rows below the tail (ids 1..8), leaving the 2-row shipped tail (9,10) and
	// every unshipped row (11..15).
	MaxAuditBytes = 1
	if err := a.MarkShipped(10); err != nil {
		t.Fatalf("MarkShipped(10): %v", err)
	}

	// (a) every unshipped row (11..15) must survive.
	unshipped, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if got := idsOf(unshipped); len(got) != 5 || got[0] != "11" || got[4] != "15" {
		t.Fatalf("unshipped rows: want ids 11..15 all retained, got %v", got)
	}

	// (d) the oldest shipped rows are purged; a 2-row shipped tail (9,10) remains.
	// So the surviving id range is [9,15]: 7 rows.
	if n := auditRowCount(t, a); n != 7 {
		t.Fatalf("retained row count = %d, want 7 (ids 9..15)", n)
	}
	minID, maxID := auditMinMaxID(t, a)
	if minID != 9 {
		t.Fatalf("lowest retained id = %d, want 9 (ids 1..8 purged)", minID)
	}
	if maxID != total {
		t.Fatalf("highest retained id = %d, want %d", maxID, total)
	}

	// (b) VerifyChain must still pass on the retained, now mid-life chain whose
	// first row's prev_hash points at the purged id 8.
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain after purge: want nil, got %v", err)
	}

	// (c) the id high-water-mark is unchanged...
	if got := readHighWaterMark(dbPath); got != hwmBefore {
		t.Fatalf("high-water-mark changed by purge: got %d, want %d", got, hwmBefore)
	}
	// ...and AUTOINCREMENT was not reset, so the next id climbs above every
	// already-shipped id rather than colliding with a purged one.
	if err := a.Log("evt.after.purge", "tail"); err != nil {
		t.Fatalf("Log after purge: %v", err)
	}
	if _, maxAfter := auditMinMaxID(t, a); maxAfter != total+1 {
		t.Fatalf("next id after purge = %d, want %d (no id reuse)", maxAfter, total+1)
	}
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain after post-purge append: %v", err)
	}
}

// TestRetentionDisabledByDefaultKeepsEverything proves the cap is opt-in: with
// MaxAuditBytes at its 0 default, MarkShipped never deletes a row.
func TestRetentionDisabledByDefaultKeepsEverything(t *testing.T) {
	origCap := MaxAuditBytes
	defer func() { MaxAuditBytes = origCap }()
	MaxAuditBytes = 0 // explicit: the default, no purge

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	for i := 0; i < 10; i++ {
		if err := a.Log("evt", strings.Repeat("y", 256)); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	if err := a.MarkShipped(10); err != nil {
		t.Fatalf("MarkShipped(10): %v", err)
	}
	if n := auditRowCount(t, a); n != 10 {
		t.Fatalf("with cap disabled, want all 10 rows retained, got %d", n)
	}
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestRetentionNeverPurgesUnshippedEvenUnderTinyCap is the sharpest evidence-
// preservation guard: when NOTHING has been shipped, an aggressively small cap
// must still delete nothing, because every row is undelivered evidence.
func TestRetentionNeverPurgesUnshippedEvenUnderTinyCap(t *testing.T) {
	origCap, origTail := MaxAuditBytes, keepShippedTailRows
	defer func() { MaxAuditBytes, keepShippedTailRows = origCap, origTail }()
	keepShippedTailRows = 0 // even with no tail reserved...
	MaxAuditBytes = 0

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer a.Close()

	for i := 0; i < 8; i++ {
		if err := a.Log("evt", strings.Repeat("z", 256)); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	// Never ship. Turn on a 1-byte cap and force the purge directly.
	MaxAuditBytes = 1
	if err := a.EnforceRetention(); err != nil {
		t.Fatalf("EnforceRetention: %v", err)
	}
	if n := auditRowCount(t, a); n != 8 {
		t.Fatalf("unshipped rows must never be purged: want 8, got %d", n)
	}
	if err := a.VerifyChain(); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}
