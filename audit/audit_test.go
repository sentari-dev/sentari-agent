package audit

import (
	"database/sql"
	"path/filepath"
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
