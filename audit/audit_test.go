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
