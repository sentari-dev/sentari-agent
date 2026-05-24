// Package audit provides an append-only local audit log backed by SQLite.
// Every agent action is recorded with a SHA-256 hash chain linking each
// entry to its predecessor.
//
// TRUST MODEL (read this before relying on these logs for security):
//
// The append-only SQLite triggers and the on-device hash chain are NOT a
// security boundary against the attacker this log exists to catch. A local
// root / Administrator can DROP the triggers and rewrite rows, and — because
// the chain is recomputable from the row contents with no secret involved —
// can also recompute every downstream hash to produce a chain that
// VerifyChain accepts. Adding an on-device HMAC would not help: the key would
// have to live on the same host the attacker already owns, so it is security
// theater, not defense.
//
// What the chain DOES give you:
//   - Tamper-EVIDENCE against unsophisticated/partial tampering (a row edited
//     without recomputing the chain, accidental corruption, truncation).
//     VerifyChain detects the first row whose stored hash no longer matches
//     its recomputed value.
//
// True tamper-EVIDENCE requires shipping entries off-host to the server for
// independent re-anchoring, so a host that is later compromised cannot
// silently rewrite history the server already witnessed. That re-anchoring
// endpoint is a documented follow-up (see UnshippedEntries / MarkShipped).
package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// AuditLog is the local append-only audit log.
type AuditLog struct {
	db       *sql.DB
	mu       sync.Mutex
	lastHash string
}

// auditDSN builds the modernc.org/sqlite connection string for the audit
// database.  WAL keeps reads from blocking the single writer, busy_timeout
// makes a writer wait (rather than immediately erroring SQLITE_BUSY) when the
// db is momentarily locked, and the caller pins SetMaxOpenConns(1) so writes
// are serialised within this process.
func auditDSN(dbPath string) string {
	return dbPath + "?_journal_mode=WAL&_pragma=busy_timeout(5000)"
}

// NewAuditLog opens or creates an audit log database at the given path.
func NewAuditLog(dbPath string) (*AuditLog, error) {
	db, err := sql.Open("sqlite", auditDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	// Serialise writers within this process: a single connection plus
	// busy_timeout(5000) means concurrent Log calls queue on the Go-side
	// connection pool instead of racing into SQLITE_BUSY.  The in-memory
	// lastHash mutex already serialises Log, but VerifyChain and any future
	// reader share this handle, so the cap keeps everyone consistent.
	db.SetMaxOpenConns(1)

	if err := initAuditSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init audit schema: %w", err)
	}

	// Restrict database file permissions to owner-only (0600).
	_ = os.Chmod(dbPath, 0600)

	// Load the last hash for chain continuity.
	var lastHash string
	row := db.QueryRow("SELECT content_hash FROM audit_log ORDER BY id DESC LIMIT 1")
	row.Scan(&lastHash) // Ignore error; empty on first use.

	a := &AuditLog{db: db, lastHash: lastHash}

	// Verify the chain on open so tampering/corruption is surfaced loudly.
	// A broken chain must NOT brick scanning — a tampered or corrupt audit
	// log is itself a finding the operator needs to see, not a reason to
	// stop collecting inventory.  Log prominently and continue.
	if verr := a.VerifyChain(); verr != nil {
		slog.Error("AUDIT LOG INTEGRITY CHECK FAILED — chain is broken or tampered; "+
			"new entries will still be appended but historical integrity is suspect",
			slog.String("db_path", dbPath),
			slog.String("err", verr.Error()))
	}

	return a, nil
}

func initAuditSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type   TEXT    NOT NULL,
			detail       TEXT    NOT NULL,
			content_hash TEXT    NOT NULL,
			prev_hash    TEXT    NOT NULL DEFAULT '',
			created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
			shipped      INTEGER NOT NULL DEFAULT 0
		);

		-- Append-only enforcement: prevent modification of audit entries.
		-- Only the "shipped" column may be updated (via MarkShipped).
		CREATE TRIGGER IF NOT EXISTS audit_no_update
		BEFORE UPDATE OF event_type, detail, content_hash, prev_hash, created_at ON audit_log
		BEGIN
			SELECT RAISE(ABORT, 'audit log is append-only: content columns cannot be modified');
		END;

		CREATE TRIGGER IF NOT EXISTS audit_no_delete
		BEFORE DELETE ON audit_log
		BEGIN
			SELECT RAISE(ABORT, 'audit log is append-only: rows cannot be deleted');
		END;
	`)
	return err
}

// Log appends an event to the audit log with hash chain integrity.
// A mutex serialises writes so that the in-memory lastHash stays consistent
// with what is persisted in SQLite.
func (a *AuditLog) Log(eventType, detail string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Compute hash: SHA-256(event_type + detail + prev_hash + timestamp).
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := eventType + detail + a.lastHash + now
	hash := sha256.Sum256([]byte(payload))
	hashHex := hex.EncodeToString(hash[:])

	_, err := a.db.Exec(
		"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		eventType, detail, hashHex, a.lastHash, now,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}

	a.lastHash = hashHex
	return nil
}

// VerifyChain recomputes the SHA-256 hash chain from genesis and returns an
// error identifying the first row whose stored hash or prev_hash does not
// match the recomputed value.  A clean (or empty) log returns nil.
//
// This detects partial tampering and corruption — NOT a sophisticated local
// attacker who recomputes the whole chain after editing a row (see the
// package doc TRUST MODEL).  It is the agent-side half of tamper-evidence;
// the authoritative half is server-side re-anchoring.
func (a *AuditLog) VerifyChain() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	rows, err := a.db.Query(
		"SELECT id, event_type, detail, content_hash, prev_hash, created_at FROM audit_log ORDER BY id ASC",
	)
	if err != nil {
		return fmt.Errorf("verify chain: query: %w", err)
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var id int
		var eventType, detail, contentHash, prevHashStored, createdAt string
		if err := rows.Scan(&id, &eventType, &detail, &contentHash, &prevHashStored, &createdAt); err != nil {
			return fmt.Errorf("verify chain: scan: %w", err)
		}

		// Each row's prev_hash must equal the previous row's content_hash.
		if prevHashStored != prevHash {
			return fmt.Errorf("verify chain: row %d: prev_hash mismatch (stored %q, expected %q)",
				id, prevHashStored, prevHash)
		}

		// Recompute the content hash exactly as Log did:
		// SHA-256(event_type + detail + prev_hash + created_at).
		payload := eventType + detail + prevHashStored + createdAt
		want := sha256.Sum256([]byte(payload))
		wantHex := hex.EncodeToString(want[:])
		if contentHash != wantHex {
			return fmt.Errorf("verify chain: row %d: content_hash mismatch (tampered or corrupt)", id)
		}

		prevHash = contentHash
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("verify chain: iterate: %w", err)
	}
	return nil
}

// UnshippedEntries returns audit log entries not yet sent to the server.
//
// TODO(server-contract): reserved for the (not-yet-implemented) server-side
// audit re-anchoring endpoint. Once the server exposes a re-anchoring API,
// the serve loop will ship these entries and call MarkShipped on success so a
// later host compromise cannot rewrite history the server already witnessed.
// This is intentionally retained (not dead code) — see the package TRUST
// MODEL doc for why off-host re-anchoring is the real tamper-evidence story.
func (a *AuditLog) UnshippedEntries() ([]map[string]string, error) {
	rows, err := a.db.Query(
		"SELECT id, event_type, detail, content_hash, prev_hash, created_at FROM audit_log WHERE shipped = 0 ORDER BY id ASC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]string
	for rows.Next() {
		var id int
		var eventType, detail, contentHash, prevHash, createdAt string
		if err := rows.Scan(&id, &eventType, &detail, &contentHash, &prevHash, &createdAt); err != nil {
			slog.Warn("audit: skipping corrupted entry", slog.String("err", err.Error()))
			continue
		}
		entries = append(entries, map[string]string{
			"id":           fmt.Sprintf("%d", id),
			"event_type":   eventType,
			"detail":       detail,
			"content_hash": contentHash,
			"prev_hash":    prevHash,
			"created_at":   createdAt,
		})
	}
	return entries, rows.Err()
}

// MarkShipped marks entries as sent to the server.
//
// TODO(server-contract): paired with UnshippedEntries — reserved for the
// not-yet-implemented server-side audit re-anchoring endpoint. The `shipped`
// column and the audit_no_update trigger's allowance for it exist for this
// future path; do not remove.
func (a *AuditLog) MarkShipped(maxID int) error {
	_, err := a.db.Exec("UPDATE audit_log SET shipped = 1 WHERE id <= ?", maxID)
	return err
}

// Close closes the audit log database.
func (a *AuditLog) Close() error {
	return a.db.Close()
}
