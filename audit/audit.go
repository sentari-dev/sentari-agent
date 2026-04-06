// Package audit provides an append-only local audit log backed by SQLite.
// Every agent action is recorded and periodically shipped to the server.
package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
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

// NewAuditLog opens or creates an audit log database at the given path.
func NewAuditLog(dbPath string) (*AuditLog, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

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

	return &AuditLog{db: db, lastHash: lastHash}, nil
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

// UnshippedEntries returns audit log entries not yet sent to the server.
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
			log.Printf("audit: skipping corrupted entry: %v", err)
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
func (a *AuditLog) MarkShipped(maxID int) error {
	_, err := a.db.Exec("UPDATE audit_log SET shipped = 1 WHERE id <= ?", maxID)
	return err
}

// Close closes the audit log database.
func (a *AuditLog) Close() error {
	return a.db.Close()
}
