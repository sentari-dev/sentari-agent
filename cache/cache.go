// Package cache provides a local SQLite-based cache for scan results.
// When the server is unreachable, scans are queued locally and drained
// in chronological order on reconnection.
package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Cache wraps a SQLite database for local scan result storage.
type Cache struct {
	db *sql.DB
}

// NewCache opens or creates a SQLite cache at the given path.
func NewCache(dbPath string) (*Cache, error) {
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open cache db: %w", err)
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init cache schema: %w", err)
	}

	// Restrict database file permissions to owner-only (0600).
	// SQLite creates files with umask permissions which may be world-readable.
	_ = os.Chmod(dbPath, 0600)

	return &Cache{db: db}, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scan_queue (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_json  TEXT    NOT NULL,
			scanned_at TEXT    NOT NULL,
			uploaded   INTEGER NOT NULL DEFAULT 0,
			created_at TEXT    NOT NULL DEFAULT (datetime('now'))
		);
		CREATE INDEX IF NOT EXISTS idx_scan_queue_uploaded ON scan_queue(uploaded);
	`)
	return err
}

// EnqueueScan stores a scan result in the local cache for later upload.
func (c *Cache) EnqueueScan(result *scanner.ScanResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal scan result: %w", err)
	}

	_, err = c.db.Exec(
		"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
		string(data), result.ScannedAt.Format(time.RFC3339),
	)
	return err
}

// CachedScan pairs a queue row ID with the deserialized scan result.
// Callers must pass QueueID to MarkUploaded after a successful upload.
type CachedScan struct {
	QueueID int64
	Result  *scanner.ScanResult
}

// DequeuePending returns all scan results that have not yet been uploaded,
// ordered by scan time (oldest first) for chronological drain.
func (c *Cache) DequeuePending() ([]CachedScan, error) {
	rows, err := c.db.Query(
		"SELECT id, scan_json FROM scan_queue WHERE uploaded = 0 ORDER BY scanned_at ASC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []CachedScan
	for rows.Next() {
		var id int64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		var result scanner.ScanResult
		if err := json.Unmarshal([]byte(data), &result); err != nil {
			log.Printf("cache: skipping corrupted entry id=%d: %v", id, err)
			continue
		}
		results = append(results, CachedScan{QueueID: id, Result: &result})
	}
	return results, rows.Err()
}

// MarkUploaded marks a cached scan as successfully uploaded to the server.
func (c *Cache) MarkUploaded(queueID int64) error {
	_, err := c.db.Exec("UPDATE scan_queue SET uploaded = 1 WHERE id = ?", queueID)
	return err
}

// PendingCount returns the number of scans waiting to be uploaded.
func (c *Cache) PendingCount() (int, error) {
	var count int
	err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE uploaded = 0").Scan(&count)
	return count, err
}

// PurgeUploaded deletes uploaded entries older than the given duration to
// prevent unbounded disk growth of the local SQLite cache.
func (c *Cache) PurgeUploaded(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UTC().Format("2006-01-02 15:04:05")
	res, err := c.db.Exec(
		"DELETE FROM scan_queue WHERE uploaded = 1 AND created_at < ?",
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("purge uploaded: %w", err)
	}
	return res.RowsAffected()
}

// Close closes the cache database.
func (c *Cache) Close() error {
	return c.db.Close()
}
