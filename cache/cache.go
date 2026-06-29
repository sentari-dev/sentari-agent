// Package cache provides a local SQLite-based cache for scan results.
// When the server is unreachable, scans are queued locally and drained
// in chronological order on reconnection.
package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// maxPendingScans caps the number of not-yet-uploaded scan rows the cache
// will retain.  A durably-offline agent (air-gap, or a server outage longer
// than the operator expected) would otherwise accumulate pending rows on
// every scan cycle forever, eventually filling the disk.  When the cap is
// exceeded EnqueueScan evicts the OLDEST pending rows (chronological drain
// order means the oldest inventory snapshot is the least valuable to keep)
// and logs a warning so the eviction is visible to operators.
//
// 500 hourly scans is ~3 weeks of continuous offline operation — far past the
// 1-day default offline window, though short of the 365-day air-gap license
// tier (a durably air-gapped fleet relies on the eviction-of-oldest behaviour
// above rather than unbounded retention).  Keeping the cap here keeps the
// SQLite file small (a few MiB).  Declared as a var, not a const, so tests can
// shrink it.
var maxPendingScans = 500

// Cache wraps a SQLite database for local scan result storage.
type Cache struct {
	db *sql.DB
}

// cacheDSN builds the modernc.org/sqlite connection string for the cache
// database.  busy_timeout makes a writer wait (rather than immediately
// erroring SQLITE_BUSY) when the db is momentarily locked, and the caller
// pins SetMaxOpenConns(1) so writes are serialised within this process.
//
// NOTE: modernc.org/sqlite does NOT honour a `_journal_mode=WAL` DSN
// parameter — it is silently ignored.  WAL keeps reads from blocking the
// single writer, so it is applied via `PRAGMA journal_mode=WAL` in
// applyWAL after the connection is opened, and verified to have taken
// effect.
func cacheDSN(dbPath string) string {
	return dbPath + "?_pragma=busy_timeout(5000)"
}

// applyWAL sets and verifies WAL journal mode.  PRAGMA journal_mode returns
// the resulting mode, so we assert it actually switched to "wal" instead of
// trusting the DSN (which modernc.org/sqlite ignores for journal_mode).
func applyWAL(db *sql.DB) error {
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return fmt.Errorf("set WAL journal mode: %w", err)
	}
	if strings.ToLower(mode) != "wal" {
		return fmt.Errorf("WAL journal mode not applied: got %q", mode)
	}
	return nil
}

// NewCache opens or creates a SQLite cache at the given path.
func NewCache(dbPath string) (*Cache, error) {
	db, err := sql.Open("sqlite", cacheDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open cache db: %w", err)
	}

	// Serialise writers within this process: a single connection plus
	// busy_timeout(5000) means concurrent EnqueueScan calls queue on the
	// Go-side connection pool instead of racing into SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	// WAL must be applied via PRAGMA — the DSN parameter is ignored by
	// modernc.org/sqlite.  Apply before schema init so the very first
	// writes land in WAL mode.
	if err := applyWAL(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL on cache db: %w", err)
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
	if err != nil {
		return err
	}

	// Bound the pending backlog so a durably-offline agent cannot fill the
	// disk.  Evict the oldest pending rows beyond the cap.
	return c.evictExcessPending()
}

// evictExcessPending deletes the oldest pending (uploaded = 0) rows so that
// at most maxPendingScans pending rows remain.  Already-uploaded rows are
// left to PurgeUploaded.  A no-op when under the cap.
func (c *Cache) evictExcessPending() error {
	var pending int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE uploaded = 0").Scan(&pending); err != nil {
		return fmt.Errorf("count pending for eviction: %w", err)
	}
	if pending <= maxPendingScans {
		return nil
	}

	excess := pending - maxPendingScans
	// Delete the `excess` oldest pending rows.  ORDER BY scanned_at, id keeps
	// eviction deterministic even when several rows share a scanned_at.
	res, err := c.db.Exec(
		`DELETE FROM scan_queue WHERE id IN (
			SELECT id FROM scan_queue WHERE uploaded = 0
			ORDER BY scanned_at ASC, id ASC LIMIT ?
		)`,
		excess,
	)
	if err != nil {
		return fmt.Errorf("evict oldest pending: %w", err)
	}
	evicted, _ := res.RowsAffected()
	if evicted > 0 {
		slog.Warn("cache: evicted oldest pending scans (backlog cap reached) — "+
			"server appears durably unreachable; oldest inventory snapshots dropped",
			slog.Int64("evicted", evicted),
			slog.Int("cap", maxPendingScans))
	}
	return nil
}

// CachedScan pairs a queue row ID with the deserialized scan result.
// Callers must pass QueueID to MarkUploaded after a successful upload.
type CachedScan struct {
	QueueID int64
	Result  *scanner.ScanResult
}

// defaultDequeueBatch bounds how many pending rows DequeuePending pulls into
// memory in one call.  Without a bound, a durably-offline agent with a large
// backlog would materialise the ENTIRE queue at once and risk OOM.  The drain
// loop processes a batch, marks each row uploaded, and re-enters on the next
// scan cycle, so a smaller batch only means more drain iterations — never
// dropped or duplicated rows.  Sized below maxPendingScans so a full backlog
// drains over a handful of cycles.
const defaultDequeueBatch = 100

// DequeuePending returns up to defaultDequeueBatch scan results that have not
// yet been uploaded, ordered by scan time (oldest first) for chronological
// drain.  It is a bounded convenience wrapper over DequeuePendingBatch so the
// legacy call site cannot OOM on a large offline backlog.
func (c *Cache) DequeuePending() ([]CachedScan, error) {
	return c.DequeuePendingBatch(defaultDequeueBatch)
}

// DequeuePendingBatch returns at most maxRows scan results that have not yet
// been uploaded, ordered by scan time (oldest first) for FIFO chronological
// drain.  A non-positive maxRows dequeues the entire pending backlog
// (unbounded) — use with care.  Rows are not removed; callers must call
// MarkUploaded after a successful upload.
func (c *Cache) DequeuePendingBatch(maxRows int) ([]CachedScan, error) {
	query := "SELECT id, scan_json FROM scan_queue WHERE uploaded = 0 ORDER BY scanned_at ASC, id ASC"
	var args []any
	if maxRows > 0 {
		query += " LIMIT ?"
		args = append(args, maxRows)
	}

	rows, err := c.db.Query(query, args...)
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
			slog.Warn("cache: skipping corrupted entry",
				slog.Int64("id", id),
				slog.String("err", err.Error()))
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
