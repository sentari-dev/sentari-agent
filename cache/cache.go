// Package cache provides a local SQLite-based cache for scan results.
// When the server is unreachable, scans are queued locally and drained
// in chronological order on reconnection.
package cache

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/common/dbhealth"
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
// above rather than unbounded retention).  A fleet's scan payloads vary from a
// few KiB to tens of MiB, so the on-disk footprint scales with payload size,
// not just row count; the byte budget in DequeuePendingBatch caps how much of
// that lands in memory per drain.  Declared as a var, not a const, so tests
// can shrink it and operators can raise it via `[cache] max_pending_scans`
// (see config.CacheConfig / SetMaxPendingScans).
var maxPendingScans = DefaultMaxPendingScans

// DefaultMaxPendingScans is the built-in cap on retained not-yet-uploaded scan
// rows, used when the operator does not override it via `[cache]
// max_pending_scans`.  Exported so config.DefaultConfig can seed the same value
// without duplicating the literal.
const DefaultMaxPendingScans = 500

// SetMaxPendingScans overrides the retained-pending-rows cap from operator
// configuration (`[cache] max_pending_scans`).  A negative value is ignored
// (the caller/config layer rejects it before reaching here); 0 is honoured and
// means "retain no backlog" — every enqueue immediately evicts older pending
// rows.  Call once at startup before the first EnqueueScan.
func SetMaxPendingScans(n int) {
	if n < 0 {
		return
	}
	maxPendingScans = n
}

// maxPendingBytes caps the cumulative scan_json BYTES the persistent offline
// queue retains, independent of the row count cap (maxPendingScans).  Row count
// alone is a poor proxy for on-disk footprint: a fleet's scan payloads range
// from a few KiB to tens of MiB, so a device queuing many LARGE scans during a
// long air-gap outage can grow the cache DB to gigabytes while still under the
// 500-row cap.  evictExcessPending evicts oldest-enqueued pending rows until
// BOTH the row count AND the total pending bytes are under their caps.
//
// Distinct from maxDequeueBytes: that bounds a SINGLE DequeuePendingBatch
// (how much lands in memory per drain); this bounds the STORED queue's on-disk
// size across cycles.  Declared as a var, not a const, so tests can shrink it
// and operators can raise it via `[cache] max_pending_bytes`
// (see config.CacheConfig / SetMaxPendingBytes).
var maxPendingBytes = DefaultMaxPendingBytes

// DefaultMaxPendingBytes is the built-in cap on retained pending scan_json
// bytes (512 MiB), used when the operator does not override it via `[cache]
// max_pending_bytes`.  It is deliberately generous: it is a safety CEILING on
// pathological large-payload fleets, not a routine limit — a typical few-KiB
// payload at the 500-row default occupies only a few MiB, far under this cap,
// so the row cap governs in the common case and the byte cap only bites when
// individual scans are unusually large.  Exported so config.DefaultConfig can
// seed the same value without duplicating the literal.
const DefaultMaxPendingBytes = 512 << 20 // 512 MiB

// SetMaxPendingBytes overrides the retained-pending-BYTES cap from operator
// configuration (`[cache] max_pending_bytes`).  A negative value is ignored
// (the caller/config layer rejects it before reaching here); 0 is honoured and
// means "retain at most the single freshest pending scan" — evictExcessPending
// always keeps at least the just-enqueued row on byte grounds, mirroring
// DequeuePendingBatch, so a scan larger than the cap can still drain rather
// than being discarded the instant it is written.  Call once at startup before
// the first EnqueueScan.
func SetMaxPendingBytes(n int) {
	if n < 0 {
		return
	}
	maxPendingBytes = n
}

// maxDequeueBytes caps the cumulative scan_json bytes a single
// DequeuePendingBatch pulls into memory (64 MiB).  Row count alone is a poor
// proxy for memory: 100 large scans can be hundreds of MiB.  DequeuePendingBatch
// always returns at least one row even if it exceeds the budget, so a single
// oversized scan can still drain over successive cycles.  Declared as a var,
// not a const, so tests can shrink it.
var maxDequeueBytes = 64 << 20 // 64 MiB

// Cache wraps a SQLite database for local scan result storage.
type Cache struct {
	db *sql.DB
	// dbPath is retained so Reopen can re-run OpenResilient against the same
	// file when a corruption is discovered LAZILY at read time (see Reopen).
	dbPath string
	// needsReopen is set when Reopen closed the old handle but could NOT swap a
	// fresh one in (a TRANSIENT OpenResilient failure — ENOSPC on a near-full
	// air-gap disk, EACCES, a locked file — or a post-quarantine open that
	// failed transiently).  The handle is then closed and every cache op errors
	// until a later Reopen succeeds.  The cycle-start health hook
	// (ensureCacheOpen in cmd/sentari-agent/serve_loop.go) checks NeedsReopen and
	// retries OpenResilient once the condition clears, so the daemon self-heals
	// IN-PROCESS without a restart instead of wedging on a dead handle for the
	// rest of a (possibly months-long) air-gap window (findings offline-1/2).
	// Written only from Reopen; the serve loop that reads it is single-threaded.
	needsReopen bool
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
// effect.  `_txlock=immediate` IS honoured by modernc and stays in the DSN.
//
// _txlock=immediate makes every BeginTx start with BEGIN IMMEDIATE, taking the
// database write lock at transaction start instead of lazily on first write.
// This is the load-bearing cross-PROCESS serialisation for the read-modify-write
// eviction (evictExcessPending): SetMaxOpenConns(1) only serialises writers
// WITHIN one process, but two agent processes sharing this cache DB could
// otherwise interleave the count/range/delete and evict the wrong rows or
// miscount.  With BEGIN IMMEDIATE the second process blocks (up to busy_timeout)
// on the write lock until the first commits, then re-reads the committed pending
// count — so the eviction sequence is atomic across processes.  This mirrors the
// audit DB's own _txlock=immediate threat model.
func cacheDSN(dbPath string) string {
	return dbPath + "?_txlock=immediate&_pragma=busy_timeout(5000)"
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

	return &Cache{db: db, dbPath: dbPath}, nil
}

// OpenResilient opens the cache at dbPath, recovering from a corrupt on-disk
// database file rather than bricking the daemon.  If NewCache fails because the
// file is CORRUPTION-class (truncated, not a SQLite database, or a damaged
// header — surfaced as SQLITE_CORRUPT/SQLITE_NOTADB via dbhealth.IsCorruption),
// the offending file — plus its WAL/SHM sidecars — is renamed aside to
// "<dbPath>.corrupt-<unix-ts>" to preserve it for forensic inspection, and
// NewCache is retried once against a fresh file.
//
// A TRANSIENT open failure (disk full during applyWAL/initSchema, permission
// denied, a locked file — anything that is NOT a corruption result code) is NOT
// recovered from: the original error is returned unchanged so the daemon exits
// and retries later with the pending offline queue intact.  Quarantining a
// healthy database on a transient error would orphan weeks of un-drained scans
// the first time the disk momentarily fills.
//
// Returns the opened cache; recovered=true when a quarantine+recreate
// happened; quarantinedPath naming the preserved corrupt file (empty when no
// recovery occurred); and an error only when the failure was transient, the
// fresh open fails, or the corrupt file could not be moved aside.  Callers
// should surface a loud log + audit entry when recovered is true — an emptied
// queue means any un-drained offline scans in the corrupt file are gone.
func OpenResilient(dbPath string) (c *Cache, recovered bool, quarantinedPath string, err error) {
	c, err = NewCache(dbPath)
	if err == nil {
		return c, false, "", nil
	}
	firstErr := err

	// Only a corruption-class failure justifies destroying the on-disk queue.
	// A transient error (ENOSPC, EACCES, locked) leaves a perfectly good queue
	// behind — return it so the daemon exits and retries with the backlog kept.
	if !dbhealth.IsCorruption(firstErr) {
		return nil, false, "", fmt.Errorf("open cache db (transient, not quarantining): %w", firstErr)
	}

	quarantinedPath = fmt.Sprintf("%s.corrupt-%d", dbPath, time.Now().Unix())
	if renameErr := os.Rename(dbPath, quarantinedPath); renameErr != nil {
		// The file could not be moved aside (e.g. it does not exist, so the
		// open failure is not a corruption we can recover from).  Surface the
		// original open error — there is no safe recovery path.
		return nil, false, "", fmt.Errorf("open cache db (%w); could not quarantine to %s: %v",
			firstErr, quarantinedPath, renameErr)
	}
	// Move the WAL/SHM sidecars alongside so the fresh db starts clean and the
	// quarantined snapshot is self-contained.  Best-effort — they may not exist.
	_ = os.Rename(dbPath+"-wal", quarantinedPath+"-wal")
	_ = os.Rename(dbPath+"-shm", quarantinedPath+"-shm")

	// Bound the quarantine set: a device with a failing disk can corrupt its
	// cache on every boot, and each recovery leaves another "<dbPath>.corrupt-*"
	// copy behind.  Unbounded, those sets fill the disk — the very failure the
	// backlog cap and PurgeUploaded exist to prevent.  Keep the most recent few
	// for forensics, prune older ones (with their sidecars).  Best-effort: a
	// prune failure must NOT abort the corruption recovery it is cleaning up
	// after, so it is only logged.
	if pruneErr := pruneCorruptQuarantines(dbPath, quarantinedPath, keepCorruptQuarantines); pruneErr != nil {
		slog.Warn("cache: failed to prune old corrupt quarantine files",
			slog.String("err", pruneErr.Error()))
	}

	c, err = NewCache(dbPath)
	if err != nil {
		return nil, false, quarantinedPath, fmt.Errorf("reopen cache db after quarantine of %s: %w",
			quarantinedPath, err)
	}
	return c, true, quarantinedPath, nil
}

// keepCorruptQuarantines bounds how many "<dbPath>.corrupt-<ts>" quarantine sets
// OpenResilient retains for forensics.  Three is enough to inspect a recurring-
// corruption pattern (e.g. a failing disk) while staying bounded.  Mirrors
// maxFallbackFiles in cmd/sentari-agent/upload_drain.go.
const keepCorruptQuarantines = 3

// pruneCorruptQuarantines deletes the oldest "<dbPath>.corrupt-<ts>" quarantine
// sets — each a base file plus its optional -wal/-shm sidecars — so that at most
// `keep` of the most RECENT sets remain.  It globs ONLY this db's corrupt-*
// siblings (never the live cache.db or its -wal/-shm), orders them newest-first
// by the embedded unix-second timestamp (falling back to mtime, then lexical
// name, when the suffix will not parse), and NEVER removes keepPath — the
// just-created quarantine — even if a clock anomaly sorted it out of the newest
// `keep`.  Best-effort: returns the first delete error for the caller to log but
// is otherwise non-fatal.
func pruneCorruptQuarantines(dbPath, keepPath string, keep int) error {
	prefix := dbPath + ".corrupt-"
	matches, err := filepath.Glob(prefix + "*")
	if err != nil {
		return err
	}
	if keep < 0 {
		keep = 0
	}
	// Count only the base quarantine files as "sets"; the -wal/-shm sidecars are
	// deleted alongside their base, not retained or counted independently.
	var sets []string
	for _, m := range matches {
		if strings.HasSuffix(m, "-wal") || strings.HasSuffix(m, "-shm") {
			continue
		}
		sets = append(sets, m)
	}
	if len(sets) <= keep {
		return nil
	}

	ts := func(p string) (int64, bool) {
		n, perr := strconv.ParseInt(strings.TrimPrefix(p, prefix), 10, 64)
		return n, perr == nil
	}
	sort.Slice(sets, func(i, j int) bool {
		ti, oki := ts(sets[i])
		tj, okj := ts(sets[j])
		if oki && okj {
			return ti > tj // newest timestamp first
		}
		fi, ei := os.Stat(sets[i])
		fj, ej := os.Stat(sets[j])
		if ei == nil && ej == nil {
			return fi.ModTime().After(fj.ModTime())
		}
		return sets[i] > sets[j]
	})

	var firstErr error
	for i, base := range sets {
		if i < keep {
			continue // retained: the newest `keep` sets (includes the just-created one)
		}
		if base == keepPath {
			continue // safety net: never delete the just-created quarantine
		}
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if rmErr := os.Remove(p); rmErr != nil && !os.IsNotExist(rmErr) && firstErr == nil {
				firstErr = rmErr
			}
		}
	}
	return firstErr
}

// Reopen closes the current handle and re-opens the cache at the same path via
// OpenResilient, swapping the fresh *sql.DB in place so a caller holding this
// *Cache keeps using it transparently after a recovery.
//
// It exists for the drain path (cmd/sentari-agent/upload_drain.go).  SQLite
// detects data-page corruption LAZILY — only on the first read that touches the
// damaged page — so a torn write in scan_queue surfaces as SQLITE_CORRUPT on
// DequeuePending/PendingCount at DRAIN time, long after NewCache opened the file
// cleanly.  OpenResilient only quarantines corruption seen at OPEN time; without
// a re-open hook a lazily-discovered corruption would error on every drain cycle
// forever with no recovery.  On such an error the caller tests
// dbhealth.IsCorruption and, when true, calls Reopen to run the SAME
// quarantine-and-recreate recovery the startup path uses.
//
// Returns recovered=true when the on-disk file was corruption-class and was
// quarantined + recreated (quarantinedPath naming the preserved file).
//
// Reopen is SELF-HEALING and NON-wedging: it never leaves the cache permanently
// unusable on a transient failure.  It must close the old handle first so
// OpenResilient can rename a corrupt file aside (SQLite cannot swap a file out
// from under an open handle portably), so on a FAILED reopen the old handle is
// gone — but rather than stranding the daemon on a dead handle for the rest of a
// possibly months-long air-gap window, it flags the Cache needsReopen (see
// NeedsReopen).  The cycle-start health hook then retries OpenResilient every
// cycle until the transient condition (ENOSPC on a near-full disk, EACCES, a
// lock) clears, at which point the SAME healthy on-disk file re-opens with the
// pending backlog INTACT — no process restart, no silent scan loss (findings
// offline-1/2).
//
// Returns an error when the failure was transient (ENOSPC/EACCES/lock) or the
// post-quarantine fresh open failed; in both cases needsReopen is set so the
// next cycle retries.  This *Cache must not be used until a subsequent Reopen
// clears the flag, but it is NOT permanently dead.
func (c *Cache) Reopen() (recovered bool, quarantinedPath string, err error) {
	// Close the (possibly corrupt) handle first so OpenResilient can rename the
	// file aside; a Close error is irrelevant here — the file is being replaced.
	// (Idempotent: harmless when the handle is already closed from a prior failed
	// reopen, i.e. this is a needsReopen retry.)
	_ = c.db.Close()

	fresh, recovered, quarantinedPath, err := OpenResilient(c.dbPath)
	if err != nil {
		// The old handle is closed and no fresh handle could be swapped in.
		// Flag the cache so the cycle-start health hook retries OpenResilient
		// once the transient condition clears — WITHOUT a process restart.
		// Leaving this unset would wedge the daemon on a dead handle and lose
		// every subsequent scan for the rest of the offline window.
		c.needsReopen = true
		return recovered, quarantinedPath, err
	}
	// Adopt the fresh connection in place.  fresh.dbPath == c.dbPath already, so
	// only the handle needs swapping.
	c.db = fresh.db
	c.needsReopen = false
	return recovered, quarantinedPath, nil
}

// NeedsReopen reports whether a prior Reopen closed the old handle but could not
// swap a fresh one in (a transient OpenResilient failure), leaving the cache
// handle closed.  The cycle-start health hook (ensureCacheOpen) uses it to decide
// whether to attempt an in-process re-open before the drain, so the daemon
// recovers on its own once the fault (e.g. a full disk) clears (findings
// offline-1/2).  Read only from the single-threaded serve loop.
func (c *Cache) NeedsReopen() bool { return c.needsReopen }

// The scan_queue.uploaded column is a tri-state, reusing the single INTEGER
// column so no migration is needed:
//
//	0 = pending  — not yet uploaded; drained oldest-first.
//	1 = uploaded — accepted by the server; retained briefly for forensics,
//	               then reaped by PurgeUploaded.
//	2 = dead     — permanently un-uploadable: either the server rejected the
//	               payload with a non-retryable 4xx (MarkFailedPermanent) or
//	               the blob is corrupt/undecodable (quarantined in
//	               DequeuePendingBatch).  Skipped by every pending query and
//	               reaped alongside uploaded rows by PurgeUploaded so a poison
//	               row can never head-of-line-block the drain forever.
//
// The uploaded_at column records the wall-clock moment a row LEFT the pending
// set (set by MarkUploaded / markDead / MarkFailedPermanent — the tri-state
// transitions to 1 or 2).  PurgeUploaded measures its forensic-retention
// window from uploaded_at, NOT created_at (scan time): after a long air-gap
// outage the catch-up drain uploads scans whose created_at is days old, and
// keying the purge on created_at would reap them the instant they were
// delivered — collapsing the retention window to zero exactly when the audit
// trail matters most.  Keying on uploaded_at measures time-since-delivery.
// Pending rows (uploaded = 0) leave uploaded_at NULL; NULL never satisfies the
// `uploaded_at < cutoff` comparison, so an offline backlog is preserved
// regardless of age (belt-and-suspenders with the `uploaded IN (1,2)` filter).
func initSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scan_queue (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_json   TEXT    NOT NULL,
			scanned_at  TEXT    NOT NULL,
			uploaded    INTEGER NOT NULL DEFAULT 0,
			created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
			uploaded_at TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_scan_queue_uploaded ON scan_queue(uploaded);
	`); err != nil {
		return err
	}
	return ensureUploadedAtColumn(db)
}

// ensureUploadedAtColumn adds the uploaded_at column to a scan_queue created
// before the forensic-retention window keyed on delivery time (rather than
// scan time) existed.  Fresh databases already have the column from initSchema's
// CREATE TABLE; this ALTER is the in-place migration for caches already on disk.
// It is guarded by a PRAGMA table_info probe so it runs at most once and is a
// no-op on up-to-date schemas — mirroring audit.ensureHashVersionColumn.
//
// After adding the column, pre-existing terminal rows (uploaded IN (1,2)) get
// uploaded_at backfilled to their created_at.  Backfilling to created_at is the
// safe default: it preserves the OLD (scan-time) retention semantics for rows
// that were already delivered before the upgrade — the same rows would have
// been purged on their created_at under the previous code — so the migration
// changes nothing for legacy rows while making the delivery-time window take
// effect for every row drained after it.  The alternatives were both worse:
// leaving them NULL would retain them forever (unbounded disk growth, defeating
// PurgeUploaded's purpose), and treating NULL as immediately purge-eligible
// would delete an operator's existing forensic trail the moment they upgraded.
func ensureUploadedAtColumn(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(scan_queue)")
	if err != nil {
		return fmt.Errorf("inspect scan_queue schema: %w", err)
	}
	present := false
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan scan_queue schema: %w", err)
		}
		if name == "uploaded_at" {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate scan_queue schema: %w", err)
	}
	// Close before issuing the ALTER: the pool is pinned to a single
	// connection (SetMaxOpenConns(1)), so an Exec while these rows are still
	// open would contend with itself.
	rows.Close()
	if present {
		return nil
	}
	if _, err := db.Exec("ALTER TABLE scan_queue ADD COLUMN uploaded_at TEXT"); err != nil {
		return fmt.Errorf("add uploaded_at column: %w", err)
	}
	if _, err := db.Exec(
		"UPDATE scan_queue SET uploaded_at = created_at WHERE uploaded IN (1, 2) AND uploaded_at IS NULL",
	); err != nil {
		return fmt.Errorf("backfill uploaded_at: %w", err)
	}
	return nil
}

// EvictionResult reports a backlog-cap eviction: how many oldest pending rows
// were dropped and the scanned_at range they spanned.  EnqueueScan surfaces it
// so the caller can write a tamper-evident `cache.evicted` audit entry — silent
// inventory loss must leave a trace in the audit record (this is a compliance
// product, and every other queue event is already audited).  Count == 0 means
// nothing was evicted.
type EvictionResult struct {
	Count           int
	OldestScannedAt string
	NewestScannedAt string
	// Reason names which cap(s) forced the eviction: "rows" (row-count cap),
	// "bytes" (cumulative-byte cap), or "rows,bytes" when both were exceeded.
	// Empty when Count == 0.  The caller may fold it into the `cache.evicted`
	// audit detail so the record distinguishes a row-cap drop from a byte-cap
	// drop; it is also surfaced in the operator warning log.
	Reason string
}

// EnqueueScan stores a scan result in the local cache for later upload.  It
// returns an EvictionResult describing any oldest-pending rows dropped to keep
// the backlog under the cap (Count == 0 when nothing was evicted) so the caller
// can audit the loss.
func (c *Cache) EnqueueScan(result *scanner.ScanResult) (EvictionResult, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return EvictionResult{}, fmt.Errorf("marshal scan result: %w", err)
	}

	_, err = c.db.Exec(
		"INSERT INTO scan_queue (scan_json, scanned_at) VALUES (?, ?)",
		string(data), result.ScannedAt.Format(time.RFC3339),
	)
	if err != nil {
		// The INSERT is the durability point and it failed BEFORE commit — the
		// scan is NOT queued.  Report the failure so the caller's last-resort
		// fallback path fires and the data is not silently lost.
		return EvictionResult{}, err
	}

	// The scan is now durably queued (the INSERT above autocommitted).  The
	// enqueue contract — "is the scan durably queued?" — is already satisfied.
	// Backlog-cap eviction is best-effort cap maintenance layered on top: it
	// opens its OWN write transaction, so a transient failure there (a
	// cross-process SQLITE_BUSY past the busy_timeout, or a hiccup on the
	// eviction commit) must NOT be reported as an enqueue failure.  If it were,
	// the caller would treat the already-queued scan as lost and write it to a
	// fallback file plus a `cache.fallback` audit entry — producing a duplicate
	// scan and a tamper-evident record asserting a failure that never happened.
	// Log the eviction error and return success; the cap is re-enforced on the
	// next EnqueueScan regardless.
	ev, evictErr := c.evictExcessPending()
	if evictErr != nil {
		slog.Warn("cache backlog eviction failed; scan is queued, cap re-enforced next enqueue",
			slog.String("err", evictErr.Error()))
		return EvictionResult{}, nil
	}
	return ev, nil
}

// evictExcessPending deletes the oldest pending (uploaded = 0) rows so that
// BOTH caps hold: at most maxPendingScans pending rows AND at most
// maxPendingBytes of cumulative scan_json remain.  Already-uploaded rows are
// left to PurgeUploaded.  A no-op (zero-valued EvictionResult) when both caps
// are satisfied.  Returns the count, scanned_at range, and the reason (which
// cap fired) so the caller can record exactly which inventory snapshots were
// lost and why.
//
// The count / range / delete run inside a single BEGIN IMMEDIATE transaction
// (see cacheDSN's _txlock=immediate).  This makes the read-modify-write atomic
// across PROCESSES, not just goroutines: without it, two agent processes
// sharing the cache DB could interleave the count and the delete and either
// evict the wrong rows or miscount (SetMaxOpenConns(1) only serialises writers
// within one process).  Taking the write lock up front means a second process
// blocks until the first commits, then re-reads the committed pending count.
func (c *Cache) evictExcessPending() (EvictionResult, error) {
	tx, err := c.db.Begin()
	if err != nil {
		return EvictionResult{}, fmt.Errorf("begin eviction tx: %w", err)
	}
	defer tx.Rollback() // no-op after a successful Commit.

	// Read the pending row count AND the cumulative on-disk byte size in one
	// pass.  length(CAST(scan_json AS BLOB)) counts BYTES (SQLite's length() on
	// a TEXT value counts CHARACTERS, which under-counts multibyte UTF-8 in
	// package names/paths); the CAST makes the budget a true byte budget.
	var pending int
	var totalBytes int64
	if err := tx.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(length(CAST(scan_json AS BLOB))), 0)
		 FROM scan_queue WHERE uploaded = 0`,
	).Scan(&pending, &totalBytes); err != nil {
		return EvictionResult{}, fmt.Errorf("count pending for eviction: %w", err)
	}

	overRows := pending > maxPendingScans
	overBytes := totalBytes > int64(maxPendingBytes)
	if !overRows && !overBytes {
		// Nothing to evict — commit the (empty) read txn to release the write
		// lock promptly rather than leaning on the deferred Rollback.
		if err := tx.Commit(); err != nil {
			return EvictionResult{}, fmt.Errorf("commit eviction tx: %w", err)
		}
		return EvictionResult{}, nil
	}

	// Row-cap excess: how many oldest rows must go to satisfy maxPendingScans.
	rowExcess := 0
	if overRows {
		rowExcess = pending - maxPendingScans
	}

	// Byte-cap excess: how many OLDEST rows must go so the remaining pending
	// bytes fall under maxPendingBytes.  Computed by walking rows NEWEST-first
	// (id DESC) and keeping the newest suffix that fits the budget; everything
	// older is excess.  At least one row is always retained on byte grounds —
	// the freshest just-enqueued snapshot — even if it alone exceeds the budget
	// (mirrors DequeuePendingBatch, which always yields one row over budget), so
	// an oversized scan drains over later cycles instead of being discarded the
	// instant it is written.
	byteExcess := 0
	if overBytes {
		rows, err := tx.Query(
			`SELECT length(CAST(scan_json AS BLOB)) FROM scan_queue
			 WHERE uploaded = 0 ORDER BY id DESC`,
		)
		if err != nil {
			return EvictionResult{}, fmt.Errorf("size pending for eviction: %w", err)
		}
		kept := 0
		var keptBytes int64
		for rows.Next() {
			var n int64
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return EvictionResult{}, fmt.Errorf("scan pending size: %w", err)
			}
			// Always keep the first (newest) row; for the rest, stop once adding
			// this older row would cross the budget — it and everything older
			// than it are excess.
			if kept > 0 && keptBytes+n > int64(maxPendingBytes) {
				break
			}
			keptBytes += n
			kept++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return EvictionResult{}, fmt.Errorf("iterate pending sizes: %w", err)
		}
		rows.Close()
		byteExcess = pending - kept
		if byteExcess < 0 {
			byteExcess = 0
		}
	}

	// Evict enough oldest rows to satisfy whichever cap demands more.
	excess := rowExcess
	if byteExcess > excess {
		excess = byteExcess
	}
	if excess <= 0 {
		if err := tx.Commit(); err != nil {
			return EvictionResult{}, fmt.Errorf("commit eviction tx: %w", err)
		}
		return EvictionResult{}, nil
	}

	// Capture the scanned_at range of the rows about to be evicted (same
	// ordering as the DELETE below, so it names the very rows removed) — cheap
	// (one aggregate over the LIMIT-bounded set) and it makes the audit entry
	// forensically useful ("which snapshots were dropped").  scanned_at is used
	// ONLY for this human-facing range report; the row SELECTION orders by id
	// (see the DELETE ordering rationale below), so MIN/MAX here just describes
	// the wall-clock span of whichever oldest-enqueued rows were dropped.
	var oldest, newest sql.NullString
	if err := tx.QueryRow(
		`SELECT MIN(scanned_at), MAX(scanned_at) FROM (
			SELECT scanned_at FROM scan_queue WHERE uploaded = 0
			ORDER BY id ASC LIMIT ?
		)`,
		excess,
	).Scan(&oldest, &newest); err != nil {
		return EvictionResult{}, fmt.Errorf("range pending for eviction: %w", err)
	}

	// Delete the `excess` oldest-ENQUEUED pending rows.  Ordering is by id
	// (AUTOINCREMENT, strictly monotonic = true enqueue order) rather than by the
	// wall-clock scanned_at: scanned_at is set from time.Now at scan and a
	// backward clock correction (NTP resync after a long air-gap outage, or a VM
	// snapshot restore — realistic on NATO/gov hosts) makes it NON-monotonic.
	// Ordering eviction by scanned_at would then drop the FRESHEST inventory
	// instead of the oldest.  id is immune to clock skew, so it is the correct
	// FIFO key.
	res, err := tx.Exec(
		`DELETE FROM scan_queue WHERE id IN (
			SELECT id FROM scan_queue WHERE uploaded = 0
			ORDER BY id ASC LIMIT ?
		)`,
		excess,
	)
	if err != nil {
		return EvictionResult{}, fmt.Errorf("evict oldest pending: %w", err)
	}
	evicted, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return EvictionResult{}, fmt.Errorf("commit eviction tx: %w", err)
	}

	reason := evictionReason(overRows, overBytes)
	if evicted > 0 {
		slog.Warn("cache: evicted oldest pending scans (backlog cap reached) — "+
			"server appears durably unreachable; oldest inventory snapshots dropped",
			slog.Int64("evicted", evicted),
			slog.String("reason", reason),
			slog.Int("row_cap", maxPendingScans),
			slog.Int("byte_cap", maxPendingBytes),
			slog.Int64("pending_bytes", totalBytes))
	}
	return EvictionResult{
		Count:           int(evicted),
		OldestScannedAt: oldest.String,
		NewestScannedAt: newest.String,
		Reason:          reason,
	}, nil
}

// evictionReason names which cap(s) triggered an eviction for the
// EvictionResult / audit detail: "rows", "bytes", or "rows,bytes".
func evictionReason(overRows, overBytes bool) string {
	switch {
	case overRows && overBytes:
		return "rows,bytes"
	case overBytes:
		return "bytes"
	default:
		return "rows"
	}
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
// legacy call site cannot OOM on a large offline backlog.  The second return
// value is the number of corrupt rows this call quarantined (see
// DequeuePendingBatch).
func (c *Cache) DequeuePending() ([]CachedScan, int, error) {
	return c.DequeuePendingBatch(defaultDequeueBatch)
}

// DequeuePendingBatch returns at most maxRows scan results that have not yet
// been uploaded, ordered by enqueue order (oldest first) for FIFO chronological
// drain.  A non-positive maxRows dequeues the entire pending backlog
// (unbounded) — use with care.  Rows are not removed; callers must call
// MarkUploaded after a successful upload.
//
// The second return value (quarantined) is how many rows this call examined,
// found undecodable, and successfully flipped to dead (uploaded = 2).  It lets
// the drain loop distinguish "this batch yielded no usable rows because it was
// ENTIRELY corrupt" (quarantined > 0 → keep draining; there may be good rows
// behind the just-quarantined ones) from "there are genuinely no more pending
// rows" (len(results) == 0 && quarantined == 0 → stop).  Because quarantined
// counts only rows durably marked uploaded = 2, the next batch skips them, so a
// drain loop that continues on quarantined > 0 makes strict forward progress and
// cannot spin (finding offline-1).
//
// Ordering is by id (AUTOINCREMENT, strictly monotonic = true enqueue order),
// NOT by the wall-clock scanned_at: a backward clock correction (NTP resync
// after a long air-gap outage, or a VM snapshot restore) makes scanned_at
// non-monotonic, which would reorder the catch-up drain.  id is immune to clock
// skew, so it preserves the exact order scans were enqueued.
func (c *Cache) DequeuePendingBatch(maxRows int) ([]CachedScan, int, error) {
	query := "SELECT id, scan_json FROM scan_queue WHERE uploaded = 0 ORDER BY id ASC"
	var args []any
	if maxRows > 0 {
		query += " LIMIT ?"
		args = append(args, maxRows)
	}

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []CachedScan
	var corrupt []int64
	var totalBytes int
	for rows.Next() {
		var id int64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			return nil, 0, err
		}
		var result scanner.ScanResult
		if err := json.Unmarshal([]byte(data), &result); err != nil {
			// Corrupt/undecodable blob.  Quarantine it (uploaded = 2) rather
			// than merely skipping it: a skipped row stays pending and would
			// re-consume a LIMIT slot on every drain cycle forever.  Log the
			// rowid + blob hash once (this is the only place the row is read
			// before quarantine, so it is logged exactly once).
			sum := sha256.Sum256([]byte(data))
			slog.Warn("cache: quarantining corrupt entry",
				slog.Int64("id", id),
				slog.String("sha256", hex.EncodeToString(sum[:])),
				slog.String("err", err.Error()))
			corrupt = append(corrupt, id)
			continue
		}
		results = append(results, CachedScan{QueueID: id, Result: &result})
		// Byte budget: stop once cumulative blob bytes cross the cap so a
		// backlog of large scans cannot OOM the drain.  Checked AFTER the
		// append so at least one row is always returned, even if that single
		// row alone exceeds the budget.
		totalBytes += len(data)
		if totalBytes >= maxDequeueBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	// Release the read cursor before issuing quarantine writes: the pool is
	// pinned to a single connection (SetMaxOpenConns(1)), so a write while the
	// rows cursor still holds that connection would deadlock.  Close is
	// idempotent, so the deferred Close remains harmless.
	_ = rows.Close()

	var quarantined int
	if len(corrupt) > 0 {
		marked, err := c.markDead(corrupt)
		quarantined = marked
		if err != nil {
			// Non-fatal: the caller still gets the decodable rows.  A failed
			// quarantine just means we retry the marking next cycle.  Only the
			// rows actually flipped to dead count toward `quarantined`, so a
			// drain loop that continues on quarantined > 0 never re-reads a row
			// that failed to mark (which would spin).
			slog.Warn("cache: failed to quarantine corrupt entries",
				slog.Int("count", len(corrupt)),
				slog.Int("marked", marked),
				slog.String("err", err.Error()))
		}
	}
	return results, quarantined, nil
}

// markDead sets uploaded = 2 (dead) on the given rowids.  Used to quarantine
// corrupt rows discovered during a dequeue.  Returns the number of rows it
// successfully flipped before any error, so the caller can report how many
// corrupt rows were durably quarantined (and thus will not be re-read).
func (c *Cache) markDead(ids []int64) (int, error) {
	marked := 0
	for _, id := range ids {
		if _, err := c.db.Exec(
			"UPDATE scan_queue SET uploaded = 2, uploaded_at = datetime('now') WHERE id = ?", id,
		); err != nil {
			return marked, err
		}
		marked++
	}
	return marked, nil
}

// MarkFailedPermanent marks a queued scan as permanently dead (uploaded = 2)
// so the drain loop stops retrying it.  Called when the server rejects the
// payload with a non-retryable 4xx (e.g. 413 too-large, 400 malformed): left
// pending, such a row head-of-line-blocks the entire queue, since the drain
// loop breaks on the first upload error every cycle.  See the tri-state
// documented above initSchema.
func (c *Cache) MarkFailedPermanent(queueID int64) error {
	_, err := c.db.Exec(
		"UPDATE scan_queue SET uploaded = 2, uploaded_at = datetime('now') WHERE id = ?", queueID,
	)
	return err
}

// MarkUploaded marks a cached scan as successfully uploaded to the server.
// uploaded_at is stamped here — the moment the row leaves the pending set —
// so PurgeUploaded's retention window measures time-since-delivery, not
// time-since-scan (see the tri-state note above initSchema).
func (c *Cache) MarkUploaded(queueID int64) error {
	_, err := c.db.Exec(
		"UPDATE scan_queue SET uploaded = 1, uploaded_at = datetime('now') WHERE id = ?", queueID,
	)
	return err
}

// PendingCount returns the number of scans waiting to be uploaded.
func (c *Cache) PendingCount() (int, error) {
	var count int
	err := c.db.QueryRow("SELECT COUNT(*) FROM scan_queue WHERE uploaded = 0").Scan(&count)
	return count, err
}

// PurgeUploaded deletes terminal entries whose delivery is older than the given
// duration to prevent unbounded disk growth of the local SQLite cache.  Both
// uploaded (uploaded = 1) and dead (uploaded = 2) rows are terminal — neither
// will ever be uploaded again — so both are reaped; PENDING rows (uploaded = 0)
// are never touched, so an offline backlog is preserved regardless of age.
//
// The window is measured from uploaded_at (the moment the row left the pending
// set), NOT created_at (scan time).  A catch-up drain after a long air-gap
// outage uploads scans with days-old created_at; keying on created_at would
// purge them the instant they were delivered, defeating the retention window.
// A terminal row always has uploaded_at set (stamped by the mark* methods, and
// backfilled for legacy rows in ensureUploadedAtColumn); the IS NOT NULL guard
// is defensive so any row that somehow lacks it is retained rather than reaped.
func (c *Cache) PurgeUploaded(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UTC().Format("2006-01-02 15:04:05")
	res, err := c.db.Exec(
		"DELETE FROM scan_queue WHERE uploaded IN (1, 2) AND uploaded_at IS NOT NULL AND uploaded_at < ?",
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
