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
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sentari-dev/sentari-agent/common/dbhealth"
)

// Hash-chain scheme versions.  Each audit row records the scheme its
// content_hash was computed with (the hash_version column) so a chain may mix
// rows written by an old agent (v1) and a new one (v2) and still verify.
//
//   - Scheme v1 (original): SHA-256(event_type + detail + prev_hash +
//     created_at) — plain concatenation with NO field delimiters.  The field
//     boundaries are ambiguous: moving trailing bytes of event_type onto the
//     front of detail (or of prev_hash onto created_at, etc.) yields byte-
//     identical hash input and therefore the SAME digest, so hash-equal
//     forgeries exist by construction.  Retained ONLY to verify rows already
//     written by older agents; never used for new writes.
//
//   - Scheme v2 (current): length-prefixed encoding.  For each field in the
//     fixed order (event_type, detail, prev_hash, created_at) the hash input
//     is an 8-byte big-endian unsigned length of the field's UTF-8 bytes
//     followed by those bytes:
//
//     sha256( u64be(len(event_type)) | event_type |
//     u64be(len(detail))     | detail     |
//     u64be(len(prev_hash))  | prev_hash  |
//     u64be(len(created_at)) | created_at )
//
//     Prefixing every field with its exact byte length makes the boundaries
//     unambiguous — no rearrangement of bytes across fields can reproduce the
//     same digest — which closes the v1 field-shift forgery by construction.
const (
	hashSchemeV1 = 1
	hashSchemeV2 = 2
)

// MaxAuditBytes is the soft cap, in bytes, on the total logical size of the
// audit_log table.  It bounds the on-disk growth of the local audit log so a
// long-lived agent does not accumulate audit rows forever.  It is the "config
// knob" for the retention purge enforced by MarkShipped (see
// enforceRetentionLocked): when the estimated table size exceeds this cap, the
// OLDEST already-SHIPPED rows are purged oldest-first.
//
//	0 (the default) DISABLES purging entirely — every row is retained forever,
//	the historical behaviour.  A deployment that wants a bound sets this once at
//	startup (e.g. from an agent-config field) to a positive byte budget.
//
// CRITICAL SAFETY INVARIANTS the purge upholds (see enforceRetentionLocked):
//
//   - It NEVER deletes an UNSHIPPED row.  An unshipped row is evidence the
//     server has not yet witnessed; dropping it would lose audit evidence.  On
//     a long air-gap outage EVERY row is unshipped (the server is unreachable),
//     so the purge is a no-op and the log grows unbounded — which is CORRECT:
//     the growth is undelivered evidence that must be preserved, not discarded.
//     The cap only ever reclaims rows the server has already re-anchored.
//
//   - It only ever purges a contiguous OLDEST-id prefix of shipped rows and
//     always retains the newest keepShippedTailRows shipped rows as a forensic
//     tail, so VerifyChain still validates the retained chain (its first row is
//     seeded from that row's own stored prev_hash — see VerifyChain).
//
//   - It never touches the id high-water-mark sidecar nor sqlite_sequence, so
//     new ids keep climbing monotonically above every id the server witnessed
//     (no id reuse after a purge → no collision on the server's re-anchor key).
var MaxAuditBytes int64 = 0

// SetMaxAuditBytes overrides the audit-log retention cap (MaxAuditBytes) from an
// operator-supplied value, applied once at startup before the log is used (see
// main_enterprise's audit setup and config.AuditConfig).  It mirrors
// cache.SetMaxPendingBytes: a NEGATIVE argument is clamped to 0 (disabled)
// rather than trusted, so a malformed value can never make the estimated-size
// comparison in enforceRetentionLocked go haywire.  A value of 0 disables
// purging entirely (retain forever — the package default); a positive value is
// a byte budget above which the oldest SHIPPED rows are reclaimed.  It only
// assigns the package var — the retention semantics enforced by MarkShipped /
// enforceRetentionLocked are unchanged.
func SetMaxAuditBytes(n int64) {
	if n < 0 {
		n = 0
	}
	MaxAuditBytes = n
}

// keepShippedTailRows is the minimum number of the most-recent SHIPPED rows the
// retention purge always retains, even when the table is over MaxAuditBytes.
// Keeping a tail preserves a window of recent, server-witnessed history on the
// device for forensics and keeps a real (non-genesis) chain segment for
// VerifyChain to walk.  A var (not a const) so tests can shrink it.
var keepShippedTailRows = 200

// auditNoDeleteTriggerSQL creates the append-only DELETE guard.  Factored into a
// constant so initAuditSchema and the retention purge (enforceRetentionLocked,
// which must DROP it to delete the shipped prefix and then recreate it) share
// ONE definition and can never drift.
const auditNoDeleteTriggerSQL = `
	CREATE TRIGGER IF NOT EXISTS audit_no_delete
	BEFORE DELETE ON audit_log
	BEGIN
		SELECT RAISE(ABORT, 'audit log is append-only: rows cannot be deleted');
	END;`

// auditRowBytesExpr is a SQLite expression estimating the stored size of one
// audit_log row: the byte length of every text field plus a fixed per-row
// overhead approximating id/flag columns, the row header, and index entries.
// The estimate need only be monotonic in row count and content size for the cap
// to bound growth; it is deliberately not an exact page-accounting figure.
const auditRowBytesExpr = "length(event_type)+length(detail)+length(content_hash)+length(prev_hash)+length(created_at)+64"

// computeHashV1 implements the original, ambiguous scheme (see the scheme-
// version doc above).  Kept solely to verify legacy rows; do not write with it.
func computeHashV1(eventType, detail, prevHash, createdAt string) string {
	payload := eventType + detail + prevHash + createdAt
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// computeHashV2 implements the length-prefixed scheme (see the scheme-version
// doc above).  This is the encoding all new rows use.
func computeHashV2(eventType, detail, prevHash, createdAt string) string {
	h := sha256.New()
	var lenBuf [8]byte
	for _, field := range []string{eventType, detail, prevHash, createdAt} {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(field)))
		h.Write(lenBuf[:])
		h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// computeHash dispatches to the encoding identified by hashVersion so callers
// (Log for writing, VerifyChain for re-deriving) share one source of truth.
func computeHash(hashVersion int, eventType, detail, prevHash, createdAt string) (string, error) {
	switch hashVersion {
	case hashSchemeV1:
		return computeHashV1(eventType, detail, prevHash, createdAt), nil
	case hashSchemeV2:
		return computeHashV2(eventType, detail, prevHash, createdAt), nil
	default:
		return "", fmt.Errorf("unknown audit hash_version %d", hashVersion)
	}
}

// AuditLog is the local append-only audit log.
type AuditLog struct {
	db     *sql.DB
	dbPath string
	mu     sync.Mutex
}

// highWaterMarkPath returns the sidecar file that persists the maximum audit
// entry id EVER assigned for this database.  It lives next to the db file so it
// survives db-file corruption — which is the whole point: after a corrupt
// recreate (OpenResilient) the fresh AUTOINCREMENT must be seeded ABOVE every id
// the server may already have witnessed, or reused ids collide with shipped ones
// and the server drops the entire post-recovery history (see OpenResilient).
func highWaterMarkPath(dbPath string) string {
	return dbPath + ".hwm"
}

// readHighWaterMark reads the persisted max-id sidecar.  A missing, empty, or
// unparseable file yields 0 ("no prior ids"): a damaged sidecar must never block
// recovery, and 0 is the safe floor (AUTOINCREMENT then simply proceeds from 1).
func readHighWaterMark(dbPath string) int64 {
	data, err := os.ReadFile(highWaterMarkPath(dbPath))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// fsyncFile flushes a file's written bytes to stable storage.  A package var
// (not a direct f.Sync() call) so a test can assert the durable-write path
// actually invokes it — the durability is the whole point of the fix, and a
// silently-dropped Sync would pass a naive round-trip test while leaving the
// power-loss hole open.
var fsyncFile = func(f *os.File) error { return f.Sync() }

// fsyncDir best-effort flushes a directory entry so a rename becomes durable
// (the new dir entry survives power loss, not just the file's data blocks).
// Opening a directory for fsync is a POSIX guarantee but NOT portable: some
// platforms (notably Windows) refuse to open a directory as a file or return an
// error from Sync.  A failure here is therefore tolerated — the sidecar's own
// bytes are already fsynced (the load-bearing durability), and the sidecar is a
// recovery aid, not part of the hash chain.  Kept no-op-tolerant to preserve
// the CGO_ENABLED=0 cross-platform charter.
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// hwmLockRetries / hwmLockBackoff bound the best-effort exclusive-lock acquire
// in writeHighWaterMark.  Kept short and cheap: the lock only guards a tiny
// read-max-write-rename, the write path is best-effort at the call site, and on
// acquire failure we fall back to a still-monotonic max-on-write — so we must
// never block the audit write path for long.  Worst-case block is
// retries*backoff (~100ms) before falling through to the lock-free path.
const (
	hwmLockRetries = 50
	hwmLockBackoff = 2 * time.Millisecond
)

// hwmLockHeldHook, when non-nil, is invoked with the lock-file path while the
// HWM lock is held (after acquire, before the critical section runs).  Test
// seam only — it lets a test observe that the lock file actually exists during
// the read-max-write-rename.  Nil in production.
var hwmLockHeldHook func(lockPath string)

// acquireHWMLock makes a best-effort attempt to take an exclusive lock on the
// sidecar by atomically creating "<sidecar>.lock" (O_CREATE|O_EXCL), retrying
// with a short backoff while it is already held.  Returns true iff the lock was
// acquired (and must be released via releaseHWMLock).
//
// Pure-Go and cross-platform: O_CREATE|O_EXCL create is atomic on both unix and
// windows, honouring the CGO_ENABLED=0 charter without any OS-specific flock.
//
// A non-contention error (permission, missing directory, …) will not clear on
// retry, so we give up immediately and let the caller fall back to the
// lock-free max-on-write.  A lock left behind by a crashed writer is likewise
// tolerated: after the bounded retries we return false and the caller falls
// back — still monotonic, never regressing — rather than risk breaking a lock
// another live writer holds.
func acquireHWMLock(sidecarPath string) bool {
	lp := sidecarPath + ".lock"
	for i := 0; i < hwmLockRetries; i++ {
		f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = f.Close()
			return true
		}
		if !os.IsExist(err) {
			return false // non-contention error: retry won't help
		}
		time.Sleep(hwmLockBackoff)
	}
	return false
}

// releaseHWMLock removes the lock file taken by acquireHWMLock.  Best-effort:
// a failed remove only degrades subsequent writers to the (still monotonic)
// lock-free path, never corrupts the sidecar.
func releaseHWMLock(sidecarPath string) {
	_ = os.Remove(sidecarPath + ".lock")
}

// writeHighWaterMark advances the persisted max-id sidecar to id.
//
// MONOTONIC (the load-bearing guarantee): the persisted value can only ever
// increase.  The decision to overwrite is made from a RE-READ of the current
// on-disk HWM taken immediately before the rename, and the rename happens only
// when id is strictly greater — i.e. it writes max(on-disk, id).  A stale
// writer holding an old, lower id can therefore never lower a higher value some
// other process already persisted (a regression would let a recreated chain
// reuse an id the server already witnessed and be flagged as tampering — the
// exact collision this sidecar exists to prevent; see OpenResilient).
//
// CROSS-PROCESS SERIALIZATION (best-effort): the read-max-write-rename runs
// under a best-effort exclusive lock file (<sidecar>.lock, O_CREATE|O_EXCL with
// bounded retry — see acquireHWMLock).  With the lock held, the whole sequence
// is serialized across processes and even the transient rename window is
// closed.  If the lock cannot be acquired within the retry budget (heavy
// contention, or a lock stranded by a crashed writer), we fall through to the
// lock-free path: still monotonic w.r.t. everything THIS process observed.
//
// RESIDUAL (documented, accepted): on the lock-free fallback path only, a
// narrow window remains between the re-read and the rename in which another
// process could persist a higher value that this rename then overwrites with a
// lower one.  In practice writers advance the HWM in near-lockstep with the
// monotonically increasing audit id, so the value re-read here is almost always
// already the max; the window is a transient, self-healing regression (the next
// advance re-raises it) rather than a durable loss, and the lock closes it in
// the common case.  A fully lock-free cross-platform CAS on a plain file is not
// available under CGO_ENABLED=0, so this is the clean bound.
//
// DURABILITY: written via a unique temp file + atomic rename so a crash
// mid-write cannot leave a torn value.  The temp file's bytes are fsynced
// BEFORE the rename and the containing directory is fsynced AFTER it, so power
// loss cannot regress the persisted HWM.  Best-effort at the call site —
// callers treat a returned error as non-fatal because the chain is already
// committed — but the successful-write path is genuinely durable: a Sync error
// surfaces here rather than being silently ignored.
func writeHighWaterMark(dbPath string, id int64) error {
	// Fast path: a value that cannot advance the persisted max is a no-op.  This
	// pre-check is only an optimisation (it avoids taking the lock for the common
	// no-op advance); the authoritative monotonic decision is re-made from a
	// fresh read under the lock below.
	if id <= readHighWaterMark(dbPath) {
		return nil
	}
	p := highWaterMarkPath(dbPath)

	// Serialize the read-max-write-rename across processes with a best-effort
	// exclusive lock.  On acquire failure we proceed lock-free — still monotonic.
	if acquireHWMLock(p) {
		defer releaseHWMLock(p)
		if hwmLockHeldHook != nil {
			hwmLockHeldHook(p + ".lock")
		}
	}

	// Re-read under the lock: another writer may have raised the HWM between the
	// fast-path check and here.  Writing only when strictly greater makes the
	// persisted value max(on-disk, id) and closes the regression in the common
	// (lock-held) case.
	if id <= readHighWaterMark(dbPath) {
		return nil
	}

	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write([]byte(strconv.FormatInt(id, 10))); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// fsync the contents before Close+Rename: without this, a power loss after
	// the rename can expose a torn/empty sidecar whose readHighWaterMark yields
	// 0, regressing the HWM and re-opening the collision window.
	if err := fsyncFile(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync hwm sidecar: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	// fsync the directory so the rename itself is durable across power loss.
	// Best-effort / cross-platform — see fsyncDir.
	fsyncDir(filepath.Dir(p))
	return nil
}

// seedAutoincrement forces audit_log's next AUTOINCREMENT id to be at least
// hwm+1 by seeding the sqlite_sequence row SQLite consults for AUTOINCREMENT
// tables (it hands out max(seq)+1, so seq=hwm makes the next id hwm+1).  A fresh
// table has no sqlite_sequence row until its first insert; this runs before the
// recreate marker is written, so it INSERTs the seed row.  If a row already
// exists it is only ever raised, never lowered.
func seedAutoincrement(db *sql.DB, hwm int64) error {
	res, err := db.Exec(
		"UPDATE sqlite_sequence SET seq = ? WHERE name = 'audit_log' AND seq < ?",
		hwm, hwm,
	)
	if err != nil {
		return fmt.Errorf("raise sqlite_sequence: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// No row updated: the seed row is either absent (no insert yet) or already
	// >= hwm.  Insert it only when absent.
	var present int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_sequence WHERE name = 'audit_log'",
	).Scan(&present); err != nil {
		return fmt.Errorf("probe sqlite_sequence: %w", err)
	}
	if present == 0 {
		if _, err := db.Exec(
			"INSERT INTO sqlite_sequence (name, seq) VALUES ('audit_log', ?)", hwm,
		); err != nil {
			return fmt.Errorf("insert sqlite_sequence: %w", err)
		}
	}
	return nil
}

// auditDSN builds the modernc.org/sqlite connection string for the audit
// database.  busy_timeout makes a writer wait (rather than immediately
// erroring SQLITE_BUSY) when the db is momentarily locked, and the caller
// pins SetMaxOpenConns(1) so writes are serialised within this process.
//
// NOTE: modernc.org/sqlite does NOT honour a `_journal_mode=WAL` DSN
// parameter — it is silently ignored.  WAL (which keeps reads from
// blocking the single writer) is applied via `PRAGMA journal_mode=WAL`
// in applyWAL after the connection is opened, and verified to have
// taken effect.  `_txlock=immediate` IS honoured by modernc and stays
// in the DSN.
//
// _txlock=immediate makes every BeginTx start with BEGIN IMMEDIATE, taking the
// database write lock at transaction start instead of lazily on first write.
// This is the load-bearing cross-PROCESS serialisation for the hash chain: a
// second agent process appending concurrently blocks (up to busy_timeout) on
// the write lock until the first commits, then reads the updated chain head —
// so two writers can never read the same prev_hash and fork the chain.  An
// in-process mutex alone cannot do this; the DB-level lock is what spans
// processes.
func auditDSN(dbPath string) string {
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

// NewAuditLog opens or creates an audit log database at the given path.
func NewAuditLog(dbPath string) (*AuditLog, error) {
	db, err := sql.Open("sqlite", auditDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	// Serialise writers within this process: a single connection plus
	// busy_timeout(5000) means concurrent Log calls queue on the Go-side
	// connection pool instead of racing into SQLITE_BUSY.  The in-process
	// mutex already serialises Log, but VerifyChain and any future reader
	// share this handle, so the cap keeps everyone consistent.
	db.SetMaxOpenConns(1)

	// WAL must be applied via PRAGMA — the DSN parameter is ignored by
	// modernc.org/sqlite.  Apply before schema init so the very first
	// writes land in WAL mode.
	if err := applyWAL(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL on audit db: %w", err)
	}

	if err := initAuditSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init audit schema: %w", err)
	}

	// Restrict database file permissions to owner-only (0600).
	_ = os.Chmod(dbPath, 0600)

	a := &AuditLog{db: db, dbPath: dbPath}

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

// OpenResilient opens the audit log at dbPath, recovering from a CORRUPTION-
// class on-disk database (truncated, not a SQLite database, damaged header —
// surfaced as SQLITE_CORRUPT/SQLITE_NOTADB via dbhealth.IsCorruption) rather
// than bricking the daemon at startup.  It mirrors cache.OpenResilient and
// shares the same corruption gate.
//
// On corruption the offending file — plus its WAL/SHM sidecars — is renamed
// aside to "<dbPath>.corrupt-<unix-ts>" and a FRESH audit log is created in its
// place.  A brand-new hash chain is started and its very first entry is a loud
// "audit.recreated" event naming the quarantined file.  Starting a fresh chain
// is acceptable BECAUSE the quarantined file preserves the old chain verbatim
// for forensic inspection — no evidence is destroyed, it is set aside — and a
// bricked daemon that collects no further audit trail is strictly worse than a
// new chain that continues recording from a clearly-marked genesis.
//
// A TRANSIENT open failure (disk full, permission denied, a locked file — not a
// corruption result code) is NOT recovered from: the original error is returned
// unchanged so the daemon exits and retries later with the existing chain
// intact.  Only a double failure (corrupt file could not be moved aside, or the
// fresh open itself fails) returns a fatal error.
//
// Returns the opened log; recovered=true when a quarantine+recreate happened;
// quarantinedPath naming the preserved corrupt file (empty when no recovery
// occurred); and an error as described above.
func OpenResilient(dbPath string) (a *AuditLog, recovered bool, quarantinedPath string, err error) {
	a, err = NewAuditLog(dbPath)
	if err != nil {
		firstErr := err
		// Only a corruption-class failure justifies quarantining the chain.  A
		// transient error leaves a perfectly good chain on disk — return it so
		// the daemon exits and retries rather than abandoning witnessed history.
		if !dbhealth.IsCorruption(firstErr) {
			return nil, false, "", fmt.Errorf("open audit db (transient, not quarantining): %w", firstErr)
		}
		return recreateCorruptAudit(dbPath, firstErr)
	}

	// NewAuditLog succeeded, but SQLite detects data-page corruption LAZILY: a
	// torn page BELOW the schema (so `CREATE TABLE IF NOT EXISTS` in
	// initAuditSchema — which reads only sqlite_master on page 1 — never touched
	// it) surfaces only when VerifyChain scans the whole audit_log table at open.
	// NewAuditLog already ran VerifyChain, logged the failure, and STILL returned
	// a usable handle — which is exactly right for a TAMPERED-but-readable chain
	// (quarantining that would destroy the tamper evidence VerifyChain exists to
	// preserve).  But a CORRUPTION-class VerifyChain failure is a damaged file,
	// not tamper evidence, so it must drive the same quarantine-and-recreate path
	// as an open-time corruption.
	//
	// The distinction is exact and load-bearing:
	//   - A broken hash chain on INTACT pages (a row edited without recomputing
	//     downstream hashes, a truncated-then-relinked chain) surfaces as a plain
	//     fmt.Errorf ("prev_hash mismatch" / "content_hash mismatch") built by
	//     VerifyChain itself.  That is NOT a *sqlite.Error, so IsCorruption is
	//     false → we leave the file untouched and logged-only, preserving the
	//     evidence for the operator/server to investigate.
	//   - An UNREADABLE page yields a wrapped *sqlite.Error with primary code
	//     SQLITE_CORRUPT → IsCorruption is true → quarantine + recreate.
	if verr := a.VerifyChain(); verr != nil && dbhealth.IsCorruption(verr) {
		_ = a.Close()
		return recreateCorruptAudit(dbPath, verr)
	}

	return a, false, "", nil
}

// recreateCorruptAudit quarantines a corruption-class audit database aside to
// "<dbPath>.corrupt-<unix-ts>" (with its WAL/SHM sidecars) and creates a FRESH
// audit log in its place, seeding the new AUTOINCREMENT counter above the
// high-water-mark and stamping an "audit.recreated" genesis marker.  Shared by
// both OpenResilient corruption paths — open-time (NewAuditLog error) and the
// lazy VerifyChain read-time detection — so recovery is identical either way.
// `cause` is the corruption error being recovered from, threaded into the error
// message when the file cannot be moved aside.
func recreateCorruptAudit(dbPath string, cause error) (a *AuditLog, recovered bool, quarantinedPath string, err error) {
	quarantinedPath = fmt.Sprintf("%s.corrupt-%d", dbPath, time.Now().Unix())
	if renameErr := os.Rename(dbPath, quarantinedPath); renameErr != nil {
		return nil, false, "", fmt.Errorf("open audit db (%w); could not quarantine to %s: %v",
			cause, quarantinedPath, renameErr)
	}
	// Move the WAL/SHM sidecars alongside so the fresh db starts clean and the
	// quarantined snapshot is self-contained.  Best-effort — they may not exist.
	_ = os.Rename(dbPath+"-wal", quarantinedPath+"-wal")
	_ = os.Rename(dbPath+"-shm", quarantinedPath+"-shm")

	// Bound the quarantine set: a device with a failing disk can corrupt its
	// audit db on every boot, and each recovery leaves another
	// "<dbPath>.corrupt-*" copy behind.  Unbounded, those sets fill the disk —
	// the very failure quarantining exists to survive.  Keep the most recent few
	// for forensics, prune older ones (with their sidecars).  Mirrors
	// cache.pruneCorruptQuarantines.  Best-effort: a prune failure must NOT abort
	// the corruption recovery it is cleaning up after, so it is only logged.
	if pruneErr := pruneAuditCorruptQuarantines(dbPath, quarantinedPath, keepCorruptQuarantines); pruneErr != nil {
		slog.Warn("audit: failed to prune old corrupt quarantine files",
			slog.String("err", pruneErr.Error()))
	}

	a, err = NewAuditLog(dbPath)
	if err != nil {
		return nil, false, quarantinedPath, fmt.Errorf("reopen audit db after quarantine of %s: %w",
			quarantinedPath, err)
	}
	// Seed the fresh table's AUTOINCREMENT counter ABOVE the highest id ever
	// assigned in the (now-quarantined) prior chain, read from the sidecar that
	// survives db corruption.  Without this the fresh chain restarts ids at 1 and
	// COLLIDES with ids the server already witnessed: server ingest keys on
	// (device_id, agent_entry_id), finds a prior row with a DIFFERENT
	// content_hash for the reused id, flags 'local tampering', and — because
	// storage is gated on the prior row being absent — silently drops the ENTIRE
	// post-recovery history, including the audit.recreated marker below.  Seeding
	// ids above the high-water-mark makes every new id unseen (prior is None), so
	// the server stores them.  See server/services/agent_audit_ingest.py
	// (ingest_agent_audit: `prior = existing.get(e.entry_id)` /
	// `if prior is None: db.add(...)`).  Best-effort: a seed failure only weakens
	// collision avoidance; the fresh log is already usable.
	if hwm := readHighWaterMark(dbPath); hwm > 0 {
		if seedErr := seedAutoincrement(a.db, hwm); seedErr != nil {
			slog.Error("audit: failed to seed post-recovery id counter above high-water-mark; "+
				"new ids may collide with already-shipped entries",
				slog.Int64("high_water_mark", hwm),
				slog.String("err", seedErr.Error()))
		}
	}
	// First entry of the fresh chain: a loud, self-documenting marker so an
	// auditor reading the new log sees exactly why it begins mid-life and where
	// the prior chain was preserved.  A write failure here is non-fatal — the
	// log is already usable; we just could not stamp the genesis marker.
	if logErr := a.Log("audit.recreated", fmt.Sprintf("corrupt_db_quarantined=%s", quarantinedPath)); logErr != nil {
		slog.Error("audit: failed to write recreate marker to fresh chain",
			slog.String("err", logErr.Error()))
	}
	return a, true, quarantinedPath, nil
}

// keepCorruptQuarantines bounds how many "<dbPath>.corrupt-<ts>" quarantine sets
// recreateCorruptAudit retains for forensics.  Three is enough to inspect a
// recurring-corruption pattern (e.g. a failing disk) while staying bounded.
// Mirrors cache.keepCorruptQuarantines.
const keepCorruptQuarantines = 3

// pruneAuditCorruptQuarantines deletes the oldest "<dbPath>.corrupt-<ts>"
// quarantine sets — each a base file plus its optional -wal/-shm sidecars — so
// that at most `keep` of the most RECENT sets remain.  It globs ONLY this db's
// corrupt-* siblings (never the live audit.db or its -wal/-shm), orders them
// newest-first by the embedded unix-second timestamp (falling back to mtime,
// then lexical name, when the suffix will not parse), and NEVER removes keepPath
// — the just-created quarantine — even if a clock anomaly sorted it out of the
// newest `keep`.  Best-effort: returns the first delete error for the caller to
// log but is otherwise non-fatal.  Mirrors cache.pruneCorruptQuarantines.
func pruneAuditCorruptQuarantines(dbPath, keepPath string, keep int) error {
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

func initAuditSchema(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type   TEXT    NOT NULL,
			detail       TEXT    NOT NULL,
			content_hash TEXT    NOT NULL,
			prev_hash    TEXT    NOT NULL DEFAULT '',
			created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
			shipped      INTEGER NOT NULL DEFAULT 0,
			-- Encoding scheme of content_hash (see hashSchemeV1/V2).  Fresh
			-- databases default rows to 1; Log writes 2.  Existing databases
			-- created before scheme v2 are migrated in ensureHashVersionColumn.
			hash_version INTEGER NOT NULL DEFAULT 1
		);

		-- Append-only enforcement: prevent modification of audit entries.
		-- Only the "shipped" column may be updated (via MarkShipped).  Both
		-- content columns and hash_version are immutable: hash_version is set
		-- once at INSERT and never rewritten.
		CREATE TRIGGER IF NOT EXISTS audit_no_update
		BEFORE UPDATE OF event_type, detail, content_hash, prev_hash, created_at, hash_version ON audit_log
		BEGIN
			SELECT RAISE(ABORT, 'audit log is append-only: content columns cannot be modified');
		END;
	` + auditNoDeleteTriggerSQL); err != nil {
		return err
	}
	return ensureHashVersionColumn(db)
}

// ensureHashVersionColumn adds the hash_version column to an audit_log created
// before scheme v2 existed.  Fresh databases already have the column from
// initAuditSchema's CREATE TABLE; this ALTER is the in-place migration for logs
// already on disk.  It is guarded by a PRAGMA table_info probe so it runs at
// most once and is a no-op on up-to-date schemas.  Pre-existing rows keep the
// column DEFAULT 1 (they were written with the v1 encoding); Log writes new
// rows with hash_version=2.  hash_version is never UPDATEd, so the append-only
// trigger (which on legacy databases does not list the new column) is not in
// its path — the same benign carve-out the `shipped` column relied on.
func ensureHashVersionColumn(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(audit_log)")
	if err != nil {
		return fmt.Errorf("inspect audit_log schema: %w", err)
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
			return fmt.Errorf("scan audit_log schema: %w", err)
		}
		if name == "hash_version" {
			present = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate audit_log schema: %w", err)
	}
	// Close before issuing the ALTER: the pool is pinned to a single
	// connection (SetMaxOpenConns(1)), so an Exec while these rows are still
	// open would contend with itself.
	rows.Close()
	if present {
		return nil
	}
	if _, err := db.Exec(
		"ALTER TABLE audit_log ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1",
	); err != nil {
		return fmt.Errorf("add hash_version column: %w", err)
	}
	return nil
}

// Log appends an event to the audit log with hash chain integrity.
//
// The read-of-the-current-head and the insert run inside a single BEGIN
// IMMEDIATE transaction (see auditDSN's _txlock=immediate).  Taking the write
// lock up front serialises appends across PROCESSES, not just goroutines: a
// second agent process blocks on the write lock until the first commits, then
// reads the freshly-committed head, so two writers can never both anchor on the
// same prev_hash and fork the chain.  The in-process mutex below is kept so
// concurrent Log calls within this process are serialised, but the DB lock is
// the cross-process guarantee.
//
// prev_hash is read from the database inside the transaction rather than from
// any in-memory cache, because another process may have appended since this
// instance was opened — trusting a stale cached value is exactly what caused
// the fork.
func (a *AuditLog) Log(eventType, detail string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ctx := context.Background()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit tx: %w", err)
	}
	defer tx.Rollback() // no-op after a successful Commit.

	// Read the current chain head under the write lock.  Empty string when the
	// log is empty (genesis).
	var prevHash string
	row := tx.QueryRowContext(ctx, "SELECT content_hash FROM audit_log ORDER BY id DESC LIMIT 1")
	if err := row.Scan(&prevHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read audit head: %w", err)
	}

	// Compute the content hash with the current scheme (v2, length-prefixed).
	// created_at is the exact RFC3339Nano string hashed and stored, so the
	// server can recompute byte-for-byte.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	hashHex := computeHashV2(eventType, detail, prevHash, now)

	res, err := tx.ExecContext(ctx,
		"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at, hash_version) VALUES (?, ?, ?, ?, ?, ?)",
		eventType, detail, hashHex, prevHash, now, hashSchemeV2,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	newID, _ := res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit log: %w", err)
	}

	// Persist the high-water-mark of assigned ids so a future corrupt-recreate
	// (OpenResilient) seeds the fresh AUTOINCREMENT above every id the server may
	// already have witnessed.  Updating it on every write (not just on
	// MarkShipped) is the safe choice: it covers ids the server witnessed via a
	// ship whose MarkShipped never landed.  Best-effort — the chain is already
	// committed; a sidecar write failure only weakens post-corruption
	// id-collision avoidance, so log and continue.
	if newID > 0 {
		if hwmErr := writeHighWaterMark(a.dbPath, newID); hwmErr != nil {
			slog.Warn("audit: failed to update id high-water-mark sidecar",
				slog.String("err", hwmErr.Error()))
		}
	}

	return nil
}

// VerifyChain recomputes the SHA-256 hash chain and returns an error
// identifying the first row whose stored hash or prev_hash does not match the
// recomputed value.  A clean (or empty) log returns nil.
//
// This detects partial tampering and corruption — NOT a sophisticated local
// attacker who recomputes the whole chain after editing a row (see the
// package doc TRUST MODEL).  It is the agent-side half of tamper-evidence;
// the authoritative half is server-side re-anchoring.
//
// The running prev_hash is SEEDED from the FIRST (lowest-id) retained row's own
// stored prev_hash rather than hard-requiring the first row to be genesis
// (prev_hash == "").  This is what lets a legitimately PURGED shipped prefix
// (see enforceRetentionLocked) still verify: after the oldest shipped rows are
// reclaimed, the lowest surviving row's prev_hash points at a now-deleted
// predecessor, which is expected, not tampering.  For a never-purged log the
// first row is genesis with prev_hash == "", so the seed is "" and behaviour is
// identical to before.  Every row's own content_hash is still recomputed from
// its stored fields (so no row can be individually forged), and every
// consecutive pair is still linkage-checked (so a mid-chain edit or a torn
// middle is still caught).  What this deliberately no longer flags on its own is
// removal of a whole leading prefix — detection of which is delegated to the
// authoritative server-side re-anchoring named in the TRUST MODEL doc.
func (a *AuditLog) VerifyChain() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	rows, err := a.db.Query(
		"SELECT id, event_type, detail, content_hash, prev_hash, created_at, hash_version FROM audit_log ORDER BY id ASC",
	)
	if err != nil {
		return fmt.Errorf("verify chain: query: %w", err)
	}
	defer rows.Close()

	prevHash := ""
	first := true
	for rows.Next() {
		var id, hashVersion int
		var eventType, detail, contentHash, prevHashStored, createdAt string
		if err := rows.Scan(&id, &eventType, &detail, &contentHash, &prevHashStored, &createdAt, &hashVersion); err != nil {
			return fmt.Errorf("verify chain: scan: %w", err)
		}

		// Seed the running chain head from the first retained row's own
		// prev_hash so a legitimately purged leading prefix does not read as a
		// break (see the doc comment).  Genesis logs seed "" and are unaffected.
		if first {
			prevHash = prevHashStored
			first = false
		}

		// Each row's prev_hash must equal the previous row's content_hash.
		// Linkage is scheme-independent, so a mixed v1/v2 chain links normally.
		if prevHashStored != prevHash {
			return fmt.Errorf("verify chain: row %d: prev_hash mismatch (stored %q, expected %q)",
				id, prevHashStored, prevHash)
		}

		// Recompute the content hash with THIS row's own encoding scheme.
		wantHex, err := computeHash(hashVersion, eventType, detail, prevHashStored, createdAt)
		if err != nil {
			return fmt.Errorf("verify chain: row %d: %w", id, err)
		}
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

// UnshippedEntries returns at most `limit` audit log entries not yet sent to
// the server, oldest first (id ascending) for FIFO re-anchoring.  A non-
// positive `limit` returns the entire unshipped backlog (unbounded) — use with
// care.  Bounding the fetch keeps peak memory proportional to the batch size
// rather than to the offline duration: a durably air-gapped agent (up to the
// 365-day tier) can accumulate tens of thousands of unshipped rows, and the
// serve loop drains them a batch at a time (fetch → ship → MarkShipped) instead
// of materialising the whole backlog at once.  Mirrors cache.DequeuePendingBatch.
//
// The enterprise serve loop ships these to the server's re-anchoring endpoint
// (POST /api/v1/agent/audit-log, contract agent-audit-ship-v1) via
// comms.Client.ShipAudit and calls MarkShipped on success, so a later host
// compromise cannot rewrite history the server already witnessed. See the
// package TRUST MODEL doc for why off-host re-anchoring is the real
// tamper-evidence story.
func (a *AuditLog) UnshippedEntries(limit int) ([]map[string]string, error) {
	query := "SELECT id, event_type, detail, content_hash, prev_hash, created_at, hash_version FROM audit_log WHERE shipped = 0 ORDER BY id ASC"
	var args []any
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := a.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []map[string]string
	for rows.Next() {
		var id, hashVersion int
		var eventType, detail, contentHash, prevHash, createdAt string
		if err := rows.Scan(&id, &eventType, &detail, &contentHash, &prevHash, &createdAt, &hashVersion); err != nil {
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
			// Encoding scheme so the server recomputes with the right recipe.
			"hash_version": fmt.Sprintf("%d", hashVersion),
		})
	}
	return entries, rows.Err()
}

// MarkShipped marks entries as sent to the server.
//
// Paired with UnshippedEntries: the serve loop calls this after a successful
// ShipAudit batch so already-witnessed entries are not re-shipped. The
// `shipped` column and the audit_no_update trigger's allowance for updating it
// exist for this path; do not remove.
//
// Immediately after advancing the shipped cursor, MarkShipped enforces the
// MaxAuditBytes retention cap by purging the oldest already-shipped rows (see
// enforceRetentionLocked).  This is the production wiring for the growth bound:
// the serve loop already calls MarkShipped after every successful ship, so the
// cap is applied exactly when new rows have just become eligible (shipped =
// server-witnessed) to reclaim.  When MaxAuditBytes is 0 (the default) the
// purge is a no-op and the DB grows monotonically with total event volume, the
// historical behaviour.  A purge failure is non-fatal — the ship itself
// succeeded — so it is logged and swallowed rather than failing the caller.
func (a *AuditLog) MarkShipped(maxID int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.db.Exec("UPDATE audit_log SET shipped = 1 WHERE id <= ?", maxID); err != nil {
		return err
	}
	if err := a.enforceRetentionLocked(); err != nil {
		slog.Warn("audit: retention purge after ship failed; log stays above the size cap this cycle",
			slog.String("err", err.Error()))
	}
	return nil
}

// EnforceRetention applies the MaxAuditBytes cap on demand (MarkShipped calls
// the same logic automatically after every ship).  Exported so a future
// explicit-maintenance caller or a test can trigger a purge without shipping.
func (a *AuditLog) EnforceRetention() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enforceRetentionLocked()
}

// enforceRetentionLocked purges the OLDEST already-shipped rows when the table's
// estimated size exceeds MaxAuditBytes.  The caller MUST hold a.mu.
//
// Safety (see MaxAuditBytes for the full contract):
//   - Never deletes an unshipped row: the purge candidates are strictly the
//     shipped rows below the retained tail, and the delete is bounded by that
//     ceiling.  Because MarkShipped only ever sets shipped=1 for a contiguous
//     id<=maxID prefix, shipped rows are a prefix and unshipped rows a suffix,
//     so purging the oldest shipped ids can never reach an unshipped row.
//   - Retains the newest keepShippedTailRows shipped rows as a forensic tail.
//   - Deletes a contiguous oldest-id prefix, so VerifyChain still validates the
//     remaining chain (it seeds from the first surviving row's prev_hash).
//   - Leaves sqlite_sequence and the id high-water-mark sidecar untouched, so
//     new ids stay monotonic above every id the server has witnessed.
//
// The delete must temporarily DROP the append-only audit_no_delete trigger; it
// is dropped and recreated inside a single write-locked transaction, and a.mu is
// held, so no other writer (this process or another) can slip a DELETE through
// the gap.
func (a *AuditLog) enforceRetentionLocked() error {
	capBytes := MaxAuditBytes
	if capBytes <= 0 {
		return nil // purging disabled — retain everything (default)
	}

	var total int64
	if err := a.db.QueryRow(
		"SELECT COALESCE(SUM(" + auditRowBytesExpr + "), 0) FROM audit_log",
	).Scan(&total); err != nil {
		return fmt.Errorf("retention: measure size: %w", err)
	}
	if total <= capBytes {
		return nil // within budget
	}

	// tailFloor is the lowest id among the newest keepShippedTailRows shipped
	// rows; rows with id >= tailFloor are the retained forensic tail and are
	// never purge candidates.  Nothing shipped ⇒ no candidates ⇒ nothing to do.
	tail := keepShippedTailRows
	if tail < 0 {
		tail = 0
	}
	var tailFloor sql.NullInt64
	if err := a.db.QueryRow(
		"SELECT MIN(id) FROM (SELECT id FROM audit_log WHERE shipped = 1 ORDER BY id DESC LIMIT ?)",
		tail,
	).Scan(&tailFloor); err != nil {
		return fmt.Errorf("retention: find tail floor: %w", err)
	}
	if !tailFloor.Valid {
		return nil // no shipped rows to reclaim
	}

	// Walk purge candidates (shipped rows below the tail) oldest-first,
	// accumulating their estimated bytes, and stop at the smallest prefix whose
	// removal brings the table under the cap.  If the candidates cannot free
	// enough (the retained tail + unshipped rows already exceed the cap), delete
	// them all — that is the most we may safely reclaim.
	need := total - capBytes
	rows, err := a.db.Query(
		"SELECT id, ("+auditRowBytesExpr+") FROM audit_log WHERE id < ? AND shipped = 1 ORDER BY id ASC",
		tailFloor.Int64,
	)
	if err != nil {
		return fmt.Errorf("retention: scan candidates: %w", err)
	}
	var (
		cutoff  int64
		freed   int64
		haveCut bool
	)
	for rows.Next() {
		var id, rowBytes int64
		if err := rows.Scan(&id, &rowBytes); err != nil {
			rows.Close()
			return fmt.Errorf("retention: scan candidate row: %w", err)
		}
		cutoff = id
		haveCut = true
		freed += rowBytes
		if freed >= need {
			break
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("retention: iterate candidates: %w", err)
	}
	rows.Close()
	if !haveCut {
		return nil // no purgeable rows below the tail
	}

	// Delete the prefix [.., cutoff].  The DELETE would be rejected by the
	// append-only trigger, so drop it for the duration of the write-locked
	// transaction and recreate it before commit.  DDL is transactional in
	// SQLite, so a rollback restores the trigger too.
	ctx := context.Background()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("retention: begin tx: %w", err)
	}
	defer tx.Rollback() // no-op after a successful Commit.

	if _, err := tx.ExecContext(ctx, "DROP TRIGGER IF EXISTS audit_no_delete"); err != nil {
		return fmt.Errorf("retention: drop delete guard: %w", err)
	}
	// Re-assert shipped=1 in the predicate as belt-and-braces: even if the
	// prefix invariant were ever violated, an unshipped row can never be
	// deleted here.
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM audit_log WHERE id <= ? AND shipped = 1", cutoff,
	); err != nil {
		return fmt.Errorf("retention: delete shipped prefix: %w", err)
	}
	if _, err := tx.ExecContext(ctx, auditNoDeleteTriggerSQL); err != nil {
		return fmt.Errorf("retention: restore delete guard: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("retention: commit purge: %w", err)
	}
	return nil
}

// Close closes the audit log database.
func (a *AuditLog) Close() error {
	return a.db.Close()
}
