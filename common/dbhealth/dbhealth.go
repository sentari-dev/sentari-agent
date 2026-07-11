// Package dbhealth classifies modernc.org/sqlite open/query failures so the
// agent's resilient-open paths (cache.OpenResilient, audit.OpenResilient) can
// tell a genuinely corrupt on-disk database — which SHOULD be quarantined aside
// and recreated — apart from a merely transient failure (ENOSPC, EACCES, a
// locked file) that must NOT destroy a healthy queue/chain.
//
// The distinction is load-bearing: quarantining on any open failure orphans
// weeks of pending offline scans (or the audit hash chain) the first time the
// disk fills or a permission bit is wrong.  Only a corruption-class result code
// means the bytes on disk are unusable.
package dbhealth

import (
	"errors"

	sqlite "modernc.org/sqlite"
)

// SQLite PRIMARY result codes that mean "the file on disk is damaged or is not
// a SQLite database at all".  modernc surfaces EXTENDED result codes (the
// primary code in the low 8 bits, a sub-code in the higher bits — e.g.
// SQLITE_CORRUPT_VTAB), so callers must compare the masked low byte, not the
// raw code.  Values are stable across every platform build of the amalgamation
// (see modernc.org/sqlite/lib: SQLITE_CORRUPT = 11, SQLITE_NOTADB = 26).
const (
	sqliteCorrupt = 11 // SQLITE_CORRUPT — the database disk image is malformed
	sqliteNotADB  = 26 // SQLITE_NOTADB  — file opened is not a database
)

// IsCorruption reports whether err (or anything in its wrapped chain) is a
// modernc.org/sqlite error whose PRIMARY result code is SQLITE_CORRUPT or
// SQLITE_NOTADB — the "the on-disk file is damaged / not a database" class that
// a resilient open may quarantine and recreate.
//
// Everything else — SQLITE_CANTOPEN (permission denied, missing parent dir),
// SQLITE_FULL / disk-full ENOSPC surfaced during applyWAL/initSchema,
// SQLITE_BUSY, or a non-sqlite error entirely — returns false, so the caller
// preserves the existing file and lets the daemon exit and retry later with the
// queue/chain intact.
func IsCorruption(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqliteCorrupt, sqliteNotADB:
			return true
		}
	}
	return false
}
