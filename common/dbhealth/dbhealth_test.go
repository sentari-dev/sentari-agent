package dbhealth

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unsafe"

	sqlite "modernc.org/sqlite"
)

// SQLite primary result codes referenced by the masking tests.  Kept as
// local literals (not imported from modernc.org/sqlite/lib) so this test
// documents the exact wire values IsCorruption depends on.
const (
	codeCorrupt  = 11 // SQLITE_CORRUPT
	codeNotADB   = 26 // SQLITE_NOTADB
	codeCantOpen = 14 // SQLITE_CANTOPEN (transient — permission/missing dir)
	codeBusy     = 5  // SQLITE_BUSY (transient — locked)
	codeFull     = 13 // SQLITE_FULL (transient — disk full)
)

// newSQLiteErr fabricates a *sqlite.Error carrying an arbitrary result
// code.  modernc.org/sqlite exposes Code() but keeps the struct fields
// unexported and ships no constructor, so the test reaches the `code`
// field via reflect+unsafe.  This lets us drive IsCorruption's extended-
// result-code masking (primary code in the low byte, a sub-code in the
// high bits — e.g. SQLITE_CORRUPT_INDEX = 11 | (3<<8)) deterministically,
// without having to provoke a real on-disk corruption of each specific
// extended variant.  TestIsCorruption_RealNotADatabaseError pins these
// fabricated errors to a genuine modernc result code so the poke stays
// faithful to reality.
func newSQLiteErr(t *testing.T, code int) *sqlite.Error {
	t.Helper()
	e := &sqlite.Error{}
	f := reflect.ValueOf(e).Elem().FieldByName("code")
	if !f.IsValid() {
		t.Fatalf("modernc.org/sqlite Error has no 'code' field; the pinned API changed")
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetInt(int64(code))
	if got := e.Code(); got != code {
		t.Fatalf("fabricated sqlite.Error code = %d, want %d", got, code)
	}
	return e
}

func TestIsCorruption_PrimaryCorruptionCodes(t *testing.T) {
	for _, code := range []int{codeCorrupt, codeNotADB} {
		if !IsCorruption(newSQLiteErr(t, code)) {
			t.Errorf("primary result code %d must classify as corruption", code)
		}
	}
}

func TestIsCorruption_ExtendedCorruptionCodesAreMasked(t *testing.T) {
	// modernc surfaces EXTENDED result codes: the primary code in the low
	// 8 bits, a sub-code in the higher bits.  IsCorruption masks with
	// &0xff, so every extended variant of CORRUPT/NOTADB must still be
	// classified as corruption — this is the branch with no other coverage.
	cases := []struct {
		name string
		code int
	}{
		{"CORRUPT_VTAB", codeCorrupt | (1 << 8)},     // 267
		{"CORRUPT_SEQUENCE", codeCorrupt | (2 << 8)}, // 523
		{"CORRUPT_INDEX", codeCorrupt | (3 << 8)},    // 779
		{"NOTADB_extended", codeNotADB | (1 << 8)},   // 282
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Guard against a test bug: the masked low byte must still be a
			// corruption primary, otherwise the assertion below is vacuous.
			if masked := tc.code & 0xff; masked != codeCorrupt && masked != codeNotADB {
				t.Fatalf("test bug: masked code %d is not a corruption primary", masked)
			}
			if !IsCorruption(newSQLiteErr(t, tc.code)) {
				t.Errorf("extended code %d (0x%x) must classify as corruption", tc.code, tc.code)
			}
		})
	}
}

func TestIsCorruption_TransientCodesAreNotCorruption(t *testing.T) {
	// CANTOPEN (permission denied / missing parent dir), BUSY (locked), and
	// FULL (disk full) are transient: quarantining on these would orphan a
	// healthy queue/chain.  Neither they nor their extended variants mask to
	// a corruption primary, so all must classify as NOT corruption.
	cases := []struct {
		name string
		code int
	}{
		{"CANTOPEN", codeCantOpen},
		{"CANTOPEN_extended", codeCantOpen | (1 << 8)},
		{"BUSY", codeBusy},
		{"FULL", codeFull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsCorruption(newSQLiteErr(t, tc.code)) {
				t.Errorf("transient code %d (0x%x) must NOT classify as corruption", tc.code, tc.code)
			}
		})
	}
}

func TestIsCorruption_WrappedSqliteError(t *testing.T) {
	// IsCorruption relies on errors.As, so a corruption code wrapped in the
	// applyWAL/initSchema fmt.Errorf chain must still be reached.
	wrapped := fmt.Errorf("initSchema: apply: %w", newSQLiteErr(t, codeCorrupt))
	if !IsCorruption(wrapped) {
		t.Error("a wrapped SQLITE_CORRUPT must classify as corruption")
	}
}

func TestIsCorruption_NonSqliteAndNil(t *testing.T) {
	if IsCorruption(errors.New("some non-sqlite failure")) {
		t.Error("a plain non-sqlite error must not classify as corruption")
	}
	if IsCorruption(nil) {
		t.Error("nil error must not classify as corruption")
	}
}

func TestIsCorruption_RealNotADatabaseError(t *testing.T) {
	// End-to-end faithfulness check: a genuine modernc error from opening a
	// non-SQLite file must classify as corruption.  This proves the
	// fabricated-error tests above mirror a real result code (and that the
	// &0xff masking is compatible with what modernc actually returns), not
	// just our own struct-poking.
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database"), 0o600); err != nil {
		t.Fatalf("seed garbage db: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	// Force a real read so SQLite parses the file header and rejects it.
	_, qerr := db.Exec("SELECT count(*) FROM sqlite_master")
	if qerr == nil {
		t.Fatal("expected an error querying a non-database file")
	}

	var se *sqlite.Error
	if !errors.As(qerr, &se) {
		t.Fatalf("expected a *sqlite.Error from modernc, got %T: %v", qerr, qerr)
	}
	t.Logf("real modernc error: code=%d masked=%d msg=%q", se.Code(), se.Code()&0xff, qerr)
	if !IsCorruption(qerr) {
		t.Errorf("a genuine 'not a database' error must classify as corruption (code=%d)", se.Code())
	}
}
