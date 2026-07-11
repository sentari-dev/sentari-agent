package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/common/dbhealth"
)

// auditFileExists reports whether path exists (any error, including
// permission, counts as absent for this test helper's purposes).
func auditFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestAuditOpenResilientRecoversFromGarbageFile verifies a corrupt audit DB
// (non-SQLite garbage → SQLITE_NOTADB) is quarantined aside, a FRESH hash chain
// is started, and that chain's first entry is the loud "audit.recreated" marker
// naming the preserved file — instead of bricking the daemon at startup
// (finding offline-3).
func TestAuditOpenResilientRecoversFromGarbageFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	if err := os.WriteFile(dbPath, []byte("this is definitely not a sqlite database"), 0o600); err != nil {
		t.Fatalf("seed garbage db: %v", err)
	}

	a, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer a.Close()
	if !recovered {
		t.Fatal("expected recovered=true for a garbage audit db")
	}
	if quarantinedPath == "" {
		t.Fatal("expected a non-empty quarantinedPath")
	}
	if _, statErr := os.Stat(quarantinedPath); statErr != nil {
		t.Fatalf("corrupt file should be preserved at %s: %v", quarantinedPath, statErr)
	}

	// The fresh chain must verify clean...
	if verr := a.VerifyChain(); verr != nil {
		t.Fatalf("fresh chain must verify clean: %v", verr)
	}
	// ...and its genesis entry must be the recreate marker naming the quarantine.
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("fresh chain must contain the audit.recreated marker")
	}
	if got := entries[0]["event_type"]; got != "audit.recreated" {
		t.Fatalf("first entry event_type = %q, want audit.recreated", got)
	}
	if detail := entries[0]["detail"]; !strings.Contains(detail, quarantinedPath) {
		t.Fatalf("recreate marker detail %q should reference quarantined path %q", detail, quarantinedPath)
	}

	// The fresh log must be writable going forward.
	if err := a.Log("scan.started", "hostname=post-recovery"); err != nil {
		t.Fatalf("Log on recovered audit: %v", err)
	}
}

// TestAuditOpenResilientPrunesOldCorruptQuarantines verifies that when more than
// keepCorruptQuarantines ".corrupt-*" sets already exist, a fresh corruption
// recovery prunes them down to the newest few (including the just-created one)
// and removes their -wal/-shm sidecars — so a device that repeatedly corrupts
// its audit db (failing disk) cannot accumulate quarantine copies without bound
// (finding offline-1, mirroring cache's round-8 fix).
func TestAuditOpenResilientPrunesOldCorruptQuarantines(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	// Seed 4 pre-existing quarantine sets with distinct, clearly-old unix-second
	// timestamps, each with its -wal/-shm sidecars.  keepCorruptQuarantines is 3,
	// so after recovery only the newest 3 sets (the 2 newest of these + the new
	// one) may survive; the 2 oldest must be pruned.
	old := []int64{1000, 1001, 1002, 1003}
	for _, ts := range old {
		base := fmt.Sprintf("%s.corrupt-%d", dbPath, ts)
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if err := os.WriteFile(p, []byte("old quarantine"), 0o600); err != nil {
				t.Fatalf("seed quarantine %s: %v", p, err)
			}
		}
	}

	// Trigger a fresh corruption recovery: garbage where the live audit db is.
	if err := os.WriteFile(dbPath, []byte("this is definitely not a sqlite database"), 0o600); err != nil {
		t.Fatalf("seed garbage db: %v", err)
	}
	a, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer a.Close()
	if !recovered {
		t.Fatal("expected recovered=true for a garbage db file")
	}

	// Exactly keepCorruptQuarantines base sets must remain (glob excludes the
	// live audit.db, whose name has no .corrupt- infix).
	bases, _ := filepath.Glob(dbPath + ".corrupt-*")
	var remaining []string
	for _, m := range bases {
		if strings.HasSuffix(m, "-wal") || strings.HasSuffix(m, "-shm") {
			continue
		}
		remaining = append(remaining, m)
	}
	if len(remaining) != keepCorruptQuarantines {
		t.Fatalf("want %d quarantine sets after prune, got %d: %v",
			keepCorruptQuarantines, len(remaining), remaining)
	}

	// The just-created quarantine must survive, and its sidecars too.
	if !auditFileExists(quarantinedPath) {
		t.Fatalf("just-created quarantine must not be pruned: %s", quarantinedPath)
	}

	// The two OLDEST seeded sets (1000, 1001) and their sidecars must be gone.
	for _, ts := range []int64{1000, 1001} {
		base := fmt.Sprintf("%s.corrupt-%d", dbPath, ts)
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if auditFileExists(p) {
				t.Fatalf("stale quarantine file must be pruned, still present: %s", p)
			}
		}
	}
	// The two NEWEST seeded sets (1002, 1003) must survive with their sidecars.
	for _, ts := range []int64{1002, 1003} {
		base := fmt.Sprintf("%s.corrupt-%d", dbPath, ts)
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if !auditFileExists(p) {
				t.Fatalf("recent quarantine file must survive prune, missing: %s", p)
			}
		}
	}
}

// TestAuditOpenResilientHappyPath verifies a healthy (or absent) db opens
// without quarantine.
func TestAuditOpenResilientHappyPath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	a, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer a.Close()
	if recovered {
		t.Fatal("healthy db must not trigger recovery")
	}
	if quarantinedPath != "" {
		t.Fatalf("healthy db must not report a quarantine path, got %q", quarantinedPath)
	}
}

// TestAuditOpenResilientDoesNotQuarantineOnTransientError verifies that a NON-
// corruption open failure (permission-denied parent dir → SQLITE_CANTOPEN) is
// returned as an error WITHOUT quarantining the chain, so a witnessed audit
// history is never abandoned over a transient disk/permission blip (finding
// offline-3, sharing the offline-1 corruption gate).
func TestAuditOpenResilientDoesNotQuarantineOnTransientError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	dbPath := filepath.Join(locked, "audit.db")

	a, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err == nil {
		if a != nil {
			a.Close()
		}
		t.Fatal("expected a transient open error, got nil")
	}
	if recovered {
		t.Fatal("a transient (permission-denied) failure must NOT trigger recovery")
	}
	if quarantinedPath != "" {
		t.Fatalf("a transient failure must not quarantine, got path %q", quarantinedPath)
	}
}

// corruptMiddlePage overwrites a couple of DATA pages in the middle of a SQLite
// file with 0xFF garbage — leaving page 1 (the schema) intact so the damage
// surfaces LAZILY on a full-table read, not at schema-open time.  An empirical
// check (modernc.org/sqlite v1.53) confirms a mid-file 0xFF page yields
// SQLITE_CORRUPT during iteration, exactly the torn-page case OpenResilient's
// lazy VerifyChain check recovers from.
func corruptMiddlePage(t *testing.T, dbPath string) {
	t.Helper()
	const pageSize = 4096
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	pages := info.Size() / pageSize
	if pages < 6 {
		t.Fatalf("db too small to corrupt a middle page (%d pages); grow the seed", pages)
	}
	f, err := os.OpenFile(dbPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open db for corruption: %v", err)
	}
	defer f.Close()
	garbage := make([]byte, pageSize)
	for i := range garbage {
		garbage[i] = 0xFF
	}
	mid := pages / 2
	for _, p := range []int64{mid, mid + 1} {
		if _, err := f.WriteAt(garbage, p*pageSize); err != nil {
			t.Fatalf("corrupt page %d: %v", p, err)
		}
	}
}

// TestAuditOpenResilientRecoversFromLazyPageCorruption verifies that a
// CORRUPTION-class VerifyChain failure discovered at open — a torn DATA page in
// audit_log that CREATE TABLE IF NOT EXISTS never touched, so it only surfaces
// when VerifyChain scans the whole table — drives the same quarantine-and-
// recreate recovery as an open-time corruption (finding offline-2).
func TestAuditOpenResilientRecoversFromLazyPageCorruption(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	// Build a VALID chain of MANY SMALL rows so audit_log becomes a multi-page
	// b-tree of packed leaf pages (rows stay in-page — no overflow pages, which
	// would only garble cell CONTENT silently rather than break b-tree
	// structure), then close cleanly so the WAL is checkpointed into the main
	// file.  ~500 rows of a few hundred bytes each spans dozens of 4 KiB pages.
	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	detail := strings.Repeat("x", 200) // small enough to avoid overflow pages
	for i := 0; i < 500; i++ {
		if err := a.Log("scan.completed", detail); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	if verr := a.VerifyChain(); verr != nil {
		t.Fatalf("pre-corruption chain must verify clean: %v", verr)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	corruptMiddlePage(t, dbPath)

	a, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer a.Close()
	if !recovered {
		t.Fatal("a lazily-discovered data-page corruption must be quarantined + recreated")
	}
	if quarantinedPath == "" {
		t.Fatal("expected a non-empty quarantinedPath")
	}
	if _, statErr := os.Stat(quarantinedPath); statErr != nil {
		t.Fatalf("corrupt file should be preserved at %s: %v", quarantinedPath, statErr)
	}
	// The fresh chain verifies clean and begins with the recreate marker.
	if verr := a.VerifyChain(); verr != nil {
		t.Fatalf("fresh chain must verify clean: %v", verr)
	}
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(entries) == 0 || entries[0]["event_type"] != "audit.recreated" {
		t.Fatalf("fresh chain must begin with audit.recreated, got %+v", entries)
	}
}

// TestAuditOpenResilientDoesNotQuarantineTamperedButReadableChain verifies the
// other half of the offline-2 distinction: a broken hash chain on INTACT pages
// (a mismatch VerifyChain reports as a plain error, NOT a *sqlite.Error) must be
// left in place — logged only, never quarantined — because quarantining a
// readable tampered chain would destroy the very tamper evidence VerifyChain
// exists to surface.
func TestAuditOpenResilientDoesNotQuarantineTamperedButReadableChain(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	a, err := NewAuditLog(dbPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	if err := a.Log("scan.started", "hostname=h1"); err != nil {
		t.Fatalf("Log genesis: %v", err)
	}
	if err := a.Log("scan.completed", "packages=1"); err != nil {
		t.Fatalf("Log second: %v", err)
	}
	// Break the chain on INTACT pages: INSERT a row whose prev_hash does NOT match
	// the current head's content_hash.  INSERT is allowed by the append-only
	// triggers (only UPDATE/DELETE are blocked), so this produces a genuine,
	// readable chain-linkage mismatch rather than an unreadable page.
	if _, err := a.db.Exec(
		"INSERT INTO audit_log (event_type, detail, content_hash, prev_hash, created_at, hash_version) VALUES (?, ?, ?, ?, ?, ?)",
		"scan.completed", "packages=2", "deadbeef", "not-the-prior-hash",
		time.Now().UTC().Format(time.RFC3339Nano), 2,
	); err != nil {
		t.Fatalf("insert tampered row: %v", err)
	}
	// The chain is now broken with a NON-corruption error.
	verr := a.VerifyChain()
	if verr == nil {
		t.Fatal("expected a broken-chain error after tampering")
	}
	if dbhealth.IsCorruption(verr) {
		t.Fatalf("a chain mismatch must NOT classify as corruption: %v", verr)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	a2, recovered, quarantinedPath, err := OpenResilient(dbPath)
	if err != nil {
		t.Fatalf("OpenResilient: %v", err)
	}
	defer a2.Close()
	if recovered {
		t.Fatal("a readable tampered chain must NOT be quarantined (that would destroy tamper evidence)")
	}
	if quarantinedPath != "" {
		t.Fatalf("no quarantine expected for a tampered-but-readable chain, got %q", quarantinedPath)
	}
	// No .corrupt-* file may have been created.
	corrupt, _ := filepath.Glob(filepath.Join(dir, "*.corrupt-*"))
	if len(corrupt) != 0 {
		t.Fatalf("no quarantine file expected, found %v", corrupt)
	}
	// The tampered row must still be present — the evidence is preserved.
	verr2 := a2.VerifyChain()
	if verr2 == nil {
		t.Fatal("tampered chain must remain broken (evidence preserved), but it verified clean")
	}
	if dbhealth.IsCorruption(verr2) {
		t.Fatalf("reopened chain must still be a mismatch, not corruption: %v", verr2)
	}
}
