package installgate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedTime keeps the embedded marker timestamp + backup filename
// reproducible across test runs.
var fixedTime = time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)

func newOpts(path string, content []byte) WriteOptions {
	return WriteOptions{
		Path:     path,
		Content:  content,
		FileMode: 0o644,
		Now:      fixedTime,
	}
}

// --- WriteAtomic -------------------------------------------------------

func TestWriteAtomic_FreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	changed, err := WriteAtomic(newOpts(path, []byte("hello\n")))
	if err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on fresh write")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("readback: got %q, want %q", got, "hello\n")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("mode: got %v, want 0644", mode)
	}
}

func TestWriteAtomic_IdempotentNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	if _, err := WriteAtomic(newOpts(path, []byte("same\n"))); err != nil {
		t.Fatal(err)
	}

	// Second write with the same bytes — must report no change and
	// must NOT create a backup file (idempotent re-write is the
	// every-scan-cycle path; producing a backup-per-scan would
	// fill the filesystem).
	changed, err := WriteAtomic(newOpts(path, []byte("same\n")))
	if err != nil {
		t.Fatalf("WriteAtomic round-2: %v", err)
	}
	if changed {
		t.Error("expected changed=false on identical re-write")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "sentari-backup") {
			t.Errorf("idempotent re-write created backup: %s", e.Name())
		}
	}
}

func TestWriteAtomic_BackupOnFirstOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")

	// Pre-existing operator-curated config (not Sentari-managed).
	if err := os.WriteFile(path, []byte("operator-curated\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// First Sentari write must back up the operator content before
	// overwriting.
	changed, err := WriteAtomic(newOpts(path, []byte("sentari-managed\n")))
	if err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on first overwrite")
	}

	// Backup name is deterministic given fixedTime.
	backup := path + ".sentari-backup-2026-04-25T10-00-00Z"
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if string(got) != "operator-curated\n" {
		t.Errorf("backup content mismatch: %q", got)
	}
}

func TestWriteAtomic_NoBackupBackup(t *testing.T) {
	// Backup-of-a-backup regression guard: when the agent rewrites
	// an already-Sentari-managed file to a *new* version, the
	// idempotency check skips and we re-run the backup branch.
	// Two Sentari versions in a row WOULD produce two backups —
	// once on the operator->v1 transition, once on v1->v2.  That's
	// expected and matches the design doc.  But re-running the
	// SAME write twice (two scan cycles, no policy change) must
	// not.  Already exercised by TestWriteAtomic_IdempotentNoOp;
	// this one tightens the assertion: the *.tmp file from a
	// previous failed run must not survive into the next call.
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	tmp := path + ".sentari-tmp"

	// Strand a tmp file from a "previous failed run".
	if err := os.WriteFile(tmp, []byte("partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteAtomic(newOpts(path, []byte("clean\n"))); err != nil {
		t.Fatalf("WriteAtomic over stranded tmp: %v", err)
	}

	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf(".sentari-tmp survived: stat err=%v", err)
	}
}

func TestWriteAtomic_RejectsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	oversize := make([]byte, MaxConfigFileBytes+1)
	if _, err := WriteAtomic(newOpts(path, oversize)); err == nil {
		t.Fatal("expected error on oversize content")
	}
	// And the file must NOT have been created — one of the
	// invariants is "no half-rendered config on the host".
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("oversize content created file anyway: stat err=%v", err)
	}
}

func TestWriteAtomic_RejectsEmptyPath(t *testing.T) {
	if _, err := WriteAtomic(WriteOptions{Content: []byte("x")}); err == nil {
		t.Error("expected error on empty path")
	}
}

func TestWriteAtomic_CreatesParentDir(t *testing.T) {
	// Fresh user host: ``~/.config/pip/`` doesn't exist yet.  The
	// writer must create it (mode 0755 so debug tooling running as
	// the same user can inspect).
	dir := t.TempDir()
	path := filepath.Join(dir, "deep", "nested", "pip.conf")
	if _, err := WriteAtomic(newOpts(path, []byte("x"))); err != nil {
		t.Fatalf("WriteAtomic into deep path: %v", err)
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Errorf("parent not a dir: %v", info)
	}
}

func TestWriteAtomic_PreservesBackupOnSecondSecondCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	if err := os.WriteFile(path, []byte("operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Two writes in the same logical second produce the same
	// backup destination.  The second must NOT clobber the first
	// — the operator's pre-Sentari content has to survive even if
	// the agent does two writes back-to-back during a re-config.
	if _, err := WriteAtomic(newOpts(path, []byte("v1\n"))); err != nil {
		t.Fatal(err)
	}
	// Manually re-create the original to exercise the second-write
	// branch (our backup helper preserves an existing destination).
	if err := os.WriteFile(path, []byte("operator-restored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteAtomic(newOpts(path, []byte("v2\n"))); err != nil {
		t.Fatal(err)
	}

	backup := path + ".sentari-backup-2026-04-25T10-00-00Z"
	got, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	// First-write backup is preserved (operator content), not
	// clobbered by the manual restore that preceded the v2 write.
	if string(got) != "operator\n" {
		t.Errorf("backup overwritten: got %q, want %q", got, "operator\n")
	}
}

// --- Remove ------------------------------------------------------------

func TestRemove_Existing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err := Remove(path)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Error("expected removed=true")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still exists after Remove: %v", err)
	}
}

func TestRemove_Missing(t *testing.T) {
	removed, err := Remove(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil {
		t.Errorf("missing-file Remove returned error: %v", err)
	}
	if removed {
		t.Error("expected removed=false when file did not exist")
	}
}

func TestRemove_EmptyPath(t *testing.T) {
	if _, err := Remove(""); err == nil {
		t.Error("expected error on empty path")
	}
}

// --- renderHashMarker --------------------------------------------------

func TestRenderHashMarker_Format(t *testing.T) {
	got := renderHashMarker(MarkerFields{
		Version: 1730901234,
		KeyID:   "primary",
		Applied: fixedTime,
	})
	want := strings.Join([]string{
		"# Managed by Sentari (version=1730901234, signed=primary, applied=2026-04-25T10:00:00Z)",
		"# Do not edit manually — changes are overwritten on the next policy sync.",
		"",
	}, "\n")
	if got != want {
		t.Errorf("marker mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

// --- error-typing sanity ----------------------------------------------

// WriteAtomic wraps the underlying os errors via fmt.Errorf("%w").
// This regression-guards the wrapping behaviour so callers can use
// errors.Is(err, fs.ErrPermission) etc. without surprises.
func TestWriteAtomic_ErrorWrapping(t *testing.T) {
	// Read-only parent → mkdir fails with EACCES on POSIX.
	if os.Getuid() == 0 {
		t.Skip("skipped: root bypasses POSIX dir permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755) // best-effort cleanup so t.TempDir can remove

	path := filepath.Join(dir, "newdir", "pip.conf")
	_, err := WriteAtomic(newOpts(path, []byte("x")))
	if err == nil {
		t.Fatal("expected error writing into read-only parent")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("expected wrapped fs.ErrPermission, got: %v", err)
	}
}
