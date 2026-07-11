package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReadFile_HappyPath: a regular file under the size cap must be
// readable unchanged.  Guards against an overzealous check that
// breaks all reads.
func TestReadFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "normal.txt")
	body := []byte("hello world")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadFile(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content mismatch: got %q, want %q", got, body)
	}
}

// TestReadFile_SymlinkRefused is the core red-team case: a malicious
// package installs /usr/share/doc/mypkg/copyright as a symlink to
// /etc/shadow; the scanner must refuse, not exfiltrate the target.
func TestReadFile_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation on Windows requires admin; covered by the Lstat-based impl")
	}
	dir := t.TempDir()

	target := filepath.Join(dir, "sensitive.txt")
	if err := os.WriteFile(target, []byte("SECRET_PASSWORD_HASH"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "copyright")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	data, err := ReadFile(link, 1024)
	if err == nil {
		t.Fatalf("expected ErrSymlink, got data: %q", data)
	}
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink, got %v", err)
	}
	// Pin: the sentinel text must NOT have leaked.  If a future
	// refactor returns partial data on the error path, this catches
	// it.
	if strings.Contains(string(data), "SECRET") {
		t.Errorf("symlink target leaked into returned data: %q", data)
	}
}

// TestReadFile_OversizedRefused: a file larger than the cap must be
// rejected and return *zero* bytes to the caller, never a truncated
// head — a malicious parser-bomb must not be half-ingested.
func TestReadFile_OversizedRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(path, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFile(path, 1024)
	if err == nil {
		t.Fatalf("expected ErrTooLarge, got %d bytes", len(data))
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("expected ErrTooLarge, got %v", err)
	}
	if len(data) != 0 {
		t.Errorf("oversized file leaked %d bytes; must return empty buffer", len(data))
	}
}

// TestReadFile_ExactSizeAllowed: file exactly equal to the cap must
// be accepted.  Off-by-one regression guard.
func TestReadFile_ExactSizeAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.bin")
	body := make([]byte, 1024)
	for i := range body {
		body[i] = 'A'
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadFile(path, 1024)
	if err != nil {
		t.Errorf("exact-size file rejected: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("got %d bytes, want 1024", len(got))
	}
}

// TestReadFile_NonPositiveSizeRejected: a caller passing 0 or
// negative must get a clean error, not a read that returns all zero
// bytes "correctly".
func TestReadFile_NonPositiveSizeRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anything.txt")
	os.WriteFile(path, []byte("x"), 0o600)

	for _, size := range []int64{0, -1} {
		if _, err := ReadFile(path, size); !errors.Is(err, ErrTooLarge) {
			t.Errorf("ReadFile(size=%d) = %v, want ErrTooLarge", size, err)
		}
	}
}

// TestReadFile_MissingFile: callers rely on the real os.PathError
// surfacing (for the "file absent" case) so ScanError paths can
// distinguish "not installed" from "refused to read".
func TestReadFile_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadFile(filepath.Join(dir, "nope.txt"), 1024)
	if err == nil || errors.Is(err, ErrSymlink) || errors.Is(err, ErrTooLarge) {
		t.Errorf("missing-file error must be neither ErrSymlink nor ErrTooLarge: %v", err)
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist, got %v", err)
	}
}

// TestReadFile_DirectoryRejected: Open on a directory succeeds on
// some platforms; the Stat-based `IsDir` check must still reject.
func TestReadFile_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadFile(dir, 1024)
	if err == nil {
		t.Error("reading a directory must fail")
	}
}

// TestReadDir_HappyPath: a real directory must be listed and its
// entries returned in name order.
func TestReadDir_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "aaa"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "bbb"), 0o755); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Name() != "aaa" || entries[1].Name() != "bbb" {
		t.Errorf("unexpected entry names: %q %q", entries[0].Name(), entries[1].Name())
	}
}

// TestReadDir_SymlinkDirRefused: a symlink to a directory must be
// refused.  This is the key security property — an attacker cannot
// install a version directory in ~/.m2 as a symlink pointing at
// /etc or another sensitive path.
func TestReadDir_SymlinkDirRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation on Windows requires admin; covered by Lstat-based impl")
	}
	outer := t.TempDir()
	realDir := filepath.Join(outer, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outer, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	entries, err := ReadDir(link)
	if err == nil {
		t.Fatalf("expected ErrSymlink, got %d entries", len(entries))
	}
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink, got %v", err)
	}
}

// TestReadDir_NotADirectory: pointing ReadDir at a regular file must be
// refused with ErrNotRegular — the fd-validated type check (unix
// O_DIRECTORY at open, plus the fstat on the held handle) must reject a
// non-directory so a FIFO/file planted where a version dir is expected
// cannot be enumerated as if it were a directory.
func TestReadDir_NotADirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(file, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := ReadDir(file)
	if err == nil {
		t.Fatalf("expected ErrNotRegular, got %d entries", len(entries))
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Errorf("expected ErrNotRegular, got %v", err)
	}
}

// TestReadDir_SymlinkToFileRefused: a symlink whose target is a regular
// file (not a directory) must still be refused as a symlink — the leaf is
// a symlink, so the refusal fires before the type check.
func TestReadDir_SymlinkToFileRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation on Windows requires admin")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	if _, err := ReadDir(link); !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink for a symlinked leaf, got %v", err)
	}
}

// TestReadDir_ManyEntriesSorted: (*os.File).ReadDir returns entries in
// directory order, so ReadDir must sort them by name to preserve the
// os.ReadDir contract callers rely on.  Uses enough entries that an
// unsorted directory order is overwhelmingly likely to differ from sorted.
func TestReadDir_ManyEntriesSorted(t *testing.T) {
	dir := t.TempDir()
	names := []string{"zeta", "alpha", "mike", "bravo", "yankee", "charlie"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != len(names) {
		t.Fatalf("expected %d entries, got %d", len(names), len(entries))
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name() > entries[i].Name() {
			t.Errorf("entries not sorted: %q before %q", entries[i-1].Name(), entries[i].Name())
		}
	}
}

// TestOpen_SymlinkRefused: the streaming Open path shares the same
// guarantee.  Dpkg status is read line-by-line via Open; it must
// refuse a symlinked status file too.
func TestOpen_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation on Windows requires admin")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	os.WriteFile(target, []byte("data"), 0o600)
	link := filepath.Join(dir, "status")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	f, err := Open(link)
	if f != nil {
		f.Close()
	}
	if err == nil || !errors.Is(err, ErrSymlink) {
		t.Errorf("Open on symlink must return ErrSymlink, got %v", err)
	}
}
