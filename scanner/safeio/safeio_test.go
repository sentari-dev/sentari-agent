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
// some platforms; the Stat-based ``IsDir`` check must still reject.
func TestReadFile_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadFile(dir, 1024)
	if err == nil {
		t.Error("reading a directory must fail")
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
