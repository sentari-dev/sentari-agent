package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestReadFileWithMTime_HappyPath: a regular file under the cap must
// be readable unchanged AND report the file's mtime derived from the
// same fd.  Guards the primary use case (install-date proxy stamping).
func TestReadFileWithMTime_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	body := []byte(`{"mcpServers":{}}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// Pin a known mtime so the assertion is deterministic.
	want := time.Date(2021, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, want, want); err != nil {
		t.Fatal(err)
	}

	got, mtime, err := ReadFileWithMTime(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content mismatch: got %q, want %q", got, body)
	}
	if !mtime.Equal(want) {
		t.Errorf("mtime mismatch: got %v, want %v", mtime, want)
	}
	if mtime.Location() != time.UTC {
		t.Errorf("mtime must be UTC-normalised, got location %v", mtime.Location())
	}
}

// TestReadFileWithMTime_SymlinkRefused: the core red-team case — a
// symlinked manifest pointing at a secret must be refused, not
// dereferenced, and must leak neither bytes nor a real mtime.
func TestReadFileWithMTime_SymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation on Windows requires admin; covered by the Lstat-based impl")
	}
	dir := t.TempDir()

	target := filepath.Join(dir, "sensitive.txt")
	if err := os.WriteFile(target, []byte("SECRET_PASSWORD_HASH"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "mcp.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	data, mtime, err := ReadFileWithMTime(link, 1024)
	if err == nil {
		t.Fatalf("expected ErrSymlink, got data: %q", data)
	}
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink, got %v", err)
	}
	if strings.Contains(string(data), "SECRET") {
		t.Errorf("symlink target leaked into returned data: %q", data)
	}
	if !mtime.IsZero() {
		t.Errorf("refused read must return a zero mtime, got %v", mtime)
	}
}

// TestReadFileWithMTime_OversizedRefused: a file larger than the cap
// must be rejected with ErrTooLarge and return zero bytes — no
// truncated head of a parser bomb.
func TestReadFileWithMTime_OversizedRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(path, make([]byte, 2048), 0o600); err != nil {
		t.Fatal(err)
	}

	data, _, err := ReadFileWithMTime(path, 1024)
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

// TestReadFileWithMTime_NonPositiveSizeRejected: passing 0 or a
// negative cap must return ErrTooLarge before opening the file.
func TestReadFileWithMTime_NonPositiveSizeRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anything.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, size := range []int64{0, -1} {
		if _, _, err := ReadFileWithMTime(path, size); !errors.Is(err, ErrTooLarge) {
			t.Errorf("ReadFileWithMTime(size=%d) = %v, want ErrTooLarge", size, err)
		}
	}
}

// TestReadFileWithMTime_MissingFile: os.ErrNotExist must pass through
// unwrapped so callers can distinguish "not installed" (silent skip)
// from "refused to read".  This is the aiagents mcp.go / ide.go
// isNotExist branch.
func TestReadFileWithMTime_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ReadFileWithMTime(filepath.Join(dir, "nope.txt"), 1024)
	if err == nil || errors.Is(err, ErrSymlink) || errors.Is(err, ErrTooLarge) {
		t.Errorf("missing-file error must be neither ErrSymlink nor ErrTooLarge: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected errors.Is(err, os.ErrNotExist), got %v", err)
	}
}

// TestReadFileWithMTime_DirectoryRejected: a directory must be
// refused with ErrNotRegular (mirroring ReadFile), not read as an
// empty file.
func TestReadFileWithMTime_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, _, err := ReadFileWithMTime(dir, 1024)
	if err == nil {
		t.Fatal("reading a directory must fail")
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Errorf("expected ErrNotRegular for a directory, got %v", err)
	}
}
