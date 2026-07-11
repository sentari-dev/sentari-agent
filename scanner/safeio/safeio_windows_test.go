//go:build windows

package safeio

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mustMakeJunction creates a DIRECTORY JUNCTION (an NTFS mount-point
// reparse point) at link pointing to target.
//
// Why a junction and not os.Symlink: creating a symbolic link on Windows
// requires SeCreateSymbolicLinkPrivilege (granted only to admins, or to
// any user when Developer Mode is ON).  GitHub's `windows-latest` runners
// have Developer Mode OFF and run the job unprivileged, so the symlink
// tests below t.Skip there — meaning the reparse-point refusal, the
// PRIMARY Windows symlink-escape defense, was never actually exercised in
// CI.  A directory junction is ALSO a reparse point
// (FILE_ATTRIBUTE_REPARSE_POINT), which is exactly what openNoFollow's
// handle check keys on — but unlike a symlink it needs NO special
// privilege, so an unprivileged runner can create one.  That makes the
// refusal path testable for real on stock CI.
//
// The junction is created via `cmd /c mklink /J`.  Exec is deliberately
// confined to TEST code (the agent's data-read path never shells out);
// `mklink` is a cmd.exe builtin so it must run through `cmd /c`.  We
// prefer this over a pure-Go DeviceIoControl(FSCTL_SET_REPARSE_POINT)
// fixture because the mount-point reparse buffer has a fiddly byte layout
// that cannot be runtime-verified from a non-Windows dev box (only
// `GOOS=windows go vet` compile-checks it), whereas mklink /J is a
// battle-tested primitive guaranteed to produce a valid reparse point.
func mustMakeJunction(t *testing.T, link, target string) {
	t.Helper()
	cmd := exec.Command("cmd", "/c", "mklink", "/J", link, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create junction %s -> %s: %v (%s)", link, target, err, out)
	}
}

// TestOpenNoFollow_RegularFile_Windows: a plain regular file opens
// successfully and its bytes are readable — the reparse-point guard
// must not reject ordinary files.
func TestOpenNoFollow_RegularFile_Windows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := openNoFollow(p)
	if err != nil {
		t.Fatalf("openNoFollow on a regular file: %v", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("expected a regular file, got mode %v", info.Mode())
	}

	buf := make([]byte, 5)
	n, _ := f.Read(buf)
	if got := string(buf[:n]); got != "hello" {
		t.Errorf("content: got %q want %q", got, "hello")
	}
}

// TestOpenNoFollow_Symlink_Windows: a symbolic link (reparse point)
// at the leaf is refused with ErrSymlink rather than followed to its
// target.  Creating a symlink on Windows needs the
// SeCreateSymbolicLink privilege (or Developer Mode); the test skips
// when that is unavailable, but the compile path is still exercised
// via `GOOS=windows go vet`.
func TestOpenNoFollow_Symlink_Windows(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink on this host (privilege required): %v", err)
	}

	if _, err := openNoFollow(link); !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink for a reparse-point leaf; got %v", err)
	}
}

// TestOpenNoFollowDir_RegularDir_Windows: a real directory opens via the
// reparse-refusing handle and enumerates through ReadDir — the reparse
// guard must not reject an ordinary directory.
func TestOpenNoFollowDir_RegularDir_Windows(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "child"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := openNoFollowDir(dir)
	if err != nil {
		t.Fatalf("openNoFollowDir on a regular directory: %v", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected a directory, got mode %v", info.Mode())
	}
}

// TestOpenNoFollowDir_Symlink_Windows: a reparse-point (symlink/junction)
// directory at the leaf is refused with ErrSymlink rather than followed.
// Creating a symlink on Windows needs privilege; the test skips when
// unavailable but the compile path is exercised via GOOS=windows go vet.
func TestOpenNoFollowDir_Symlink_Windows(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("cannot create symlink on this host (privilege required): %v", err)
	}

	if _, err := openNoFollowDir(link); !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink for a reparse-point directory leaf; got %v", err)
	}
}

// TestOpenNoFollow_Junction_Windows: openNoFollow must refuse ANY
// reparse-point leaf, junctions included.  Unlike the symlink test above
// this needs no privilege, so it actually RUNS on stock windows-latest
// CI — making it the test that genuinely verifies the reparse-point
// refusal.  A junction always targets a directory; openNoFollow opens it
// with FILE_FLAG_BACKUP_SEMANTICS and, seeing FILE_ATTRIBUTE_REPARSE_POINT
// on the handle, must refuse with ErrSymlink rather than resolve to the
// target.
func TestOpenNoFollow_Junction_Windows(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(dir, "junction")
	mustMakeJunction(t, link, target)

	if _, err := openNoFollow(link); !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink for a junction (reparse-point) leaf; got %v", err)
	}
}

// TestOpenNoFollowDir_Junction_Windows: the ReadDir-side entry point must
// likewise refuse a directory junction with ErrSymlink instead of
// enumerating the target's contents.  Runs unprivileged on CI (see
// mustMakeJunction), so the directory reparse-point refusal is verified
// for real rather than skipped.
func TestOpenNoFollowDir_Junction_Windows(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	// Prove the junction would otherwise resolve to real content, so the
	// refusal is meaningful and not just an empty-dir artifact.
	if err := os.WriteFile(filepath.Join(target, "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write inside target: %v", err)
	}
	link := filepath.Join(dir, "junction")
	mustMakeJunction(t, link, target)

	if _, err := openNoFollowDir(link); !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink for a junction (reparse-point) directory leaf; got %v", err)
	}
}
