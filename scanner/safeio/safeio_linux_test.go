//go:build linux

package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// openat2Available reports whether the running kernel honours
// openat2(2).  On pre-5.6 kernels the syscall returns ENOSYS; a
// seccomp filter that has not allow-listed it typically returns EPERM.
// Tests that exercise the openat2-only guarantee skip when it is
// unavailable so they still compile and pass everywhere while only
// asserting the stronger behaviour where the kernel can deliver it.
func openat2Available(t *testing.T) bool {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "openat2probe")
	if err != nil {
		t.Fatalf("probe temp file: %v", err)
	}
	name := f.Name()
	_ = f.Close()

	how := &unix.OpenHow{Flags: uint64(os.O_RDONLY), Resolve: unix.RESOLVE_NO_SYMLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, name, how)
	if err == nil {
		_ = unix.Close(fd)
		return true
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		return false
	}
	// Any other error means openat2 itself is present (it reached the
	// resolver and objected to something else), so treat it as available.
	return true
}

// TestOpenNoFollow_IntermediateSymlinkRefused is the core anti-exfil
// guarantee that openat2 adds over O_NOFOLLOW: a file reached through a
// symlinked *intermediate directory* must be refused.  This is skipped
// on kernels without openat2, where the leaf-only fallback cannot catch
// it (documented residual).
func TestOpenNoFollow_IntermediateSymlinkRefused(t *testing.T) {
	if !openat2Available(t) {
		t.Skip("kernel lacks openat2 (RESOLVE_NO_SYMLINKS); intermediate-dir refusal is openat2-only")
	}

	root := t.TempDir()
	realDir := filepath.Join(root, "realdir")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir realdir: %v", err)
	}
	secret := filepath.Join(realDir, "secret")
	if err := os.WriteFile(secret, []byte("top secret"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	// linkdir -> realdir; reaching secret through linkdir traverses a
	// symlinked intermediate component.
	linkDir := filepath.Join(root, "linkdir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink linkdir: %v", err)
	}

	viaLink := filepath.Join(linkDir, "secret")
	f, err := openNoFollow(viaLink)
	if err == nil {
		_ = f.Close()
		t.Fatalf("openNoFollow(%q) succeeded through a symlinked intermediate dir; want ErrSymlink", viaLink)
	}
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("openNoFollow(%q) err = %v; want ErrSymlink", viaLink, err)
	}
}

// TestReadDir_IntermediateSymlinkRefused is the directory analogue of
// TestOpenNoFollow_IntermediateSymlinkRefused: enumerating a directory
// reached through a symlinked INTERMEDIATE component must be refused on
// openat2 kernels (RESOLVE_NO_SYMLINKS).  Skipped where openat2 is
// unavailable, since the leaf-only fallback cannot catch it (documented
// residual on the fallback path).
func TestReadDir_IntermediateSymlinkRefused(t *testing.T) {
	if !openat2Available(t) {
		t.Skip("kernel lacks openat2 (RESOLVE_NO_SYMLINKS); intermediate-dir refusal is openat2-only")
	}

	root := t.TempDir()
	realDir := filepath.Join(root, "realdir")
	inner := filepath.Join(realDir, "versions")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatalf("mkdir inner: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inner, "1.0.0"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	// linkdir -> realdir; enumerating linkdir/versions traverses a
	// symlinked intermediate component.
	linkDir := filepath.Join(root, "linkdir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink linkdir: %v", err)
	}

	viaLink := filepath.Join(linkDir, "versions")
	entries, err := ReadDir(viaLink)
	if err == nil {
		t.Fatalf("ReadDir(%q) succeeded through a symlinked intermediate dir (%d entries); want ErrSymlink", viaLink, len(entries))
	}
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("ReadDir(%q) err = %v; want ErrSymlink", viaLink, err)
	}
}

// TestOpenNoFollowDir_NormalDirOpens guards the openat2 directory path
// against an overzealous refusal: a plain directory with no symlink in
// its path must open and enumerate.
func TestOpenNoFollowDir_NormalDirOpens(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	f, err := openNoFollowDir(sub)
	if err != nil {
		t.Fatalf("openNoFollowDir(%q) = %v; want success", sub, err)
	}
	_ = f.Close()
}

// TestOpenNoFollow_NormalFileOpens guards against an overzealous
// refusal breaking every read: a plain file with no symlink anywhere in
// its path must open and read back unchanged.  Runs on both the openat2
// and fallback paths.
func TestOpenNoFollow_NormalFileOpens(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "plain.txt")
	want := []byte("hello world")
	if err := os.WriteFile(p, want, 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	f, err := openNoFollow(p)
	if err != nil {
		t.Fatalf("openNoFollow(%q) = %v; want success", p, err)
	}
	defer f.Close()

	got := make([]byte, len(want))
	n, err := f.Read(got)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got[:n]) != string(want) {
		t.Fatalf("read %q; want %q", got[:n], want)
	}
}

// TestOpenNoFollow_LeafSymlinkRefused is the guarantee both branches
// share: a symlink at the leaf is refused with ErrSymlink whether we go
// through openat2 (RESOLVE_NO_SYMLINKS) or the O_NOFOLLOW fallback.
func TestOpenNoFollow_LeafSymlinkRefused(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "leaflink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink leaflink: %v", err)
	}

	f, err := openNoFollow(link)
	if err == nil {
		_ = f.Close()
		t.Fatalf("openNoFollow(%q) followed a leaf symlink; want ErrSymlink", link)
	}
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("openNoFollow(%q) err = %v; want ErrSymlink", link, err)
	}
}
