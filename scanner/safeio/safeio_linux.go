//go:build linux

package safeio

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openNoFollow opens path read-only while refusing to traverse any
// symbolic link, using the strongest primitive the running kernel
// offers.
//
// Primary (Linux 5.6+): openat2(2) with RESOLVE_NO_SYMLINKS.  Unlike
// O_NOFOLLOW — which only refuses a symlink at the *leaf* — this
// refuses a symlink at ANY path component.  A symlinked ancestor
// directory (e.g. /usr/share/doc/mypkg -> /etc) can therefore no
// longer redirect a bounded read outside the intended tree, closing
// the intermediate-directory anti-exfiltration gap that O_NOFOLLOW
// alone leaves open.  The kernel resolves and rejects atomically, so
// there is no per-component TOCTOU race for us to lose.
//
// Fallback: on kernels without openat2 the syscall returns ENOSYS; a
// seccomp filter that has not allow-listed openat2 typically returns
// EPERM (older container runtimes did this before openat2 was added to
// the default profile).  In either case we degrade to the leaf-only
// O_NOFOLLOW open below.
//
// Residual (fallback path only) — identical to the darwin/BSD path in
// safeio_unix.go and the Windows sibling's documented residual: the
// leaf-only O_NOFOLLOW open still resolves symlinked intermediate
// directory components.  A symlinked ancestor dir can redirect the
// read on such (pre-5.6 / openat2-blocked) kernels.  There is no
// non-race-prone way to close this without openat2, so we accept it
// only where openat2 is unavailable.
//
// Flags and returned *os.File semantics match the fallback exactly
// (O_RDONLY|O_NONBLOCK|O_CLOEXEC, name == path), so callers — and the
// hot ReadFile path — are unchanged regardless of which branch runs.
func openNoFollow(path string) (*os.File, error) {
	// O_NONBLOCK so a blocking open() of a writer-less FIFO returns
	// immediately instead of hanging the scanner; the caller's fstat
	// then rejects the non-regular file.  O_CLOEXEC to match the
	// close-on-exec that os.OpenFile sets for us on the fallback path.
	how := &unix.OpenHow{
		Flags:   uint64(os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err == nil {
		// Hand the validated fd to *os.File so the caller's shared
		// Stat/Read/Close path works unchanged; f.Close() closes this fd.
		return os.NewFile(uintptr(fd), path), nil
	}
	switch {
	case errors.Is(err, unix.ELOOP):
		// A symlink at some component — leaf OR an intermediate dir.
		// This is exactly what RESOLVE_NO_SYMLINKS is here to catch.
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPERM):
		// openat2 unavailable (pre-5.6 kernel) or blocked by seccomp.
		// Degrade to leaf-only O_NOFOLLOW.
		return openNoFollowLeaf(path)
	default:
		// A real error on the target itself (ENOENT, EACCES, …).
		return nil, err
	}
}

// openNoFollowLeaf is the pre-openat2 fallback: a leaf-only O_NOFOLLOW
// open, identical to the darwin/BSD openNoFollow in safeio_unix.go.  It
// refuses only a symlink at the leaf; see openNoFollow's residual note.
func openNoFollowLeaf(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		return f, nil
	}
	// ELOOP on a symlink leaf is the Linux behaviour; EMLINK is the
	// older-BSD spelling.  Both mean "you asked me not to follow
	// symlinks and the leaf was one."
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errno, ok := pathErr.Err.(syscall.Errno); ok {
			if errno == syscall.ELOOP || errno == syscall.EMLINK {
				return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
			}
		}
	}
	return nil, err
}

// openNoFollowDir opens path as a DIRECTORY for enumeration, refusing to
// traverse any symbolic link, using the same openat2-primary / O_NOFOLLOW-
// fallback strategy as openNoFollow.  It is the ReadDir analogue of the
// file open above; O_DIRECTORY makes the open itself reject a non-
// directory (ENOTDIR), and O_NONBLOCK keeps a FIFO planted at the path
// from blocking the open.  The returned *os.File is a directory handle;
// ReadDir fstats and enumerates it without a second path lookup.
//
// Primary (Linux 5.6+): openat2 with RESOLVE_NO_SYMLINKS refuses a
// symlink at ANY component — an ancestor symlink can no longer redirect
// the enumeration.  Fallback (ENOSYS/EPERM): leaf-only O_NOFOLLOW, whose
// residual (ancestor symlinks resolved) matches openNoFollow's.
func openNoFollowDir(path string) (*os.File, error) {
	how := &unix.OpenHow{
		Flags:   uint64(os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC | syscall.O_DIRECTORY),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err == nil {
		return os.NewFile(uintptr(fd), path), nil
	}
	switch {
	case errors.Is(err, unix.ELOOP):
		// A symlink at some component — leaf OR an intermediate dir.
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	case errors.Is(err, unix.ENOTDIR):
		// O_DIRECTORY rejected a non-directory target (file, FIFO, …).
		return nil, fmt.Errorf("%w: %s is not a directory", ErrNotRegular, path)
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPERM):
		// openat2 unavailable or seccomp-blocked; degrade to leaf-only.
		return openNoFollowDirLeaf(path)
	default:
		return nil, err
	}
}

// openNoFollowDirLeaf is the pre-openat2 directory fallback: a leaf-only
// O_NOFOLLOW open, identical to the darwin/BSD openNoFollowDir in
// safeio_unix.go.  Refuses only a symlink at the leaf.
//
// Deliberately NOT O_DIRECTORY (unlike the openat2 primary above): on
// some kernels/BSDs the O_DIRECTORY check can precede the O_NOFOLLOW
// symlink check, so a symlinked leaf would surface as ENOTDIR and lose
// the ErrSymlink signal.  We let O_NOFOLLOW deliver ELOOP for a symlink
// and defer the not-a-directory decision to ReadDir's fstat on the held
// fd — matching safeio_unix.go's non-Linux path exactly.
func openNoFollowDirLeaf(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		return f, nil
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if errno, ok := pathErr.Err.(syscall.Errno); ok {
			if errno == syscall.ELOOP || errno == syscall.EMLINK {
				return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
			}
		}
	}
	return nil, err
}
