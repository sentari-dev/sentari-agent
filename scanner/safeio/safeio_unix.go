//go:build unix && !linux

package safeio

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path read-only with O_NOFOLLOW.  If the leaf is a
// symbolic link the kernel returns ELOOP (Linux) or EMLINK on older
// BSD; we normalise both to ErrSymlink so callers can test it.
//
// This file is the non-Linux unix path — darwin and the *BSDs, which
// have no openat2(2).  Linux gets a stronger primitive in
// safeio_linux.go (openat2 with RESOLVE_NO_SYMLINKS refuses a symlink
// at ANY component) and only falls back to this same leaf-only
// behaviour on pre-5.6 kernels.
//
// Residual (leaf-only) — identical to the Windows sibling's documented
// residual: O_NOFOLLOW only refuses a *leaf* symlink.  Directory
// components in the path are resolved through any symlinks that exist,
// so a symlinked ancestor dir can still redirect the read outside the
// intended tree.  A fully resolved-beneath variant requires
// openat2(RESOLVE_NO_SYMLINKS), which these platforms do not provide.
// See package doc for the threat-model discussion.
func openNoFollow(path string) (*os.File, error) {
	// O_NONBLOCK so a blocking open() of a writer-less FIFO returns
	// immediately instead of hanging the scanner forever; the caller
	// then rejects any non-regular file via its fstat check.  On a
	// regular file O_NONBLOCK has no effect on read semantics.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		return f, nil
	}
	// ELOOP on symlink-leaf is the Linux / recent-BSD behaviour.
	// Older BSDs return EMLINK.  Both mean "you asked me not to
	// follow symlinks and the leaf was one."
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

// openNoFollowDir opens path for enumeration with O_NOFOLLOW.  It is the
// ReadDir analogue of openNoFollow on the non-Linux unix path (darwin,
// *BSD — no openat2).  A symlinked leaf yields ELOOP/EMLINK (→ ErrSymlink);
// O_NONBLOCK keeps a FIFO planted at the path from blocking the open.
//
// Deliberately NOT O_DIRECTORY: on macOS the O_DIRECTORY check precedes
// the O_NOFOLLOW check, so opening a *symlink* (whose target is a
// directory) fails ENOTDIR rather than ELOOP — which would misreport an
// attacker's symlink as a mere "not a directory" and lose the ErrSymlink
// signal callers audit on.  We therefore let O_NOFOLLOW deliver ELOOP for
// a symlinked leaf and defer the not-a-directory decision to ReadDir's
// fstat on the returned handle (the held-fd type check), so a plain file
// or FIFO at the path is still refused with ErrNotRegular.
//
// Residual (leaf-only) — identical to openNoFollow's: O_NOFOLLOW refuses
// only a symlinked leaf, so an ancestor directory symlink is still
// resolved.  Closing that needs openat2(RESOLVE_NO_SYMLINKS), which these
// platforms do not provide; Linux gets it in safeio_linux.go.
func openNoFollowDir(path string) (*os.File, error) {
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
