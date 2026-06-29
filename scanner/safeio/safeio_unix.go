//go:build unix

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
// O_NOFOLLOW only refuses a *leaf* symlink.  Directory components in
// the path are resolved through any symlinks that exist — a fully
// resolved-beneath variant would require openat2(RESOLVE_NO_SYMLINKS)
// on Linux 5.6+.  See package doc for the threat-model discussion.
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
