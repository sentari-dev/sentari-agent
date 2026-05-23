//go:build windows

// openExclNoFollow Windows implementation.
//
// Windows has no O_NOFOLLOW flag (the syscall package doesn't define
// one and CreateFile's symlink semantics differ from POSIX), so we
// rely on O_EXCL alone.  O_CREATE|O_EXCL fails if the path already
// exists — including if it's a reparse-point/symlink — which is the
// property we need: the agent only ever writes through an inode it
// just created itself, never one a local attacker pre-planted.
package installgate

import "os"

func openExclNoFollow(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
}
