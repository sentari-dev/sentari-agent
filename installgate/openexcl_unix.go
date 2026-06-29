//go:build !windows

// openExclNoFollow POSIX implementation.
//
// The install-gate writers create their atomic-replace temp file in
// the SAME directory as the final config — a world-writable location
// (pip / npm / Maven config dirs are 0755 by design) where a local
// attacker can pre-plant inodes.  Opening that temp path with plain
// O_CREATE|O_WRONLY|O_TRUNC let an attacker plant a symlink to a
// root-owned file and have the root-running agent truncate+overwrite
// the target (local privilege escalation).
//
// O_EXCL refuses to open if the path already names an inode (regular
// file, dir, or symlink) — combined with O_CREATE the open succeeds
// only when WE create a brand-new inode.  O_NOFOLLOW is belt-and-
// suspenders: even in the impossible-with-O_EXCL case of a symlink
// leaf, the kernel returns ELOOP rather than following it.
package installgate

import (
	"os"
	"syscall"
)

func openExclNoFollow(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
}
