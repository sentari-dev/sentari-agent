//go:build !windows

// syncDir POSIX implementation.
//
// On ext4 / xfs / btrfs, an atomic-replace's ``os.Rename`` only
// updates the parent directory's metadata in the page cache; a
// power-cut before the journal flushes loses the rename even
// though the file's data was fsynced.  Calling ``Sync`` on the
// directory's file descriptor is the documented way to make the
// metadata change durable.
//
// Best-effort — operators may run the agent on filesystems where
// directory fsync is unsupported (some FUSE backends, in-memory
// tmpfs).  The caller treats a non-nil error as warning-level.

package installgate

import "os"

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
