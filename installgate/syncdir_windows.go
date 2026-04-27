//go:build windows

// syncDir Windows stub.
//
// NTFS metadata updates are durable as soon as ``os.Rename``
// returns — Windows does not expose a directory-fsync primitive
// equivalent to POSIX ``fsync(dirfd)``.  Returning nil here keeps
// the caller's "best-effort durability" semantics consistent
// across platforms without false-failing on every Windows apply.

package installgate

func syncDir(_ string) error { return nil }
