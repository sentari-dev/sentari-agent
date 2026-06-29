//go:build darwin

package pathfilter

import (
	"strings"

	"golang.org/x/sys/unix"
)

// networkFstypes lists the Statfs.Fstypename values that indicate a
// network filesystem on darwin.  The comparison is case-insensitive
// because macOS reports e.g. "nfs" but the kernel macros use "NFS";
// future macOS releases may flip the casing.
//
// Sources:
//   - <sys/mount.h> MNT_* defines
//   - mount(8) man page (FILESYSTEMS section)
//   - osxfuse / macfuse exposes ``fuse`` as the fstype
var networkFstypes = map[string]struct{}{
	"nfs":      {},
	"smbfs":    {},
	"cifs":     {},
	"afpfs":    {}, // legacy AppleTalk Filing Protocol
	"webdav":   {},
	"autofs":   {},
	"fuse":     {}, // covers sshfs, rclone, s3fs, restic, etc.
	"macfuse":  {},
	"osxfuse":  {},
	"acfs":     {}, // Xsan / acfs
	"nullfs":   {}, // sometimes wraps network mounts
}

// IsNetworkFilesystem reports whether path lives on a network mount.
// Errors from statfs (path missing, permission denied) return
// (false, err) so callers can decide whether to skip silently or
// surface; runtime walkers in this repo treat any error as "scan it"
// to preserve coverage on quirky hosts.
func IsNetworkFilesystem(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, err
	}
	// Fstypename is a fixed-size byte array on darwin; trim the
	// trailing NULs and lowercase before lookup.
	name := strings.ToLower(strings.Trim(nullTerminated(stat.Fstypename[:]), "\x00"))
	_, isNetwork := networkFstypes[name]
	return isNetwork, nil
}

// nullTerminated converts a fixed-size byte array (as Statfs uses for
// Fstypename on darwin) to a Go string, stopping at the first NUL.
// Inline so the package stays cgo-free.
func nullTerminated(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
