//go:build linux

package pathfilter

import "golang.org/x/sys/unix"

// linuxNetworkMagic lists the ``Statfs.Type`` magic numbers that
// indicate a network filesystem on Linux.
//
// Source: linux/include/uapi/linux/magic.h (cross-checked against
// fs/<fstype>/super.c for each entry).  Lowercase comments name the
// kernel macro so a reader can map each constant back to the header
// without re-deriving the magic byte-for-byte.
//
// Filesystems intentionally NOT in this list:
//   - SQUASHFS (0x73717368): read-only image, often network-staged but
//     local at scan time; treating it as network would block valid
//     container-image scans.
//   - TMPFS (0x01021994): local RAM-backed; not network.
//   - OPENPROMFS, PROCFS, SYSFS, CGROUPFS: kernel virtual FS; skipped
//     by depth-cap + already irrelevant to runtime discovery.
var linuxNetworkMagic = map[int64]struct{}{
	0x6969:     {}, // NFS_SUPER_MAGIC
	0xff534d42: {}, // CIFS_SUPER_MAGIC / SMB2_SUPER_MAGIC (same value)
	0x517b:     {}, // SMB_SUPER_MAGIC (older smbfs, pre-CIFS)
	0x5346414f: {}, // AFS_SUPER_MAGIC
	0x6b414653: {}, // AFS_FS_MAGIC (kafs)
	0x0187:     {}, // AUTOFS_SUPER_MAGIC
	0x65735546: {}, // FUSE_SUPER_MAGIC — sshfs, rclone, s3fs, restic, davfs2, ...
	0x01021997: {}, // V9FS_MAGIC (9P, used by container-host bridges)
	0x73757245: {}, // CODA_SUPER_MAGIC
	0x564c:     {}, // NCP_SUPER_MAGIC (legacy Novell)
}

// IsNetworkFilesystem reports whether path lives on a Linux network
// mount.  Errors from statfs (path missing, EACCES) return
// (false, err); the runtime walkers treat any error as "scan it" to
// preserve coverage on quirky hosts.
func IsNetworkFilesystem(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, err
	}
	_, isNetwork := linuxNetworkMagic[int64(stat.Type)]
	return isNetwork, nil
}
