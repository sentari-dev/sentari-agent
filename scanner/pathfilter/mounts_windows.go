//go:build windows

package pathfilter

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// IsNetworkFilesystem reports whether path's root drive is a network
// drive on Windows.  Uses GetDriveTypeW which categorises drive
// letters into FIXED / REMOTE / REMOVABLE / CDROM / RAMDISK / UNKNOWN
// — only REMOTE (network share) is treated as network.
//
// UNC paths (\\server\share\...) are always classified as network
// even when GetDriveType returns UNKNOWN: the UNC prefix is the
// canonical "this lives on a remote server" signal.
//
// Errors propagate from the caller's perspective as (false, err) so
// the runtime walkers fall back to "scan it" on syscall failure.
func IsNetworkFilesystem(path string) (bool, error) {
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, `\\`) {
		return true, nil
	}

	// Extract the volume root (e.g. ``C:\``).  filepath.VolumeName on
	// windows returns ``C:`` for ``C:\foo``; append a backslash so
	// GetDriveType treats it as a root path.
	vol := filepath.VolumeName(clean)
	if vol == "" {
		// Relative path or a path we can't classify — match unix
		// behaviour (do not skip).
		return false, nil
	}
	root := vol + `\`
	rootUTF16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return false, err
	}
	dt := windows.GetDriveType(rootUTF16)
	return dt == windows.DRIVE_REMOTE, nil
}
