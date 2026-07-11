//go:build windows

package scanner

import "golang.org/x/sys/windows"

// This file binds the cross-platform drive-enumeration seams declared in
// scanner.go (logicalDrivesBitmap / driveTypeOf) to the real Windows syscalls,
// so the "secondary fixed drive not scanned" diagnostic in Run actually fires
// on a Windows host.  The pure logic (fixedDrivesFromBitmap / windowsFixedDrives
// / fixedDrivesSkippedBy) stays in scanner.go and remains unit-testable on any
// OS via those seams; here we only supply the platform truth.
//
// The seams are package-level vars, so we reassign them in init() — matching the
// var-seam pattern scanner.go established for test injection.  golang.org/x/sys/
// windows is pure Go (CGO_ENABLED=0-safe) and already a dependency.
func init() {
	logicalDrivesBitmap = windowsLogicalDrivesBitmap
	driveTypeOf = windowsDriveTypeOf
}

// windowsLogicalDrivesBitmap returns the GetLogicalDrives bitmask (bit i set =
// the (A+i): volume exists).  On error it falls back to 0, which makes
// windowsFixedDrives report no drives rather than crash — the diagnostic is
// best-effort and must never break a scan.
func windowsLogicalDrivesBitmap() uint32 {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return 0
	}
	return mask
}

// windowsDriveTypeOf classifies a Windows drive root like `D:\` via
// GetDriveTypeW and maps the Windows DRIVE_* codes onto this package's local
// drive-type constants (declared in scanner.go).  An un-encodable root or an
// unrecognised code maps to driveUnknown, so such a volume is never treated as a
// fixed drive by fixedDrivesFromBitmap.
func windowsDriveTypeOf(root string) uint32 {
	ptr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return driveUnknown
	}
	switch windows.GetDriveType(ptr) {
	case windows.DRIVE_REMOVABLE:
		return driveRemovable
	case windows.DRIVE_FIXED:
		return driveFixed
	case windows.DRIVE_REMOTE:
		return driveRemote
	case windows.DRIVE_CDROM:
		return driveCDROM
	case windows.DRIVE_RAMDISK:
		return driveRAMDisk
	case windows.DRIVE_NO_ROOT_DIR:
		return driveNoRootDir
	default:
		return driveUnknown
	}
}
