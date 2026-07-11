//go:build windows

package scanner

import "testing"

// TestWindowsDriveTypeOf_MapsKnownRoots checks that the real GetDriveTypeW
// binding maps a bogus root to driveUnknown (so it is never treated as fixed)
// and classifies the system drive as fixed.  Runs only on a Windows host.
func TestWindowsDriveTypeOf_MapsKnownRoots(t *testing.T) {
	// A root that cannot exist must classify as Unknown, never Fixed.
	if got := windowsDriveTypeOf("\x00:\\"); got == driveFixed {
		t.Errorf("bogus root classified as fixed (%d), want non-fixed", got)
	}

	// The system drive is a real local disk, so GetDriveTypeW must report it
	// as fixed via the mapping.
	if got := windowsDriveTypeOf("C:\\"); got != driveFixed {
		t.Errorf("windowsDriveTypeOf(C:\\): got %d, want driveFixed (%d)", got, driveFixed)
	}
}

// TestWindowsLogicalDrivesBitmap_HasSystemDrive verifies the GetLogicalDrives
// binding reports the C: volume present (bit 2, since 'C'-'A' == 2).
func TestWindowsLogicalDrivesBitmap_HasSystemDrive(t *testing.T) {
	const cBit = uint32(1) << (uint('C') - uint('A'))
	if windowsLogicalDrivesBitmap()&cBit == 0 {
		t.Error("GetLogicalDrives bitmap missing the C: system drive")
	}
}

// TestInit_BindsDriveSeams confirms init() wired the package-level seams to the
// real syscalls (they must no longer be nil after import on Windows).
func TestInit_BindsDriveSeams(t *testing.T) {
	if logicalDrivesBitmap == nil {
		t.Error("logicalDrivesBitmap seam is nil; init() did not bind it")
	}
	if driveTypeOf == nil {
		t.Error("driveTypeOf seam is nil; init() did not bind it")
	}
}
