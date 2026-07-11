package scanner

import (
	"reflect"
	"testing"
)

// TestFixedDrivesFromBitmap verifies the pure bitmap decode + DRIVE_FIXED
// filter: only bits set in the bitmask become candidate drive roots, and only
// those the injected classifier reports as DRIVE_FIXED are kept.  Removable,
// network, optical and RAM-disk volumes are excluded.
func TestFixedDrivesFromBitmap(t *testing.T) {
	// Present drives: C, D, E, Z (bits 2, 3, 4, 25).
	bitmap := uint32(1<<2 | 1<<3 | 1<<4 | 1<<25)
	types := map[string]uint32{
		"C:\\": driveFixed,
		"D:\\": driveFixed,
		"E:\\": driveRemote,    // mapped network share — excluded
		"Z:\\": driveRemovable, // USB stick — excluded
	}
	got := fixedDrivesFromBitmap(bitmap, func(root string) uint32 {
		return types[root]
	})
	want := []string{"C:\\", "D:\\"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fixedDrivesFromBitmap = %v, want %v", got, want)
	}
}

// TestFixedDrivesFromBitmapExcludesAllNonFixed proves every non-fixed drive
// type is filtered out even when present in the bitmap.
func TestFixedDrivesFromBitmapExcludesAllNonFixed(t *testing.T) {
	bitmap := uint32(1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4)
	types := map[string]uint32{
		"A:\\": driveRemovable,
		"B:\\": driveCDROM,
		"C:\\": driveRemote,
		"D:\\": driveRAMDisk,
		"E:\\": driveUnknown,
	}
	got := fixedDrivesFromBitmap(bitmap, func(root string) uint32 { return types[root] })
	if len(got) != 0 {
		t.Fatalf("fixedDrivesFromBitmap = %v, want none (no DRIVE_FIXED volumes)", got)
	}
}

// TestFixedDrivesSkippedBy verifies the scanned drive is removed from the set
// of fixed drives, leaving exactly the secondary disks the single-root scan
// misses.  Comparison is case-insensitive on the drive letter.
func TestFixedDrivesSkippedBy(t *testing.T) {
	fixed := []string{"C:\\", "D:\\", "E:\\"}

	skipped := fixedDrivesSkippedBy("C:\\", fixed)
	want := []string{"D:\\", "E:\\"}
	if !reflect.DeepEqual(skipped, want) {
		t.Fatalf("skipped by C:\\ = %v, want %v", skipped, want)
	}

	// Case-insensitive: lower-case scan root still matches the C: entry.
	if s := fixedDrivesSkippedBy("c:\\", fixed); !reflect.DeepEqual(s, want) {
		t.Fatalf("skipped by c:\\ = %v, want %v", s, want)
	}

	// Single fixed drive that IS the scan root -> nothing skipped.
	if s := fixedDrivesSkippedBy("C:\\", []string{"C:\\"}); len(s) != 0 {
		t.Fatalf("skipped = %v, want none", s)
	}
}

// TestWindowsFixedDrivesUsesSeams proves windowsFixedDrives is driven entirely
// by the injectable logicalDrivesBitmap / driveTypeOf seams, so the enumeration
// is testable without real Windows syscalls.  Restores the seams after.
func TestWindowsFixedDrives_InjectedSeams(t *testing.T) {
	origBitmap := logicalDrivesBitmap
	origType := driveTypeOf
	defer func() { logicalDrivesBitmap = origBitmap; driveTypeOf = origType }()

	logicalDrivesBitmap = func() uint32 { return 1<<2 | 1<<3 } // C:, D:
	driveTypeOf = func(root string) uint32 {
		if root == "D:\\" {
			return driveRemote // exclude the network drive
		}
		return driveFixed
	}
	got := windowsFixedDrives()
	want := []string{"C:\\"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("windowsFixedDrives = %v, want %v", got, want)
	}
}
