//go:build windows

package safeio

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openNoFollow opens path read-only on Windows without following a
// reparse point (symbolic link, junction, or mount point) at the
// leaf.
//
// Windows has no O_NOFOLLOW.  The previous implementation Lstat'd the
// path and then os.Open'd it, leaving a TOCTOU window: between the
// symlink check and the open, an attacker with write access to the
// directory could swap the leaf for a symlink/reparse point and the
// scanner would silently follow it (the same /etc/shadow-exfil class
// the Unix O_NOFOLLOW path closes kernel-side).  We close that window
// by validating the OPEN handle instead of the path:
//
//  1. CreateFile with FILE_FLAG_OPEN_REPARSE_POINT opens the leaf
//     itself rather than following it, so a reparse-point leaf yields
//     a handle to the reparse point — not to its target.
//     FILE_FLAG_BACKUP_SEMANTICS lets the same call open directories,
//     matching the Unix path where the caller's fstat rejects dirs.
//  2. GetFileInformationByHandle reports the real attributes of the
//     object we actually opened; if FILE_ATTRIBUTE_REPARSE_POINT is
//     set we close the handle and refuse with ErrSymlink.
//
// Because step 2 inspects the handle we already hold rather than
// re-resolving the path, there is no second lookup to race: a swap
// performed after step 1 cannot make us read a link target.  This is
// check-after-open on one object, not check-then-open on a path.
//
// Residual (identical to the Unix O_NOFOLLOW leaf-only guarantee — see
// the package doc): reparse points among the *intermediate directory
// components* of path are still resolved by CreateFile.  A fully
// resolved-beneath open would require per-component handle walking (or
// an openat2-equivalent Windows primitive, which does not exist).  The
// threat model here is the single-leaf reparse-point swap, which this
// fully covers.
func openNoFollow(path string) (*os.File, error) {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	handle, err := windows.CreateFile(
		pathp,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	// Verify on the handle we hold — not by re-statting the path — that
	// we did not open a reparse point.  Check-after-open on the same
	// object is what makes this race-free.
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}

	// Hand ownership of the validated handle to *os.File so the caller's
	// existing Stat/Read/Close path (shared with Unix) works unchanged;
	// f.Close() closes this handle.
	return os.NewFile(uintptr(handle), path), nil
}

// openNoFollowDir opens path as a DIRECTORY for enumeration without
// following a reparse point at the leaf.  It is the ReadDir analogue of
// openNoFollow above and shares its handle-validated, race-free design:
// the very same CreateFile flags (FILE_FLAG_OPEN_REPARSE_POINT to open a
// reparse-point leaf itself rather than follow it, FILE_FLAG_BACKUP_
// SEMANTICS to permit opening a directory) already return a handle to the
// leaf object, which GetFileInformationByHandle then inspects — a
// FILE_ATTRIBUTE_REPARSE_POINT leaf (symlink, junction, mount point) is
// refused with ErrSymlink.  GENERIC_READ grants FILE_LIST_DIRECTORY on a
// directory handle, so ReadDir can enumerate the returned *os.File.
//
// The not-a-directory case is left to ReadDir's fstat on the returned
// handle (there is no Windows O_DIRECTORY), which reports ErrNotRegular
// for a file/FIFO/device planted at the path.
//
// Residual (identical to openNoFollow / the Unix leaf-only guarantee):
// reparse points among the INTERMEDIATE path components are still
// resolved by CreateFile; only the single-leaf reparse-point swap is
// covered, which is the threat model here.
func openNoFollowDir(path string) (*os.File, error) {
	// Reuse the file open: its CreateFile flags already open directories
	// (BACKUP_SEMANTICS) and refuse a reparse-point leaf on the held
	// handle, so no second, race-prone path lookup is introduced.
	return openNoFollow(path)
}
