//go:build windows

package scanner

import (
	"golang.org/x/sys/windows"
)

// getFileOwner returns the Windows account name that owns the file at path.
// It opens a read-control handle to the file, calls GetSecurityInfo to obtain
// the owner SID, then resolves the SID to an account name via LookupAccount.
// Returns "" on any error so callers can treat missing ownership as non-fatal.
func getFileOwner(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}

	h, err := windows.CreateFile(
		p,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		// FILE_FLAG_BACKUP_SEMANTICS is required to open directories.
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	sd, err := windows.GetSecurityInfo(
		h,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return ""
	}

	ownerSID, _, err := sd.Owner()
	if err != nil {
		return ""
	}

	account, _, _, err := ownerSID.LookupAccount("")
	if err != nil {
		// Fall back to the raw SID string (e.g. "S-1-5-32-544").
		if s := ownerSID.String(); s != "" {
			return s
		}
		return ""
	}
	return account
}
