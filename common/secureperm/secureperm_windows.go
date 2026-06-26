//go:build windows

package secureperm

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// restrict replaces the object's DACL with an explicit, inheritance-protected
// ACL granting full control to LocalSystem, the Builtin Administrators group
// and the current process user — and nobody else.  PROTECTED_DACL strips any
// inherited ACEs (e.g. the "Users" read grant a file under %ProgramData%
// inherits by default), which is the whole point: the device private key must
// not be readable by ordinary local accounts.
func restrict(path string, isDir bool) error {
	// Current process user SID.
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("secureperm: get token user: %w", err)
	}
	userSID := tokenUser.User.Sid

	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("secureperm: system SID: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("secureperm: administrators SID: %w", err)
	}

	// Directories grant an inheritable ACE so newly-created children (the
	// cert files written after the dir is hardened) inherit the restriction;
	// files get a non-inheritable ACE.
	inheritance := uint32(windows.NO_INHERITANCE)
	if isDir {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}

	grant := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	acl, err := windows.ACLFromEntries(
		[]windows.EXPLICIT_ACCESS{grant(systemSID), grant(adminSID), grant(userSID)},
		nil,
	)
	if err != nil {
		return fmt.Errorf("secureperm: build ACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, // owner unchanged
		nil, // group unchanged
		acl,
		nil, // SACL unchanged
	); err != nil {
		return fmt.Errorf("secureperm: set DACL on %s: %w", path, err)
	}
	return nil
}
