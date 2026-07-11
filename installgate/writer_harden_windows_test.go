//go:build windows

package installgate

import (
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readDACL fetches the discretionary ACL and control flags for a path.
func readDACL(t *testing.T, path string) (*windows.ACL, windows.SECURITY_DESCRIPTOR_CONTROL) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control(): %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(): %v", err)
	}
	return dacl, control
}

// daclGrantsSID reports whether any ACE in the DACL names sid.
func daclGrantsSID(t *testing.T, dacl *windows.ACL, sid *windows.SID) bool {
	t.Helper()
	if dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID.Equals(sid) {
			return true
		}
	}
	return false
}

// TestWriteAtomic_CredentialFileDACLExcludesEveryone is the Windows-side
// guarantee: a 0600 credential config written by WriteAtomic carries an
// inheritance-PROTECTED DACL (the inherited "Users: read" ACE stripped),
// grants the current process user (owner-read preserved so pip/npm can read
// their own config), and grants NO access to the Everyone/World principal.
func TestWriteAtomic_CredentialFileDACLExcludesEveryone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	if _, err := WriteAtomic(WriteOptions{
		Path:     path,
		Content:  []byte("# Managed by Sentari\n//registry/:_authToken=secret\n"),
		FileMode: 0o600,
		Now:      time.Unix(0, 0).UTC(),
	}); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	dacl, control := readDACL(t, path)

	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("credential config DACL is not PROTECTED — inherited world-readable ACE not stripped")
	}

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if daclGrantsSID(t, dacl, everyone) {
		t.Error("credential config DACL grants Everyone — credential is world-readable")
	}

	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !daclGrantsSID(t, dacl, tokenUser.User.Sid) {
		t.Error("credential config DACL does not grant the current user — install-gate owner-read broken")
	}
}

// TestWriteAtomic_WorldReadableConfigDACLNotProtected is the differential
// case: a 0644 config (pip.conf) must be left with its normal inherited
// (unprotected) DACL so non-admin tooling can still read it — the hardening
// pass must NOT run for world-readable files.
func TestWriteAtomic_WorldReadableConfigDACLNotProtected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.ini")
	if _, err := WriteAtomic(WriteOptions{
		Path:     path,
		Content:  []byte("# Managed by Sentari\n[global]\nindex-url = https://proxy/simple\n"),
		FileMode: 0o644,
		Now:      time.Unix(0, 0).UTC(),
	}); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	_, control := readDACL(t, path)
	if control&windows.SE_DACL_PROTECTED != 0 {
		t.Error("world-readable config DACL is PROTECTED — hardening wrongly ran on a 0644 file")
	}
}
