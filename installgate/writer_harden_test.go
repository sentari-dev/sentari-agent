package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestWriteAtomic_CredentialModePreserved0600 confirms the confidentiality
// hardening pass leaves the unix behaviour unchanged: a 0600 credential
// config still lands at 0600 (the hardening is additive — a Windows DACL —
// and re-asserts the same 0600 on unix).
func TestWriteAtomic_CredentialModePreserved0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	changed, err := WriteAtomic(WriteOptions{
		Path:     path,
		Content:  []byte("# Managed by Sentari\n//registry/:_authToken=secret\n"),
		FileMode: 0o600,
		Now:      time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true for fresh write")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credential config perm = %o, want 600", perm)
		}
	}
}

// TestWriteAtomic_WorldReadableModeUntouched0644 confirms the hardening pass
// does NOT touch the world-readable configs (pip.conf, apt/yum repo files):
// a 0644 file must stay 0644 so non-root debugging tooling can read it.  If
// hardenIfConfidential mistakenly ran secureperm.HardenFile here, unix would
// have clamped the file to 0600 and broken that flow.
func TestWriteAtomic_WorldReadableModeUntouched0644(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	if _, err := WriteAtomic(WriteOptions{
		Path:     path,
		Content:  []byte("# Managed by Sentari\n[global]\nindex-url = https://proxy/simple\n"),
		FileMode: 0o644,
		Now:      time.Unix(0, 0).UTC(),
	}); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Errorf("world-readable config perm = %o, want 644 (hardening must skip it)", perm)
		}
	}
}

// TestHardenIfConfidential_SkipsWorldReadable proves the mode-classification
// gate: a world-readable mode short-circuits BEFORE secureperm.HardenFile is
// ever called.  We pass a path that does not exist — if the helper tried to
// harden it, secureperm.HardenFile would fail (chmod/DACL on a missing file);
// a nil return proves the credential-only branch was skipped.
func TestHardenIfConfidential_SkipsWorldReadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, mode := range []os.FileMode{0o644, 0o640, 0o664, 0o755} {
		if err := hardenIfConfidential(missing, mode); err != nil {
			t.Errorf("mode %o: expected skip (nil), got %v", mode, err)
		}
	}
}

// TestHardenIfConfidential_HardensOwnerOnly proves the hardening call IS
// invoked for a credential (owner-only) mode.  On unix the observable effect
// is a re-assert to 0600; we seed the file at 0644 and assert it is clamped,
// which can only happen if secureperm.HardenFile ran.
func TestHardenIfConfidential_HardensOwnerOnly(t *testing.T) {
	f := filepath.Join(t.TempDir(), "creds")
	if err := os.WriteFile(f, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hardenIfConfidential(f, 0o600); err != nil {
		t.Fatalf("hardenIfConfidential: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("perm = %o, want 600 (hardening should have run)", perm)
		}
	}
}

// TestWriteAtomic_CredentialBackupHardened confirms the SECOND credential
// write path — backupOriginal — also runs the hardening pass.  When an
// operator-curated credential config (0600 .npmrc with auth tokens) is
// overwritten, its verbatim `.sentari-backup-*` copy carries the same
// secrets and must inherit the same owner-only protection, not the parent
// dir's world-readable ACL.
func TestWriteAtomic_CredentialBackupHardened(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	// Operator-curated credential file, owner-only.
	if err := os.WriteFile(path, []byte("//registry/:_authToken=operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	if _, err := WriteAtomic(WriteOptions{
		Path:     path,
		Content:  []byte("# Managed by Sentari\n//registry/:_authToken=managed\n"),
		FileMode: 0o600,
		Now:      now,
	}); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	matches, err := filepath.Glob(path + ".sentari-backup-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one backup, got %v (err %v)", matches, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credential backup perm = %o, want 600", perm)
		}
	}
}
