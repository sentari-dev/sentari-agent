package comms

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveAndLoadLicenseMapTrust_RoundTrip: the pubkey+key_id the server
// returns at /register must round-trip through the on-disk trust file
// unchanged — the downstream scanner.RegisterTrustedMapKey relies on
// byte-exact fidelity, any corruption here would cause silent envelope
// verification failures on every license-map fetch.
func TestSaveAndLoadLicenseMapTrust_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	const keyID = "primary"
	const pubB64 = "ll5zbn6EoKZXgO/o08tuoy6c1DawfHaE6pVWw7XMCPg="

	if err := SaveLicenseMapTrust(dir, keyID, pubB64); err != nil {
		t.Fatalf("save: %v", err)
	}

	// File must exist with mode 0600 — a looser mode could let an
	// unprivileged process swap in a malicious trust record.
	info, err := os.Stat(filepath.Join(dir, "license_map_trust.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("trust file too permissive: %v", mode)
	}

	got, err := LoadLicenseMapTrust(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil {
		t.Fatal("load returned nil; expected trust record")
	}
	if got.KeyID != keyID || got.PubKeyB64 != pubB64 {
		t.Errorf("round-trip mismatch: got %+v, want {KeyID=%s, PubKeyB64=%s}",
			got, keyID, pubB64)
	}
}

// TestSaveLicenseMapTrust_EmptySkips: when the server omits the pubkey
// fields (e.g. the signing key couldn't be loaded at register time)
// the agent must not write a partial trust record — loading it later
// would fail and the agent would incorrectly treat license-map as
// misconfigured rather than simply unbootstrapped.
func TestSaveLicenseMapTrust_EmptySkips(t *testing.T) {
	dir := t.TempDir()
	if err := SaveLicenseMapTrust(dir, "", ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "license_map_trust.json")); !os.IsNotExist(err) {
		t.Errorf("expected no file to be written; stat err: %v", err)
	}
}

// TestLoadLicenseMapTrust_MissingReturnsNil: pre-register state must
// not be an error — a fresh agent has no trust file yet.  Callers
// proceed without license-map verification and log; the next
// successful register creates the file.
func TestLoadLicenseMapTrust_MissingReturnsNil(t *testing.T) {
	got, err := LoadLicenseMapTrust(t.TempDir())
	if err != nil {
		t.Errorf("unexpected error on missing trust file: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil trust record when file is absent, got %+v", got)
	}
}

// TestLoadLicenseMapTrust_RejectsPartialRecord: a trust file missing
// either key_id or pubkey_b64 is corrupt; loading must fail rather
// than returning a record the caller would misuse.
func TestLoadLicenseMapTrust_RejectsPartialRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license_map_trust.json")
	if err := os.WriteFile(path, []byte(`{"key_id":"primary"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLicenseMapTrust(dir); err == nil {
		t.Error("expected error on partial trust record")
	}
}
