package comms

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveAndLoadInstallGateTrust_RoundTrip — same contract as the
// license-map trust round-trip: the install-gate pubkey + key_id the
// server returns at /register must round-trip through the on-disk
// trust file unchanged.  scanner.RegisterTrustedInstallGateKey
// downstream relies on byte-exact fidelity; any corruption here would
// silently break envelope verification on every policy-map fetch.
func TestSaveAndLoadInstallGateTrust_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	const keyID = "primary"
	const pubB64 = "PIhuJo4nt2HclCwhwbgqIZmMdSgTOji7ypfmhNUEXsU="

	if err := SaveInstallGateTrust(dir, keyID, pubB64); err != nil {
		t.Fatalf("save: %v", err)
	}

	// 0600 — the trust file pins what the agent will accept as a
	// signed-policy authority; a looser mode would let a local
	// process swap in a malicious trust record.
	info, err := os.Stat(filepath.Join(dir, "install_gate_trust.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("trust file too permissive: %v", mode)
	}

	got, err := LoadInstallGateTrust(dir)
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

// TestSaveInstallGateTrust_EmptySkips: a server that has not
// provisioned an install-gate signing key returns empty fields on
// /register.  Writing a partial trust record would later fail to
// load and the agent would treat install-gate as misconfigured
// rather than simply unbootstrapped.
func TestSaveInstallGateTrust_EmptySkips(t *testing.T) {
	dir := t.TempDir()
	if err := SaveInstallGateTrust(dir, "", ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "install_gate_trust.json")); !os.IsNotExist(err) {
		t.Errorf("expected no file to be written; stat err: %v", err)
	}
}

// TestLoadInstallGateTrust_MissingReturnsNil: pre-register state must
// not be an error — a fresh agent has no trust file yet.  Callers
// proceed without install-gate verification and log; the next
// successful register creates the file.
func TestLoadInstallGateTrust_MissingReturnsNil(t *testing.T) {
	got, err := LoadInstallGateTrust(t.TempDir())
	if err != nil {
		t.Errorf("unexpected error on missing trust file: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil trust record when file is absent, got %+v", got)
	}
}

// TestLoadInstallGateTrust_RejectsPartialRecord: a trust file missing
// either ``key_id`` or ``pubkey_b64`` is corrupt; loading must fail
// rather than returning a record the caller would misuse.
func TestLoadInstallGateTrust_RejectsPartialRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "install_gate_trust.json")
	if err := os.WriteFile(path, []byte(`{"key_id":"primary"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInstallGateTrust(dir); err == nil {
		t.Error("expected error on partial trust record")
	}
}

// TestInstallGateTrustFileIsDistinctFromLicenseMap: belt-and-braces
// channel-isolation guard.  Saving an install-gate trust record must
// not overwrite the license-map trust record under the same dir, and
// vice-versa — trust state per channel is independent and a key
// rotation on one must not touch the other.
func TestInstallGateTrustFileIsDistinctFromLicenseMap(t *testing.T) {
	dir := t.TempDir()
	if err := SaveLicenseMapTrust(dir, "lm-key", "bGljZW5zZS1tYXAtcHVia2V5LWZha2U="); err != nil {
		t.Fatalf("save license: %v", err)
	}
	if err := SaveInstallGateTrust(dir, "ig-key", "aW5zdGFsbC1nYXRlLXB1YmtleS1mYWtl"); err != nil {
		t.Fatalf("save install-gate: %v", err)
	}

	lm, err := LoadLicenseMapTrust(dir)
	if err != nil || lm == nil || lm.KeyID != "lm-key" {
		t.Errorf("license-map trust corrupted: lm=%+v err=%v", lm, err)
	}
	ig, err := LoadInstallGateTrust(dir)
	if err != nil || ig == nil || ig.KeyID != "ig-key" {
		t.Errorf("install-gate trust corrupted: ig=%+v err=%v", ig, err)
	}
}
