package comms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSaveAndLoadVulnMapTrust_RoundTrip — same contract as the
// license-map and install-gate trust round-trips: the vuln-map
// pubkey + key_id the server returns at /register must round-trip
// through the on-disk trust file unchanged.  A downstream verifier
// will rely on byte-exact fidelity; any corruption here would
// silently break envelope verification on every vuln-map fetch.
func TestSaveAndLoadVulnMapTrust_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	const keyID = "primary"
	const pubB64 = "dnVsbi1tYXAtcHVia2V5LWZha2UtZm9yLXJvdW5kdHJpcA=="

	if err := SaveVulnMapTrust(dir, keyID, pubB64); err != nil {
		t.Fatalf("save: %v", err)
	}

	// 0600 — same posture as the other two channels.  A looser mode
	// would let a local process swap in a malicious trust record and
	// have the agent accept forged vuln-map envelopes.
	info, err := os.Stat(filepath.Join(dir, "vuln_map_trust.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("trust file too permissive: %v", mode)
	}

	got, err := LoadVulnMapTrust(dir)
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

// TestSaveVulnMapTrust_EmptySkips: a server that has not provisioned
// a vuln-map signing key (older deployments, or air-gap operators
// who haven't imported an NVD bundle yet) returns empty fields on
// /register.  Writing a partial trust record would later fail to
// load and the agent would treat the channel as misconfigured rather
// than simply unbootstrapped.
func TestSaveVulnMapTrust_EmptySkips(t *testing.T) {
	dir := t.TempDir()
	if err := SaveVulnMapTrust(dir, "", ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vuln_map_trust.json")); !os.IsNotExist(err) {
		t.Errorf("expected no file to be written; stat err: %v", err)
	}
}

// One-half-empty inputs must also no-op rather than fail (server may
// supply key_id without pubkey on a misconfigured signing-key path;
// fail-closed is safer than half-writing the file).
func TestSaveVulnMapTrust_PartialInputsSkip(t *testing.T) {
	dir := t.TempDir()
	if err := SaveVulnMapTrust(dir, "primary", ""); err != nil {
		t.Errorf("save with empty pubkey: %v", err)
	}
	if err := SaveVulnMapTrust(dir, "", "anybase64=="); err != nil {
		t.Errorf("save with empty keyID: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vuln_map_trust.json")); !os.IsNotExist(err) {
		t.Errorf("expected no file to be written; stat err: %v", err)
	}
}

// TestLoadVulnMapTrust_MissingReturnsNil: pre-register state must
// not be an error — a fresh agent has no trust file yet.  Callers
// proceed without vuln-map verification and log; the next
// successful register creates the file.
func TestLoadVulnMapTrust_MissingReturnsNil(t *testing.T) {
	got, err := LoadVulnMapTrust(t.TempDir())
	if err != nil {
		t.Errorf("unexpected error on missing trust file: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil trust record when file is absent, got %+v", got)
	}
}

// TestLoadVulnMapTrust_RejectsPartialRecord: a trust file missing
// either “key_id“ or “pubkey_b64“ is corrupt; loading must fail
// rather than returning a record the caller would misuse.
func TestLoadVulnMapTrust_RejectsPartialRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vuln_map_trust.json")
	if err := os.WriteFile(path, []byte(`{"key_id":"primary"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVulnMapTrust(dir); err == nil {
		t.Error("expected error on partial trust record")
	}
}

// TestVulnMapTrustFileIsDistinctFromOthers: belt-and-braces
// channel-isolation guard.  Saving a vuln-map trust record must not
// overwrite the license-map or install-gate trust records under the
// same dir, and vice-versa — trust state per channel is independent
// and a key rotation on one must not touch the others.
func TestVulnMapTrustFileIsDistinctFromOthers(t *testing.T) {
	dir := t.TempDir()
	if err := SaveLicenseMapTrust(dir, "lm-key", "bGljZW5zZS1tYXAtcHVia2V5LWZha2U="); err != nil {
		t.Fatalf("save license: %v", err)
	}
	if err := SaveInstallGateTrust(dir, "ig-key", "aW5zdGFsbC1nYXRlLXB1YmtleS1mYWtl"); err != nil {
		t.Fatalf("save install-gate: %v", err)
	}
	if err := SaveVulnMapTrust(dir, "vm-key", "dnVsbi1tYXAtcHVia2V5LWZha2U="); err != nil {
		t.Fatalf("save vuln-map: %v", err)
	}

	lm, err := LoadLicenseMapTrust(dir)
	if err != nil || lm == nil || lm.KeyID != "lm-key" {
		t.Errorf("license-map trust corrupted: lm=%+v err=%v", lm, err)
	}
	ig, err := LoadInstallGateTrust(dir)
	if err != nil || ig == nil || ig.KeyID != "ig-key" {
		t.Errorf("install-gate trust corrupted: ig=%+v err=%v", ig, err)
	}
	vm, err := LoadVulnMapTrust(dir)
	if err != nil || vm == nil || vm.KeyID != "vm-key" {
		t.Errorf("vuln-map trust corrupted: vm=%+v err=%v", vm, err)
	}
}

// TestVulnMapTrustResponseFieldOmitEmpty: belt-and-braces over the
// JSON tag contract for the new fields on RegisterResponse.  Two
// guarantees in one test:
//
//	(a) When VulnMapKeyID / VulnMapPubKey are empty, the JSON-marshal
//	    output omits them entirely — older servers that don't emit
//	    these keys produce a wire format the agent round-trips
//	    without surprises.
//	(b) Calling SaveVulnMapTrust with the empty zero values is a
//	    no-op-safe operation that doesn't error or create a trust
//	    file the loader would later treat as authoritative.
func TestVulnMapTrustResponseFieldOmitEmpty(t *testing.T) {
	resp := RegisterResponse{DeviceID: "d"}

	// (a) Marshal-assertion: confirm the omitempty tags actually fire.
	out, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal RegisterResponse: %v", err)
	}
	encoded := string(out)
	if strings.Contains(encoded, "vuln_map_pubkey") {
		t.Errorf("expected vuln_map_pubkey omitted on empty value; got %s", encoded)
	}
	if strings.Contains(encoded, "vuln_map_key_id") {
		t.Errorf("expected vuln_map_key_id omitted on empty value; got %s", encoded)
	}

	// (b) Empty-value safety: SaveVulnMapTrust must accept zero values
	// without writing a trust file the loader would later mistake for
	// an authoritative answer.
	if err := SaveVulnMapTrust(t.TempDir(), resp.VulnMapKeyID, resp.VulnMapPubKey); err != nil {
		t.Errorf("empty fields must be no-op-safe: %v", err)
	}
}
