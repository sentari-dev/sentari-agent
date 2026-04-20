// Tests for the signed license-map verification primitive.
//
// Covers:
//   - Canonical JSON matches the Python canonicalizer bit-for-bit on
//     license-map payloads.
//   - Envelope round-trip: sign with a test key, verify with the
//     registered trusted key.
//   - Red-team: tampered payload, wrong key_id, signature-bit-flip,
//     size cap overflow, empty-map downgrade, malformed JSON.
//   - Cache round-trip: SaveVerifiedEnvelopeToFile + LoadVerifiedOverlayFromFile
//     re-verify on load and refuse disk tampering.

package scanner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: generate an ephemeral keypair and register its pub as a
// trusted map key under the given id.  Test-only — production never
// registers keys this way.
func registerTestKey(t *testing.T, keyID string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Trust the public key in the global registry for the duration of
	// this test.  We don't restore — tests should use distinct key_ids.
	RegisterTrustedMapKey(keyID, pub)
	return priv
}

// helper: build and sign a license-map envelope.
func signTestEnvelope(t *testing.T, priv ed25519.PrivateKey, keyID string, payload map[string]interface{}) []byte {
	t.Helper()
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	env := map[string]interface{}{
		"payload":   payload,
		"signature": base64.StdEncoding.EncodeToString(sig),
		"key_id":    keyID,
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return out
}

func validPayload() map[string]interface{} {
	return map[string]interface{}{
		"version":  2,
		"spdx_map": map[string]string{"MIT License": "MIT"},
		"tier_map": map[string]string{"MIT": "permissive"},
	}
}

// --- canonicalJSON -----------------------------------------------------

func TestCanonicalJSON_SortsTopLevelKeys(t *testing.T) {
	got, err := canonicalJSON(map[string]interface{}{"b": 1, "a": 2})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_NestedMapsSort(t *testing.T) {
	got, err := canonicalJSON(map[string]interface{}{
		"outer": map[string]interface{}{"z": 1, "a": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"outer":{"a":2,"z":1}}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_NoTrailingNewline(t *testing.T) {
	got, err := canonicalJSON(map[string]interface{}{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Errorf("got trailing newline: %q", got)
	}
}

func TestCanonicalJSON_HTMLCharsNotEscaped(t *testing.T) {
	got, err := canonicalJSON(map[string]interface{}{"x": "<a&b>"})
	if err != nil {
		t.Fatal(err)
	}
	// Matches Python's json.dumps(..., ensure_ascii=False) on the
	// same input — no \u003c / \u003e / \u0026 escapes.
	want := `{"x":"<a&b>"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Cross-validation against the server-side canonicalizer output.  The
// Python canonicalizer produces exactly these bytes for the license-map
// payload shape — any drift here indicates signature verification will
// start failing between agent and server.
func TestCanonicalJSON_LicenseMapShapeMatchesServer(t *testing.T) {
	payload := map[string]interface{}{
		"version":  3,
		"spdx_map": map[string]string{"MIT License": "MIT", "Apache 2.0": "Apache-2.0"},
		"tier_map": map[string]string{"MIT": "permissive", "Apache-2.0": "permissive"},
	}
	got, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"spdx_map":{"Apache 2.0":"Apache-2.0","MIT License":"MIT"},` +
		`"tier_map":{"Apache-2.0":"permissive","MIT":"permissive"},` +
		`"version":3}`
	if string(got) != want {
		t.Errorf("canonical bytes differ from server contract:\n  got:  %q\n  want: %q", got, want)
	}
}

// --- envelope round-trip ---------------------------------------------

func TestVerifyMapEnvelope_RoundTrip(t *testing.T) {
	priv := registerTestKey(t, "test-roundtrip")
	env := signTestEnvelope(t, priv, "test-roundtrip", validPayload())

	m, err := VerifyMapEnvelope(env)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.Version != 2 {
		t.Errorf("version: got %d, want 2", m.Version)
	}
	if m.SPDXMap["MIT License"] != "MIT" {
		t.Errorf("spdx_map mismatch: %v", m.SPDXMap)
	}
	if m.TierMap["MIT"] != "permissive" {
		t.Errorf("tier_map mismatch: %v", m.TierMap)
	}
}

func TestVerifyMapEnvelope_RejectsTamperedPayload(t *testing.T) {
	priv := registerTestKey(t, "test-tamper")
	env := signTestEnvelope(t, priv, "test-tamper", validPayload())

	// Inject an extra SPDX entry in the serialized envelope.  Since
	// canonical bytes differ, the signature no longer matches.
	tampered := bytes.Replace(env,
		[]byte(`"MIT"`),
		[]byte(`"MIT-0"`), 1)

	_, err := VerifyMapEnvelope(tampered)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("expected signature failure, got: %v", err)
	}
}

func TestVerifyMapEnvelope_RejectsFlippedSignatureBit(t *testing.T) {
	priv := registerTestKey(t, "test-sigflip")
	env := signTestEnvelope(t, priv, "test-sigflip", validPayload())

	// Parse, flip one byte in the signature, re-serialize.
	var envMap map[string]interface{}
	if err := json.Unmarshal(env, &envMap); err != nil {
		t.Fatal(err)
	}
	sigBytes, _ := base64.StdEncoding.DecodeString(envMap["signature"].(string))
	sigBytes[0] ^= 0x01
	envMap["signature"] = base64.StdEncoding.EncodeToString(sigBytes)
	broken, _ := json.Marshal(envMap)

	_, err := VerifyMapEnvelope(broken)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("expected signature failure, got: %v", err)
	}
}

func TestVerifyMapEnvelope_RejectsUnknownKeyID(t *testing.T) {
	// Sign with a key whose pub is NOT registered.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env := signTestEnvelope(t, priv, "never-registered", validPayload())

	_, err := VerifyMapEnvelope(env)
	if err == nil || !strings.Contains(err.Error(), "unknown signing key_id") {
		t.Errorf("expected unknown-key-id error, got: %v", err)
	}
}

func TestVerifyMapEnvelope_RejectsMalformedJSON(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("not-json"),
		[]byte(`{"payload": {}}`),                    // missing signature, key_id
		[]byte(`{"payload":"string","signature":"AA==","key_id":"k"}`), // payload not object
	}
	for i, c := range cases {
		if _, err := VerifyMapEnvelope(c); err == nil {
			t.Errorf("case %d: expected error on input %q", i, c)
		}
	}
}

func TestVerifyMapEnvelope_RejectsEmptyMaps(t *testing.T) {
	priv := registerTestKey(t, "test-empty")
	env := signTestEnvelope(t, priv, "test-empty", map[string]interface{}{
		"version":  5,
		"spdx_map": map[string]string{},
		"tier_map": map[string]string{},
	})

	_, err := VerifyMapEnvelope(env)
	if err == nil || !strings.Contains(err.Error(), "empty maps") {
		t.Errorf("expected empty-maps downgrade error, got: %v", err)
	}
}

func TestVerifyMapEnvelope_RejectsOversizedPayload(t *testing.T) {
	oversized := make([]byte, MaxMapPayloadBytes+1)
	_, err := VerifyMapEnvelope(oversized)
	if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
		t.Errorf("expected size-cap error, got: %v", err)
	}
}

// --- cache round-trip -------------------------------------------------

func TestSaveAndLoadVerifiedEnvelope_RoundTrip(t *testing.T) {
	ResetToDefaults()
	priv := registerTestKey(t, "test-cache-ok")
	env := signTestEnvelope(t, priv, "test-cache-ok", validPayload())

	path := filepath.Join(t.TempDir(), "license_map.json")
	if err := SaveVerifiedEnvelopeToFile(path, env); err != nil {
		t.Fatalf("save: %v", err)
	}

	// File permissions should be 0600 (owner rw only).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("file mode too permissive: %v", mode)
	}

	if !LoadVerifiedOverlayFromFile(path) {
		t.Errorf("load: expected success for valid cached envelope")
	}
	if MapVersion() != 2 {
		t.Errorf("map version after load: got %d, want 2", MapVersion())
	}
}

func TestLoadVerifiedOverlay_RejectsDiskTampering(t *testing.T) {
	ResetToDefaults()
	priv := registerTestKey(t, "test-cache-tamper")
	env := signTestEnvelope(t, priv, "test-cache-tamper", validPayload())

	path := filepath.Join(t.TempDir(), "license_map.json")
	if err := SaveVerifiedEnvelopeToFile(path, env); err != nil {
		t.Fatal(err)
	}

	// Attacker edits the cached file: changes MIT → Apache-2.0 in the
	// spdx_map.  Signature no longer matches; load must refuse and
	// the in-memory map must NOT be mutated.
	data, _ := os.ReadFile(path)
	tampered := bytes.Replace(data, []byte(`"MIT"`), []byte(`"GPL"`), 1)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	if LoadVerifiedOverlayFromFile(path) {
		t.Errorf("load succeeded on tampered file — security regression")
	}
	// mapVersion must still be zero (defaults) since no overlay was applied.
	if MapVersion() != 0 {
		t.Errorf("overlay was applied despite verification failure; version=%d", MapVersion())
	}
}

func TestLoadVerifiedOverlay_ReturnsFalseOnMissingFile(t *testing.T) {
	if LoadVerifiedOverlayFromFile(filepath.Join(t.TempDir(), "absent.json")) {
		t.Errorf("expected false for missing file")
	}
}
