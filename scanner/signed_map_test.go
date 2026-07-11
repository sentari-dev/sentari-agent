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

// TestCanonicalJSON_LineSeparatorsRawUTF8 pins the U+2028/U+2029 fix: Go's
// json encoder escapes those runes to ` `/` ` even with HTML escaping
// off, but the server signs over json.dumps(ensure_ascii=False) which emits
// them as raw UTF-8 (E2 80 A8 / E2 80 A9).  Without the post-process a validly
// signed map containing either rune would fail verification on the agent.  The
// golden byte-vector is the exact output of Python's canonicalizer for the same
// payload (computed with json.dumps(sort_keys=True, separators=(',',':'),
// ensure_ascii=False)).
func TestCanonicalJSON_LineSeparatorsRawUTF8(t *testing.T) {
	// Value carries a real U+2028 then a real U+2029.
	payload := map[string]interface{}{
		"note":    "line1\u2028line2\u2029end",
		"version": 3,
	}
	got, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}

	// No ASCII escape must survive.
	if bytes.Contains(got, []byte(`\u2028`)) || bytes.Contains(got, []byte(`\u2029`)) {
		t.Errorf("canonical bytes still contain a \\u2028/\\u2029 escape: %q", got)
	}
	// Raw UTF-8 encodings must be present.
	if !bytes.Contains(got, []byte{0xe2, 0x80, 0xa8}) {
		t.Errorf("missing raw U+2028 (E2 80 A8): %x", got)
	}
	if !bytes.Contains(got, []byte{0xe2, 0x80, 0xa9}) {
		t.Errorf("missing raw U+2029 (E2 80 A9): %x", got)
	}

	// Exact golden byte-vector — must equal Python's canonical_json output.
	want := []byte{
		0x7b, 0x22, 0x6e, 0x6f, 0x74, 0x65, 0x22, 0x3a, 0x22, 0x6c, 0x69, 0x6e,
		0x65, 0x31, 0xe2, 0x80, 0xa8, 0x6c, 0x69, 0x6e, 0x65, 0x32, 0xe2, 0x80,
		0xa9, 0x65, 0x6e, 0x64, 0x22, 0x2c, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69,
		0x6f, 0x6e, 0x22, 0x3a, 0x33, 0x7d,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("canonical bytes differ from Python golden:\n  got:  %x\n  want: %x", got, want)
	}
}

// TestCanonicalJSON_LiteralBackslashU2028Preserved is the edge case a naive
// bytes.Replace would corrupt: a string value that literally contains the six
// characters `\u2028` (a source backslash, not the rune).  Go escapes the
// backslash to `\\u2028`, and so does Python — the two already agree, so the
// post-process must leave it untouched.  A blind substring replace would turn
// `\\u2028` into `\`+U+2028 and diverge from the server.
func TestCanonicalJSON_LiteralBackslashU2028Preserved(t *testing.T) {
	payload := map[string]interface{}{"x": `\u2028`}
	got, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	// Python golden: {"x":"\\u2028"} — the backslash escaped, u2028 literal.
	want := []byte(`{"x":"\\u2028"}`)
	if !bytes.Equal(got, want) {
		t.Errorf("literal \\u2028 corrupted:\n  got:  %x\n  want: %x", got, want)
	}
}

// TestCanonicalJSON_BackslashThenLineSeparator covers the mixed case: a source
// literal backslash immediately followed by a REAL U+2028 rune.  Go emits the
// escaped backslash `\\` then its rune escape `\u2028` (three backslashes then
// u2028); only the trailing genuine escape may be rewritten, leaving the `\\`
// intact — matching Python's `\\`+rawU+2028.
func TestCanonicalJSON_BackslashThenLineSeparator(t *testing.T) {
	payload := map[string]interface{}{"x": "\\\u2028"}
	got, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	// Python golden: {"x":"\\<E2 80 A8>"}.
	want := []byte{0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0x5c, 0x5c, 0xe2, 0x80, 0xa8, 0x22, 0x7d}
	if !bytes.Equal(got, want) {
		t.Errorf("mixed backslash+U+2028 wrong:\n  got:  %x\n  want: %x", got, want)
	}
}

// TestCanonicalJSON_NoLineSeparatorUnchanged pins the fast path: a payload with
// no U+2028/U+2029 anywhere is returned byte-identical to Go's encoder output.
func TestCanonicalJSON_NoLineSeparatorUnchanged(t *testing.T) {
	got, err := canonicalJSON(map[string]interface{}{"a": "plain", "b": 1})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"plain","b":1}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestVerifyMapEnvelope_RoundTripWithLineSeparator proves a signed map whose
// payload contains U+2028/U+2029 verifies end-to-end: the signature is produced
// over the SAME canonical bytes the agent recomputes.  This is the concrete
// regression the fix prevents — before it, this envelope's valid signature was
// rejected.
func TestVerifyMapEnvelope_RoundTripWithLineSeparator(t *testing.T) {
	priv := registerTestKey(t, "test-linesep")
	env := signTestEnvelope(t, priv, "test-linesep", map[string]interface{}{
		"version":  7,
		"spdx_map": map[string]string{"Weird\u2028License": "MIT"},
		"tier_map": map[string]string{"MIT": "permissive\u2029"},
	})
	m, err := VerifyMapEnvelope(env)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.Version != 7 {
		t.Errorf("version: got %d, want 7", m.Version)
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
		[]byte(`{"payload": {}}`), // missing signature, key_id
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

// payloadWithVersion builds a valid license-map payload at a chosen
// version.  The maps are non-empty so VerifyMapEnvelope's downgrade guard
// does not fire on the map contents themselves.
func payloadWithVersion(v int) map[string]interface{} {
	return map[string]interface{}{
		"version":  v,
		"spdx_map": map[string]string{"MIT License": "MIT"},
		"tier_map": map[string]string{"MIT": "permissive"},
	}
}

// TestLoadVerifiedOverlay_RefusesRollback is the audit security-3 case:
// once a newer license map has been applied, an attacker who replaces the
// on-disk cache with an OLDER but still-validly-signed envelope must not
// be able to roll the agent back to stale entitlements.  The persisted
// version high-water mark is the floor; the signature check alone cannot
// catch this because the old map was legitimately signed once.
func TestLoadVerifiedOverlay_RefusesRollback(t *testing.T) {
	ResetToDefaults()
	priv := registerTestKey(t, "test-rollback")
	path := filepath.Join(t.TempDir(), "license_map.json")

	// Apply v5 through the normal cache path (Save advances the floor to 5,
	// then Load applies at the floor).
	envV5 := signTestEnvelope(t, priv, "test-rollback", payloadWithVersion(5))
	if err := SaveVerifiedEnvelopeToFile(path, envV5); err != nil {
		t.Fatalf("save v5: %v", err)
	}
	if !LoadVerifiedOverlayFromFile(path) {
		t.Fatal("v5 should load")
	}
	if MapVersion() != 5 {
		t.Fatalf("version after v5: got %d, want 5", MapVersion())
	}

	// Attacker swaps the cache for a validly-signed OLDER v3.  It verifies
	// (real signature) but is below the floor, so it must be refused and
	// the in-memory overlay must NOT be downgraded.
	envV3 := signTestEnvelope(t, priv, "test-rollback", payloadWithVersion(3))
	if err := os.WriteFile(path, envV3, 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadVerifiedOverlayFromFile(path) {
		t.Error("rolled-back v3 must be refused (below floor)")
	}
	if MapVersion() != 5 {
		t.Errorf("overlay downgraded despite version floor: got %d, want 5", MapVersion())
	}

	// A genuinely newer v6 is accepted and advances the floor.
	envV6 := signTestEnvelope(t, priv, "test-rollback", payloadWithVersion(6))
	if err := os.WriteFile(path, envV6, 0o600); err != nil {
		t.Fatal(err)
	}
	if !LoadVerifiedOverlayFromFile(path) {
		t.Error("newer v6 must be accepted")
	}
	if MapVersion() != 6 {
		t.Errorf("version after v6: got %d, want 6", MapVersion())
	}

	// After the floor advanced to 6, the old v3 remains refused.
	if err := os.WriteFile(path, envV3, 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadVerifiedOverlayFromFile(path) {
		t.Error("v3 must remain refused after floor advanced to 6")
	}
	if MapVersion() != 6 {
		t.Errorf("version floor breached: got %d, want 6", MapVersion())
	}
}

// TestSaveVerifiedEnvelope_AdvancesVersionFloor pins that the online-
// update persistence path (Save) establishes the rollback floor on its
// own, so a later disk swap to an older signed envelope is refused even
// if the newer map was never re-loaded from disk.
func TestSaveVerifiedEnvelope_AdvancesVersionFloor(t *testing.T) {
	ResetToDefaults()
	priv := registerTestKey(t, "test-save-floor")
	path := filepath.Join(t.TempDir(), "license_map.json")

	// Cache v4 (as the fetch path would after ApplyOverlay).
	envV4 := signTestEnvelope(t, priv, "test-save-floor", payloadWithVersion(4))
	if err := SaveVerifiedEnvelopeToFile(path, envV4); err != nil {
		t.Fatalf("save v4: %v", err)
	}

	// Attacker swaps in a signed older v2 before the next startup load.
	envV2 := signTestEnvelope(t, priv, "test-save-floor", payloadWithVersion(2))
	if err := os.WriteFile(path, envV2, 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadVerifiedOverlayFromFile(path) {
		t.Error("older v2 must be refused; Save should have set the floor to 4")
	}
}
