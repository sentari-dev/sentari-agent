// Tests for integer-precision-preserving canonicalization in the
// license-map and install-gate envelope verifiers.
//
// The server signs canonical(payload) where every JSON number keeps
// its exact source text (Python ints are arbitrary-precision).  A
// verifier that re-canonicalizes through map[string]interface{} coerces
// every number to float64, so an integer field at or above 2^53 (e.g.
// the install-gate ``version`` epoch) round-trips with lost precision
// and ed25519.Verify fails on an otherwise-valid envelope.  These tests
// pin the round-trip on a >2^53 integer.

package scanner

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// serverCanonicalize mirrors the server's canonicalizer: decode with
// json.Number (UseNumber) so integers keep their exact textual form,
// then emit sorted-key, no-whitespace, no-HTML-escape, no-trailing-
// newline bytes.  This is the byte sequence the server actually signs.
func serverCanonicalize(t *testing.T, raw []byte) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("server canonicalize decode: %v", err)
	}
	out, err := canonicalJSON(v)
	if err != nil {
		t.Fatalf("server canonicalize encode: %v", err)
	}
	return out
}

// signRawEnvelope signs the exact server-canonical bytes of a raw JSON
// payload and returns a {payload, signature, key_id} envelope whose
// payload field is the verbatim raw bytes (so the version integer is
// not pre-mangled by Go's float64 coercion before it ever reaches the
// verifier).
func signRawEnvelope(t *testing.T, priv ed25519.PrivateKey, keyID string, rawPayload []byte) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, serverCanonicalize(t, rawPayload))
	env := struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
		KeyID     string          `json:"key_id"`
	}{
		Payload:   json.RawMessage(rawPayload),
		Signature: base64.StdEncoding.EncodeToString(sig),
		KeyID:     keyID,
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal raw envelope: %v", err)
	}
	return out
}

func TestVerifyInstallGate_LargeIntVersionRoundTrips(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-bigint")
	// 9007199254740993 == 2^53 + 1, the smallest integer float64 cannot
	// represent exactly.  A float64-coercing verifier re-renders it as
	// 9007199254740992 and the signature check fails.
	raw := []byte(`{"version":9007199254740993,` +
		`"ecosystems":{"pypi":{"mode":"deny_list","entries":[]}},` +
		`"proxy_endpoints":{}}`)
	envelope := signRawEnvelope(t, priv, "ig-bigint", raw)

	m, err := VerifyInstallGateEnvelope(envelope)
	if err != nil {
		t.Fatalf("verify large-int version: %v", err)
	}
	if m.Version != 9007199254740993 {
		t.Errorf("version: got %d, want 9007199254740993", m.Version)
	}
}

func TestVerifyMapEnvelope_LargeIntVersionRoundTrips(t *testing.T) {
	priv := registerTestKey(t, "lm-bigint")
	raw := []byte(`{"version":9007199254740993,` +
		`"spdx_map":{"MIT License":"MIT"},` +
		`"tier_map":{"MIT":"permissive"}}`)
	envelope := signRawEnvelope(t, priv, "lm-bigint", raw)

	m, err := VerifyMapEnvelope(envelope)
	if err != nil {
		t.Fatalf("verify large-int version: %v", err)
	}
	if m.SPDXMap["MIT License"] != "MIT" {
		t.Errorf("spdx_map round-trip mismatch: %v", m.SPDXMap)
	}
}
