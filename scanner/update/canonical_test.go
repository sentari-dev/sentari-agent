package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestVerifyEnvelope_largeIntegerRoundTrips proves the canonicalization
// used during signature verification preserves integers >= 2^53.  The
// server (Python signing.canonical_json) renders these as integers; if
// the agent re-canonicalizes through map[string]interface{} every
// number becomes a float64 and large values lose precision / gain an
// exponent, so ed25519.Verify fails on a perfectly valid manifest.
//
// 9007199254740993 == 2^53 + 1 is the classic float64-unrepresentable
// integer.
func TestVerifyEnvelope_largeIntegerRoundTrips(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Build the signed payload as RAW JSON with the large integer
	// rendered exactly as the server would render it (no exponent, no
	// trailing .0).  Keys are pre-sorted so this raw form already equals
	// the canonical form.
	rawPayload := []byte(`{"latest_version":"1.0.0","min_supported_version":"0.1.0","platforms":{},"size_bytes":9007199254740993}`)

	// Sign over the canonical bytes.  Since the keys are sorted and
	// there is no insignificant whitespace, canonicalize(decode(raw))
	// must equal raw — that is exactly the property under test.
	sig := ed25519.Sign(priv, rawPayload)

	env, _ := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(rawPayload),
		"signature": base64.StdEncoding.EncodeToString(sig),
		"key_id":    "primary",
	})

	trusted := map[string]ed25519.PublicKey{"primary": pub}
	m, err := verifyEnvelope(env, trusted)
	if err != nil {
		t.Fatalf("verifyEnvelope rejected a valid large-integer payload: %v", err)
	}
	if m.LatestVersion != "1.0.0" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

// TestCanonicalizePayload_preservesLargeInt is the focused unit test on
// the canonicalization helper: round-tripping a payload with a large
// integer must not mutate the integer's textual form.
func TestCanonicalizePayload_preservesLargeInt(t *testing.T) {
	raw := []byte(`{"a":1,"size_bytes":9007199254740993,"z":"x"}`)
	got, err := canonicalizePayload(raw)
	if err != nil {
		t.Fatalf("canonicalizePayload: %v", err)
	}
	if !strings.Contains(string(got), "9007199254740993") {
		t.Fatalf("large integer not preserved; got %s", got)
	}
	if strings.Contains(string(got), "9.0072") || strings.Contains(string(got), "e+") {
		t.Fatalf("integer was rendered as float; got %s", got)
	}
}
