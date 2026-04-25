package scanner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// helper: register a fresh test key under the install-gate trust
// registry.  Distinct key_ids per test keep the registries from
// cross-contaminating; we deliberately do not restore on test exit
// because the registry is tested as append-only at runtime.
func registerInstallGateTestKey(t *testing.T, keyID string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	RegisterTrustedInstallGateKey(keyID, pub)
	return priv
}

// helper: build and sign an install-gate policy-map envelope using
// the canonicalJSON byte format the production verifier expects.
func signInstallGateEnvelope(t *testing.T, priv ed25519.PrivateKey, keyID string, payload map[string]interface{}) []byte {
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

// validInstallGatePayload returns a payload that exercises every
// schema field the verifier inspects: a populated ecosystem block,
// an empty ecosystem block, and a non-empty proxy_endpoints map.
func validInstallGatePayload() map[string]interface{} {
	return map[string]interface{}{
		"version": 1730901234,
		"ecosystems": map[string]interface{}{
			"pypi": map[string]interface{}{
				"mode": "deny_list",
				"entries": []interface{}{
					map[string]interface{}{
						"pattern":       "evil-pkg",
						"version_range": nil,
						"severity":      "critical",
						"reason":        "typosquat detected 2026-04-20",
						"scope_env_tag": nil,
						"expires_at":    nil,
					},
				},
			},
			"npm": map[string]interface{}{
				"mode":    "deny_list",
				"entries": []interface{}{},
			},
		},
		"proxy_endpoints": map[string]interface{}{
			"pypi": "https://sentari-proxy.test/pypi/",
			"npm":  "",
		},
	}
}

// --- VerifyInstallGateEnvelope -----------------------------------------

func TestVerifyInstallGate_RoundTrip(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-roundtrip")
	envelope := signInstallGateEnvelope(t, priv, "ig-roundtrip", validInstallGatePayload())

	m, err := VerifyInstallGateEnvelope(envelope)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.Version != 1730901234 {
		t.Errorf("version: got %d, want 1730901234", m.Version)
	}
	if m.Ecosystems["pypi"].Mode != "deny_list" {
		t.Errorf("pypi mode: got %q, want deny_list", m.Ecosystems["pypi"].Mode)
	}
	if got := len(m.Ecosystems["pypi"].Entries); got != 1 {
		t.Fatalf("pypi entries: got %d, want 1", got)
	}
	if m.Ecosystems["pypi"].Entries[0].Pattern != "evil-pkg" {
		t.Errorf("pypi entry pattern: got %q, want evil-pkg", m.Ecosystems["pypi"].Entries[0].Pattern)
	}
	if got := len(m.Ecosystems["npm"].Entries); got != 0 {
		t.Errorf("npm entries: got %d, want 0", got)
	}
	if m.ProxyEndpoints["pypi"] != "https://sentari-proxy.test/pypi/" {
		t.Errorf("proxy_endpoints[pypi]: %q", m.ProxyEndpoints["pypi"])
	}
}

func TestVerifyInstallGate_RejectsTamperedPayload(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-tamper")
	envelope := signInstallGateEnvelope(t, priv, "ig-tamper", validInstallGatePayload())

	// Decode, mutate the entry pattern, re-encode without re-signing.
	// The signature was computed over the original canonical bytes; the
	// re-encoded payload now disagrees, so verification must fail.
	var env map[string]interface{}
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	payload := env["payload"].(map[string]interface{})
	ecos := payload["ecosystems"].(map[string]interface{})
	pypi := ecos["pypi"].(map[string]interface{})
	entries := pypi["entries"].([]interface{})
	entries[0].(map[string]interface{})["pattern"] = "swapped"
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInstallGateEnvelope(tampered); err == nil {
		t.Fatal("expected verification failure on tampered payload")
	}
}

func TestVerifyInstallGate_RejectsUnknownKeyID(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-known")
	// Sign with a known key but stamp a different (un-pinned) key_id
	// in the envelope — this is the exact shape an attacker would
	// forge if they had stolen one channel's key.
	envelope := signInstallGateEnvelope(t, priv, "ig-not-pinned", validInstallGatePayload())
	if _, err := VerifyInstallGateEnvelope(envelope); err == nil {
		t.Fatal("expected verification failure on unknown key_id")
	}
}

func TestVerifyInstallGate_RejectsLicenseMapKeyID(t *testing.T) {
	// Channel-isolation guard: a key_id that is pinned for the
	// license-map registry must NOT validate an install-gate
	// envelope, even when the envelope is otherwise well-formed.
	// The two trust registries are intentionally disjoint.
	priv := registerTestKey(t, "license-map-only")
	envelope := signInstallGateEnvelope(t, priv, "license-map-only", validInstallGatePayload())
	if _, err := VerifyInstallGateEnvelope(envelope); err == nil {
		t.Fatal("license-map key_id must not validate install-gate envelopes")
	}
}

func TestVerifyInstallGate_RejectsEmpty(t *testing.T) {
	if _, err := VerifyInstallGateEnvelope(nil); err == nil {
		t.Error("expected error on nil input")
	}
	if _, err := VerifyInstallGateEnvelope([]byte{}); err == nil {
		t.Error("expected error on empty input")
	}
}

func TestVerifyInstallGate_RejectsOversize(t *testing.T) {
	oversize := make([]byte, MaxInstallGatePayloadBytes+1)
	if _, err := VerifyInstallGateEnvelope(oversize); err == nil {
		t.Error("expected error on oversize input")
	}
}

func TestVerifyInstallGate_RejectsMalformedJSON(t *testing.T) {
	if _, err := VerifyInstallGateEnvelope([]byte("not json")); err == nil {
		t.Error("expected error on malformed JSON")
	}
}

func TestVerifyInstallGate_RejectsMissingEcosystems(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-no-ecosystems")
	// Payload that's structurally valid (passes JSON + signature) but
	// lacks the ``ecosystems`` field.  Could be a forged payload
	// signed by a compromised key, or the agent talking to the wrong
	// envelope endpoint.  Refuse rather than silently apply nothing.
	payload := map[string]interface{}{
		"version":         1,
		"proxy_endpoints": map[string]interface{}{},
	}
	envelope := signInstallGateEnvelope(t, priv, "ig-no-ecosystems", payload)
	if _, err := VerifyInstallGateEnvelope(envelope); err == nil {
		t.Error("expected error when ecosystems field is missing")
	}
}

// --- Cache load + save -------------------------------------------------

func TestInstallGateCache_RoundTrip(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-cache")
	envelope := signInstallGateEnvelope(t, priv, "ig-cache", validInstallGatePayload())

	dir := t.TempDir()
	path := filepath.Join(dir, "policy_map.json")
	if err := SaveVerifiedInstallGateEnvelopeToFile(path, envelope); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Persisted file must be 0600 — the envelope embeds operator
	// notes (``reason`` field) that may contain incident references.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("cache file too permissive: %v", mode)
	}

	got, raw, err := LoadVerifiedInstallGateFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil {
		t.Fatal("load returned nil; expected map")
	}
	if got.Version != 1730901234 {
		t.Errorf("loaded version: got %d", got.Version)
	}
	if len(raw) != len(envelope) {
		t.Errorf("raw bytes round-trip: got %d, want %d", len(raw), len(envelope))
	}
}

func TestInstallGateCache_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	got, raw, err := LoadVerifiedInstallGateFromFile(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Errorf("missing-file load: unexpected error: %v", err)
	}
	if got != nil || raw != nil {
		t.Errorf("missing-file load: expected (nil, nil, nil), got (%v, %v, nil)", got, raw)
	}
}

func TestInstallGateCache_RefusesOversizeFile(t *testing.T) {
	// Hostile / corrupt cache file: write more bytes than the cap.
	// The bounded reader inside LoadVerifiedInstallGateFromFile must
	// stop before pulling the whole file into memory — we assert the
	// failure mode is "over-size error", not a verification error
	// triggered by the truncated bytes downstream.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_map.json")
	oversize := make([]byte, MaxInstallGatePayloadBytes+1024)
	if err := os.WriteFile(path, oversize, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadVerifiedInstallGateFromFile(path)
	if err == nil {
		t.Fatal("expected error on oversize cache file")
	}
}

func TestInstallGateCache_TamperedFileFailsVerify(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-cache-tamper")
	envelope := signInstallGateEnvelope(t, priv, "ig-cache-tamper", validInstallGatePayload())

	dir := t.TempDir()
	path := filepath.Join(dir, "policy_map.json")
	if err := SaveVerifiedInstallGateEnvelopeToFile(path, envelope); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Flip one byte in the middle of the file — same shape an attacker
	// would use if they had write access to the cache directory.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := LoadVerifiedInstallGateFromFile(path); err == nil {
		t.Fatal("expected verify failure on tampered cache file")
	}
}

// --- Trusted-key registry helpers --------------------------------------

func TestRegisterTrustedInstallGateKey_RejectsWrongLength(t *testing.T) {
	const keyID = "ig-bad-length"
	// Wrong-length pubkey must be silently dropped — the alternative
	// (panic at registration) would crash the agent every time it
	// reads a corrupted trust file.
	RegisterTrustedInstallGateKey(keyID, []byte{0x01, 0x02, 0x03})

	for _, id := range TrustedInstallGateKeyIDs() {
		if id == keyID {
			t.Errorf("short pubkey was accepted under key_id %q", keyID)
		}
	}
}

func TestTrustedInstallGateKeyIDs_SortedAndDeduplicated(t *testing.T) {
	// Re-register the same id with a fresh key — the registry is a
	// map, so the second registration overwrites the first.  The
	// listing helper must return each key_id exactly once.
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	RegisterTrustedInstallGateKey("zeta", pub1)
	RegisterTrustedInstallGateKey("zeta", pub2)
	RegisterTrustedInstallGateKey("alpha", pub1)

	ids := TrustedInstallGateKeyIDs()
	seenZeta := 0
	for _, id := range ids {
		if id == "zeta" {
			seenZeta++
		}
	}
	if seenZeta != 1 {
		t.Errorf("zeta seen %d times, want 1", seenZeta)
	}

	// Sort guarantee from the docstring — alpha < zeta.
	var alphaIdx, zetaIdx = -1, -1
	for i, id := range ids {
		switch id {
		case "alpha":
			alphaIdx = i
		case "zeta":
			zetaIdx = i
		}
	}
	if alphaIdx >= 0 && zetaIdx >= 0 && alphaIdx > zetaIdx {
		t.Errorf("ids not sorted: alpha at %d, zeta at %d", alphaIdx, zetaIdx)
	}
}
