package comms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// signInstallGateEnvelope builds a signed install-gate policy-map envelope the
// agent will accept.  It mirrors signMapEnvelope (license-map) but pins the key
// under the install-gate trust store and emits an install-gate-shaped payload
// (a non-nil `ecosystems` map is mandatory — VerifyInstallGateEnvelope rejects
// a payload without it).
func signInstallGateEnvelope(t *testing.T, keyID string, version int) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	scanner.RegisterTrustedInstallGateKey(keyID, pub)

	payload := map[string]any{
		"version": version,
		"ecosystems": map[string]any{
			"pip": map[string]any{"entries": []any{}},
		},
		"proxy_endpoints": map[string]string{"pip": "https://proxy.example/pip"},
	}

	// Canonical form: sorted keys, HTML escaping off, no trailing newline —
	// byte-identical to scanner.canonicalJSON / the server canonicalizer, so
	// VerifyInstallGateEnvelope's re-canonicalize-then-verify step succeeds.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	canonical := bytes.TrimRight(buf.Bytes(), "\n")
	sig := ed25519.Sign(priv, canonical)

	env, err := json.Marshal(map[string]any{
		"payload":   payload,
		"signature": base64.StdEncoding.EncodeToString(sig),
		"key_id":    keyID,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return env
}

// Happy path: a valid signed envelope whose version is newer than the caller's
// currentVersion is verified and returned along with the raw envelope bytes.
func TestFetchInstallGateMap_HappyPathReturnsNewerMap(t *testing.T) {
	env := signInstallGateEnvelope(t, "comms-ig-happy", 42)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write(env)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchInstallGateMap(context.Background(), 1)
	if err != nil {
		t.Fatalf("FetchInstallGateMap error: %v", err)
	}
	if gotPath != "/api/v1/agent/policy-map" {
		t.Fatalf("path = %q, want /api/v1/agent/policy-map", gotPath)
	}
	if m == nil {
		t.Fatal("want an InstallGateMap, got nil")
	}
	if m.Version != 42 {
		t.Fatalf("version = %d, want 42", m.Version)
	}
	if m.Ecosystems == nil {
		t.Fatal("verified map must carry the decoded ecosystems block")
	}
	if !bytes.Equal(raw, env) {
		t.Fatal("returned raw bytes must equal the served envelope")
	}
}

// Version gating: a valid envelope whose version is not newer than the caller's
// currentVersion returns (nil, nil, nil) — no update, no error.
func TestFetchInstallGateMap_NotNewerReturnsNil(t *testing.T) {
	env := signInstallGateEnvelope(t, "comms-ig-gate", 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(env)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchInstallGateMap(context.Background(), 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil || raw != nil {
		t.Fatalf("want (nil,nil) when not newer, got m=%v rawLen=%d", m, len(raw))
	}
}

// Size cap: a response of MaxInstallGatePayloadBytes+1 bytes is rejected before
// signature verification, so an oversized body cannot exhaust memory.
func TestFetchInstallGateMap_OversizedRejected(t *testing.T) {
	oversized := bytes.Repeat([]byte("A"), scanner.MaxInstallGatePayloadBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchInstallGateMap(context.Background(), 1)
	if err == nil {
		t.Fatal("want size-cap error, got nil")
	}
	if m != nil || raw != nil {
		t.Fatal("want nil map/raw on size-cap rejection")
	}
	if !strings.Contains(err.Error(), "size cap") {
		t.Fatalf("error should mention size cap, got: %v", err)
	}
}

// A non-200 (503) status is surfaced as an error with no map returned.  (The
// 404 disable-signal and plain-404 cases live in install_gate_disabled_test.go.)
func TestFetchInstallGateMap_Non200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchInstallGateMap(context.Background(), 1)
	if err == nil {
		t.Fatal("want error on HTTP 503, got nil")
	}
	if m != nil || raw != nil {
		t.Fatal("want nil map/raw on error status")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error should mention status 503, got: %v", err)
	}
}

// A 200 whose body is a well-formed envelope signed by no pinned key fails
// signature verification.
func TestFetchInstallGateMap_VerifyFailureErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"payload":{"version":9,"ecosystems":{"pip":{"entries":[]}}},"signature":"AAAA","key_id":"nope"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, _, err := c.FetchInstallGateMap(context.Background(), 1)
	if err == nil {
		t.Fatal("want verify error, got nil")
	}
	if m != nil {
		t.Fatal("want nil map on verify failure")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Fatalf("error should mention verify, got: %v", err)
	}
}
