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

// --- PollConfig -------------------------------------------------------------

// Happy path: a 200 with a well-formed AgentConfig body is decoded and every
// field is mapped from its JSON tag.
func TestPollConfig_HappyPathDecodes(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scan_interval":3600,"scan_root":"/opt","max_depth":7,"config_version":"v9"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	cfg, err := c.PollConfig(context.Background())
	if err != nil {
		t.Fatalf("PollConfig error: %v", err)
	}
	if gotPath != "/api/v1/agent/config" {
		t.Fatalf("path = %q, want /api/v1/agent/config", gotPath)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method = %q, want GET", gotMethod)
	}
	if cfg.ScanInterval != 3600 || cfg.ScanRoot != "/opt" || cfg.MaxDepth != 7 || cfg.Version != "v9" {
		t.Fatalf("decoded config mismatch: %+v", cfg)
	}
}

// A non-200 status is a transport/auth failure: no config is returned and the
// HTTP status is surfaced in the error.
func TestPollConfig_Non200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	cfg, err := c.PollConfig(context.Background())
	if err == nil {
		t.Fatal("want error on HTTP 503, got nil")
	}
	if cfg != nil {
		t.Fatalf("want nil config on error, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error should mention status 503, got: %v", err)
	}
}

// A 200 whose body is not valid JSON exercises the decode-error branch (the
// body is read through a bounded io.LimitReader before decoding).
func TestPollConfig_MalformedBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	if _, err := c.PollConfig(context.Background()); err == nil {
		t.Fatal("want decode error on malformed body, got nil")
	}
}

// --- FetchLicenseMap --------------------------------------------------------

// signMapEnvelope builds a signed license-map envelope the agent will accept:
// it pins an ephemeral key under keyID and signs the canonical form of the
// payload, mirroring scanner's signed_map_test helpers but from this package.
func signMapEnvelope(t *testing.T, keyID string, version int) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	scanner.RegisterTrustedMapKey(keyID, pub)

	payload := map[string]any{
		"version":  version,
		"spdx_map": map[string]string{"MIT License": "MIT"},
		"tier_map": map[string]string{"MIT": "permissive"},
	}

	// Canonical form: sorted keys, HTML escaping off, no trailing newline —
	// byte-identical to scanner.canonicalJSON / the server canonicalizer, so
	// VerifyMapEnvelope's re-canonicalize-then-verify step succeeds.
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
// currentVersion is verified and returned along with the raw envelope bytes
// (so the caller can cache them for offline reuse).
func TestFetchLicenseMap_HappyPathReturnsNewerMap(t *testing.T) {
	env := signMapEnvelope(t, "comms-fetch-happy", 42)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write(env)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchLicenseMap(context.Background(), 1)
	if err != nil {
		t.Fatalf("FetchLicenseMap error: %v", err)
	}
	if gotPath != "/api/v1/agent/license-map" {
		t.Fatalf("path = %q, want /api/v1/agent/license-map", gotPath)
	}
	if m == nil {
		t.Fatal("want a LicenseMap, got nil")
	}
	if m.Version != 42 {
		t.Fatalf("version = %d, want 42", m.Version)
	}
	if !bytes.Equal(raw, env) {
		t.Fatal("returned raw bytes must equal the served envelope")
	}
}

// Version gating: a valid envelope whose version is not newer than the
// caller's currentVersion returns (nil, nil, nil) — no update, no error.
func TestFetchLicenseMap_NotNewerReturnsNil(t *testing.T) {
	env := signMapEnvelope(t, "comms-fetch-gate", 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(env)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	// currentVersion == served version (5): m.Version <= currentVersion gates.
	m, raw, err := c.FetchLicenseMap(context.Background(), 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil || raw != nil {
		t.Fatalf("want (nil,nil) when not newer, got m=%v rawLen=%d", m, len(raw))
	}
}

// Size cap: a response exceeding scanner.MaxMapPayloadBytes is rejected before
// signature verification, so an oversized body cannot exhaust memory.
func TestFetchLicenseMap_OversizedRejected(t *testing.T) {
	oversized := bytes.Repeat([]byte("A"), scanner.MaxMapPayloadBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchLicenseMap(context.Background(), 1)
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

// A non-200 status is surfaced as an error with no map returned.
func TestFetchLicenseMap_Non200Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, raw, err := c.FetchLicenseMap(context.Background(), 1)
	if err == nil {
		t.Fatal("want error on HTTP 500, got nil")
	}
	if m != nil || raw != nil {
		t.Fatal("want nil map/raw on error status")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention status 500, got: %v", err)
	}
}

// A 200 whose body is not a valid signed envelope fails signature verification
// (the envelope is well-formed JSON but signed by no pinned key).
func TestFetchLicenseMap_VerifyFailureErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"payload":{"version":9,"spdx_map":{"MIT License":"MIT"},"tier_map":{"MIT":"permissive"}},"signature":"AAAA","key_id":"nope"}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	m, _, err := c.FetchLicenseMap(context.Background(), 1)
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
