package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// envelopeServer builds a tiny httptest server that serves a signed
// manifest at /api/v1/agent/release/manifest and the per-platform
// binary at /api/v1/agent/release/binary/<os>/<arch>.  Reused across
// most tests so we exercise the real wire flow end-to-end.
func envelopeServer(t *testing.T, keyID string, priv ed25519.PrivateKey, version string, body []byte) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	platformKey := runtime.GOOS + "/" + runtime.GOARCH
	binaryURL := "/api/v1/agent/release/binary/" + platformKey
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	payload := map[string]interface{}{
		"latest_version":        version,
		"min_supported_version": "0.1.0",
		"released_at":           "2026-05-22T10:00:00Z",
		"notes":                 "",
		"served_at":             "2026-05-22T10:00:01Z",
		"platforms": map[string]interface{}{
			platformKey: map[string]interface{}{
				"url":        binaryURL,
				"sha256":     sha,
				"size_bytes": float64(len(body)),
				"filename":   "sentari-agent-" + version + "-" + runtime.GOOS + "-" + runtime.GOARCH,
			},
		},
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonicalize payload: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	envelopeBytes, err := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(rawPayload),
		"signature": base64.StdEncoding.EncodeToString(sig),
		"key_id":    keyID,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	mux.HandleFunc("/api/v1/agent/release/manifest", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelopeBytes)
	})
	mux.HandleFunc(binaryURL, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	})
	return httptest.NewServer(mux)
}

func newClient(srvURL string, keyID string, pub ed25519.PublicKey, current string) *Client {
	return &Client{
		HTTPClient:  http.DefaultClient,
		ServerURL:   srvURL,
		TrustedKeys: map[string]ed25519.PublicKey{keyID: pub},
		CurrentVer:  current,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
	}
}

func TestCheck_envelopeVerifiedAndUpgradeAdvertised(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binaryBody := bytes.Repeat([]byte("#!fake\n"), 100)
	srv := envelopeServer(t, "primary", priv, "0.2.0", binaryBody)
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.1.3")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !plan.UpgradeAvailable {
		t.Fatalf("expected upgrade advertised; got plan=%+v", plan)
	}
	if plan.LatestVersion != "0.2.0" || plan.CurrentVersion != "0.1.3" {
		t.Fatalf("version mismatch in plan: %+v", plan)
	}
	if plan.Platform.SHA256 == "" || plan.Platform.URL == "" {
		t.Fatalf("platform manifest empty: %+v", plan.Platform)
	}
}

func TestCheck_unknownKeyIDRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := envelopeServer(t, "primary", priv, "0.2.0", []byte("body"))
	defer srv.Close()

	// Pin under a DIFFERENT key id — verification must refuse to look
	// up an unknown key rather than silently fall back.
	c := newClient(srv.URL, "secondary", pub, "0.1.0")
	_, err := c.Check()
	if err == nil || !strings.Contains(err.Error(), "unknown signing key_id") {
		t.Fatalf("expected unknown-key error, got %v", err)
	}
}

func TestCheck_tamperedPayloadRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := envelopeServer(t, "primary", priv, "0.2.0", []byte("body"))
	defer srv.Close()

	// Wrap the real server in a proxy that mutates the payload's
	// latest_version field after the signature is computed.  The
	// signature must no longer verify.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(srv.URL + r.URL.Path)
		if err != nil {
			t.Fatalf("proxy fetch: %v", err)
		}
		defer resp.Body.Close()
		var env map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			t.Fatalf("proxy decode: %v", err)
		}
		// Tamper: replace inside the signed payload.
		rawPayload, _ := json.Marshal(env["payload"])
		mangled := strings.ReplaceAll(string(rawPayload), "0.2.0", "9.9.9")
		env["payload"] = json.RawMessage(mangled)
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer proxy.Close()

	c := newClient(proxy.URL, "primary", pub, "0.1.0")
	_, err := c.Check()
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature failure on tampered payload, got %v", err)
	}
}

func TestCheck_404TreatedAsNoUpgrade(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no release", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.1.3")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check should not error on 404, got %v", err)
	}
	if plan.UpgradeAvailable {
		t.Fatalf("404 must mean no upgrade; got %+v", plan)
	}
	if plan.CurrentVersion != "0.1.3" {
		t.Fatalf("current version should be preserved on 404; got %+v", plan)
	}
}

func TestApply_downloadAndAtomicReplaceWithRollback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("#!fake-binary v0.2.0\n" + strings.Repeat("x", 4096))
	srv := envelopeServer(t, "primary", priv, "0.2.0", body)
	defer srv.Close()

	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	// Seed an existing "old" binary so .prev preservation is exercised.
	if err := os.WriteFile(installPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := newClient(srv.URL, "primary", pub, "0.1.3")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !plan.UpgradeAvailable {
		t.Fatalf("expected upgrade; got %+v", plan)
	}

	// Apply will reach restartService at the end — on darwin that
	// shells out to launchctl which isn't running in the test
	// environment, so we expect the binary swap to succeed but the
	// restart to surface as a wrapped error.  Either way we verify
	// the install path holds the new bytes.
	applyErr := c.Apply(plan, installPath, filepath.Join(tmp, "staged"))
	// applyErr might be nil (linux/CI sometimes), or the wrapped
	// "service restart failed" — accept both.  What MUST be true is
	// the binary swap completed before the restart attempt.
	if applyErr != nil && !strings.Contains(applyErr.Error(), "service restart") {
		t.Fatalf("Apply failed before swap: %v", applyErr)
	}
	gotNew, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if !bytes.Equal(gotNew, body) {
		t.Fatal("install path does not contain the new binary bytes")
	}
	gotPrev, err := os.ReadFile(installPath + ".prev")
	if err != nil {
		t.Fatalf("read .prev: %v", err)
	}
	if !bytes.Equal(gotPrev, []byte("old-binary")) {
		t.Fatalf(".prev does not hold the original binary; got %q", gotPrev)
	}

	// Rollback path: should swap them back.  restartService failing
	// is again non-fatal for the swap itself.
	rollbackErr := Rollback(installPath)
	if rollbackErr != nil && !strings.Contains(rollbackErr.Error(), "service restart") &&
		!strings.Contains(rollbackErr.Error(), "launchctl") &&
		!strings.Contains(rollbackErr.Error(), "systemctl") {
		t.Fatalf("Rollback failed unexpectedly: %v", rollbackErr)
	}
	restored, _ := os.ReadFile(installPath)
	if !bytes.Equal(restored, []byte("old-binary")) {
		t.Fatalf("rollback did not restore original binary; got %q", restored)
	}
	stagedAgain, _ := os.ReadFile(installPath + ".prev")
	if !bytes.Equal(stagedAgain, body) {
		t.Fatalf("rollback did not move new binary to .prev; got %q", stagedAgain)
	}
}

func TestApply_sha256MismatchAborts(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("real-body")
	srv := envelopeServer(t, "primary", priv, "0.2.0", body)
	defer srv.Close()

	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	if err := os.WriteFile(installPath, []byte("untouched"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := newClient(srv.URL, "primary", pub, "0.1.0")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Tamper the SHA in the plan so the manifest no longer matches the
	// downloaded bytes — simulates an attacker substituting the
	// binary in the release dir between hash and serve.
	plan.Platform.SHA256 = strings.Repeat("00", 32)

	err = c.Apply(plan, installPath, filepath.Join(tmp, "staged"))
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch error, got %v", err)
	}
	// Install path must be untouched on aborted Apply.
	cur, _ := os.ReadFile(installPath)
	if !bytes.Equal(cur, []byte("untouched")) {
		t.Fatal("install path was clobbered despite failed Apply")
	}
}

func TestRollback_noPrev(t *testing.T) {
	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	if err := os.WriteFile(installPath, []byte("only-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Rollback(installPath)
	if err == nil || !strings.Contains(err.Error(), "no previous") {
		t.Fatalf("expected no-previous error, got %v", err)
	}
}
