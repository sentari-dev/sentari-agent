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

// signedManifestServer is like envelopeServer but lets the caller set
// min_supported_version and (optionally) served_at so the
// downgrade/replay tests can drive those fields.
func signedManifestServer(t *testing.T, keyID string, priv ed25519.PrivateKey, version, minSupported, servedAt string, body []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	platformKey := runtime.GOOS + "/" + runtime.GOARCH
	binaryURL := "/api/v1/agent/release/binary/" + platformKey
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	payload := map[string]interface{}{
		"latest_version":        version,
		"min_supported_version": minSupported,
		"released_at":           "2026-05-22T10:00:00Z",
		"notes":                 "",
		"served_at":             servedAt,
		"platforms": map[string]interface{}{
			platformKey: map[string]interface{}{
				"url":        binaryURL,
				"sha256":     sha,
				"size_bytes": float64(len(body)),
				"filename":   "sentari-agent-" + version,
			},
		},
	}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	rawPayload, _ := json.Marshal(payload)
	envelopeBytes, _ := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(rawPayload),
		"signature": base64.StdEncoding.EncodeToString(sig),
		"key_id":    keyID,
	})
	mux.HandleFunc("/api/v1/agent/release/manifest", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(envelopeBytes)
	})
	mux.HandleFunc(binaryURL, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	return httptest.NewServer(mux)
}

func TestCheck_olderLatestNotUpgrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := signedManifestServer(t, "primary", priv, "0.1.0", "0.1.0", "2026-05-22T10:00:01Z", []byte("body"))
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0") // current newer than latest
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if plan.UpgradeAvailable {
		t.Fatalf("older latest must NOT be an upgrade; got %+v", plan)
	}
}

func TestCheck_equalLatestNotUpgrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := signedManifestServer(t, "primary", priv, "0.2.0", "0.1.0", "2026-05-22T10:00:01Z", []byte("body"))
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if plan.UpgradeAvailable {
		t.Fatalf("equal version must NOT be an upgrade; got %+v", plan)
	}
}

func TestCheck_newerLatestIsUpgrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := signedManifestServer(t, "primary", priv, "0.3.0", "0.1.0", "2026-05-22T10:00:01Z", []byte("body"))
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !plan.UpgradeAvailable {
		t.Fatalf("newer version must be an upgrade; got %+v", plan)
	}
}

func TestCheck_unparseableVersionErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := signedManifestServer(t, "primary", priv, "not-a-version", "0.1.0", "2026-05-22T10:00:01Z", []byte("body"))
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	_, err := c.Check()
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version parse error, got %v", err)
	}
}

func TestCheck_latestBelowMinSupportedRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// latest 0.5.0 but min_supported_version 1.0.0 — inconsistent /
	// malicious manifest; must be refused.
	srv := signedManifestServer(t, "primary", priv, "0.5.0", "1.0.0", "2026-05-22T10:00:01Z", []byte("body"))
	defer srv.Close()

	c := newClient(srv.URL, "primary", pub, "0.2.0")
	_, err := c.Check()
	if err == nil || !strings.Contains(err.Error(), "min_supported") {
		t.Fatalf("expected min_supported rejection, got %v", err)
	}
}

func TestApply_refusesDowngrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("older-binary")
	srv := signedManifestServer(t, "primary", priv, "0.1.0", "0.1.0", "2026-05-22T10:00:01Z", body)
	defer srv.Close()

	tmp := t.TempDir()
	installPath := filepath.Join(tmp, "sentari-agent")
	c := newClient(srv.URL, "primary", pub, "0.2.0")
	plan, err := c.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Force a plan that claims an upgrade to simulate a tampered caller;
	// Apply itself must independently refuse the downgrade.
	plan.UpgradeAvailable = true
	plan.Platform.URL = "/api/v1/agent/release/binary/" + runtime.GOOS + "/" + runtime.GOARCH
	sum := sha256.Sum256(body)
	plan.Platform.SHA256 = hex.EncodeToString(sum[:])
	plan.LatestVersion = "0.1.0"

	err = c.Apply(plan, installPath, filepath.Join(tmp, "staged"))
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("Apply must refuse downgrade, got %v", err)
	}
	// install path must be untouched (never created)
	if _, statErr := os.Stat(installPath); statErr == nil {
		t.Fatal("install path should not have been created on refused downgrade")
	}
}

var _ = bytes.Equal
