//go:build enterprise

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// renewServerWithKeys is renewServer plus configurable signing-pubkey fields on
// the response, so a test can assert the post-renewal keyring reload picks up a
// rotated key_id.
func renewServerWithKeys(t *testing.T, caPEM []byte, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, resp comms.RegisterResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/renew" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		var body struct {
			CSR string `json:"csr"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		block, _ := pem.Decode([]byte(body.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "device"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
		resp.CACert = string(caPEM)
		resp.DeviceCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestMaybeRenew_HonorsConfigOverridePaths: when the cert material lives at
// config-overridden paths (NOT the dataDir/certs convention), renewal must
// read the expiring cert from and write the renewed cert to those exact
// override paths.  Asserting the override cert file is swapped to the renewed
// long-lived cert while no dataDir/certs/device.crt is ever created.
func TestMaybeRenew_HonorsConfigOverridePaths(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	srv := renewServerWithKeys(t, caPEM, caKey, caCert, comms.RegisterResponse{DeviceID: "dev-1"})

	// Override paths in a directory that is NOT <certDir> ("certs").
	overrideDir := t.TempDir()
	certFile := filepath.Join(overrideDir, "tls", "agent.pem")
	keyFile := filepath.Join(overrideDir, "tls", "agent.key")
	caFile := filepath.Join(overrideDir, "tls", "ca.pem")

	// certDir is the conventional dataDir/certs fallback — must stay empty.
	certDir := filepath.Join(t.TempDir(), "certs")

	// Seed the override paths with a soon-to-expire cert.
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(5*24*time.Hour))
	if err := comms.SaveCertificatesAtomicAt(
		comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed override certs: %v", err)
	}

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	rc := renewClientConfig{
		serverURL: srv.URL,
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		timeout:   5 * time.Second,
	}

	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()

	newClient := maybeRenewCertificate(context.Background(), client, rc, certDir, "host", auditLog)
	if newClient == client {
		t.Fatalf("expected a rebuilt client after a renewal at override paths")
	}

	// The override cert must be the renewed long-lived one.
	na, err := comms.DeviceCertNotAfterAt(certFile)
	if err != nil {
		t.Fatalf("read renewed override cert: %v", err)
	}
	if time.Until(na) < 300*24*time.Hour {
		t.Fatalf("override cert not swapped to renewed cert; remaining=%v", time.Until(na))
	}

	// The conventional dataDir/certs/device.crt must NOT have been written.
	if _, err := os.Stat(filepath.Join(certDir, "device.crt")); !os.IsNotExist(err) {
		t.Fatalf("renewal wrote to dataDir/certs instead of override paths (stat err=%v)", err)
	}
}

// TestMaybeRenew_ReloadsRotatedSigningKeyring: after a renewal that returns a
// rotated license-map signing key, the new key_id must be live in the in-memory
// scanner keyring (no daemon restart needed).
func TestMaybeRenew_ReloadsRotatedSigningKeyring(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)

	// A freshly-generated ed25519 pubkey with a unique key_id we can assert on.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	rotatedKeyID := "rotated-lm-key-" + t.Name()
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	srv := renewServerWithKeys(t, caPEM, caKey, caCert, comms.RegisterResponse{
		DeviceID:         "dev-1",
		LicenseMapKeyID:  rotatedKeyID,
		LicenseMapPubKey: pubB64,
	})

	certDir := filepath.Join(t.TempDir(), "certs")
	certFile := filepath.Join(certDir, "device.crt")
	keyFile := filepath.Join(certDir, "device.key")
	caFile := filepath.Join(certDir, "ca.crt")

	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(5*24*time.Hour))
	if err := comms.SaveCertificatesAtomicAt(
		comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certs: %v", err)
	}

	// Precondition: the rotated key_id must NOT be in the keyring yet.
	for _, id := range scanner.TrustedMapKeyIDs() {
		if id == rotatedKeyID {
			t.Fatalf("precondition failed: rotated key_id already present")
		}
	}

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	rc := renewClientConfig{
		serverURL: srv.URL,
		certFile:  certFile,
		keyFile:   keyFile,
		caFile:    caFile,
		timeout:   5 * time.Second,
	}
	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()

	maybeRenewCertificate(context.Background(), client, rc, certDir, "host", auditLog)

	found := false
	for _, id := range scanner.TrustedMapKeyIDs() {
		if id == rotatedKeyID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rotated license-map key_id %q not loaded into in-memory keyring after renewal", rotatedKeyID)
	}
}
