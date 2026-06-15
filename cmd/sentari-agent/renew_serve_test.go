//go:build enterprise

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
)

// testCA returns a self-signed CA (PEM + key + parsed cert).
func testCA(t *testing.T) (caPEM []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, _ = x509.ParseCertificate(der)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return caPEM, key, cert
}

// issueDeviceCert issues a device leaf cert (PEM) + its key (PEM) signed by ca,
// with the given NotAfter.
func issueDeviceCert(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kDER})
	return certPEM, keyPEM
}

// renewServer signs the posted CSR with the CA and returns a register-shaped
// bundle.  Records whether it was hit.
func renewServer(t *testing.T, caPEM []byte, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, hit *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/renew" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		*hit = true
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
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		resp := comms.RegisterResponse{
			DeviceID:   "dev-1",
			CACert:     string(caPEM),
			DeviceCert: string(certPEM),
			Message:    "renewed",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeBundle(t *testing.T, dir string, caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	if err := comms.SaveCertificatesAtomic(dir, caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

// Within-window cert triggers a renewal and the on-disk cert is swapped to the
// freshly-issued (far-future) one.
func TestMaybeRenew_WithinWindowRenews(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	var hit bool
	srv := renewServer(t, caPEM, caKey, caCert, &hit)

	dir := t.TempDir()
	// Cert expiring in 5 days — inside the 30-day window.
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(5*24*time.Hour))
	writeBundle(t, dir, caPEM, certPEM, keyPEM)

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	rc := renewClientConfig{
		serverURL: srv.URL,
		certFile:  filepath.Join(dir, "device.crt"),
		keyFile:   filepath.Join(dir, "device.key"),
		caFile:    filepath.Join(dir, "ca.crt"),
		timeout:   5 * time.Second,
	}

	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()

	newClient := maybeRenewCertificate(context.Background(), client, rc, dir, "host", auditLog)
	if !hit {
		t.Fatalf("expected /renew to be hit within window")
	}
	if newClient == client {
		t.Fatalf("expected a rebuilt client after successful renewal")
	}
	// On-disk cert must now be the renewed (far-future) one.
	na, err := comms.DeviceCertNotAfter(dir)
	if err != nil {
		t.Fatalf("read renewed NotAfter: %v", err)
	}
	if time.Until(na) < 300*24*time.Hour {
		t.Fatalf("on-disk cert not swapped to renewed long-lived cert; remaining=%v", time.Until(na))
	}
}

// Outside-window cert is a no-op: server is never hit and the same client comes
// back.
func TestMaybeRenew_OutsideWindowNoop(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	var hit bool
	srv := renewServer(t, caPEM, caKey, caCert, &hit)

	dir := t.TempDir()
	// Cert valid for 200 days — well outside the 30-day window.
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(200*24*time.Hour))
	writeBundle(t, dir, caPEM, certPEM, keyPEM)

	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	rc := renewClientConfig{serverURL: srv.URL}

	newClient := maybeRenewCertificate(context.Background(), client, rc, dir, "host", nil)
	if hit {
		t.Fatalf("renew must not be attempted outside the window")
	}
	if newClient != client {
		t.Fatalf("client must be unchanged outside the window")
	}
}

// A failing renew (server 503) is non-fatal: same client returned, on-disk cert
// untouched.
func TestMaybeRenew_FailureNonFatal(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(5*24*time.Hour))
	writeBundle(t, dir, caPEM, certPEM, keyPEM)
	before, _ := os.ReadFile(filepath.Join(dir, "device.crt"))

	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})
	rc := renewClientConfig{serverURL: srv.URL}

	newClient := maybeRenewCertificate(context.Background(), client, rc, dir, "host", nil)
	if newClient != client {
		t.Fatalf("client must be unchanged on renewal failure")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "device.crt"))
	if string(before) != string(after) {
		t.Fatalf("on-disk cert must be untouched on renewal failure")
	}
}

// Missing cert dir is a safe no-op (no panic), same client returned.
func TestMaybeRenew_MissingCertNoop(t *testing.T) {
	dir := t.TempDir()
	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: "https://unused.invalid", Timeout: time.Second})
	rc := renewClientConfig{serverURL: "https://unused.invalid"}
	newClient := maybeRenewCertificate(context.Background(), client, rc, dir, "host", nil)
	if newClient != client {
		t.Fatalf("client must be unchanged when no cert exists")
	}
}
