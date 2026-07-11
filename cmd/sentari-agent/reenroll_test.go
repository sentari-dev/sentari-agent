//go:build enterprise

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/comms"
)

// registerServer stands in for the server's /api/v1/agent/register endpoint:
// it signs the posted CSR with the test CA and returns a register-shaped bundle
// whose device cert chains to the returned CA (so RegisterWithToken's
// verifyDeviceCertChain accepts it).  Records whether it was hit.
func registerServer(t *testing.T, caPEM []byte, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, hit *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/register" {
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
		resp := comms.RegisterResponse{
			DeviceID:   "dev-reenrolled",
			CACert:     string(caPEM),
			DeviceCert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			Message:    "registered",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func auditEntryTypes(t *testing.T, a *audit.AuditLog) []string {
	t.Helper()
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	types := make([]string, 0, len(entries))
	for _, e := range entries {
		types = append(types, e["event_type"])
	}
	return types
}

func hasAuditType(types []string, want string) bool {
	for _, tp := range types {
		if tp == want {
			return true
		}
	}
	return false
}

// TestMaybeReenroll_ValidCertIsNoop: with a still-valid device cert on disk the
// re-enrollment path must be a no-op — the same client is returned and the
// register server is never contacted.
func TestMaybeReenroll_ValidCertIsNoop(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	var hit bool
	srv := registerServer(t, caPEM, caKey, caCert, &hit)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "device.crt")
	keyFile := filepath.Join(dir, "device.key")
	caFile := filepath.Join(dir, "ca.crt")
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(200*24*time.Hour))
	if err := comms.SaveCertificatesAtomicAt(
		comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certs: %v", err)
	}

	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	bp := bootstrapParams{
		serverURL:   srv.URL,
		enrollToken: "tok",
		certPaths:   comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		certDir:     dir,
	}
	rc := renewClientConfig{serverURL: srv.URL, certFile: certFile, keyFile: keyFile, caFile: caFile, timeout: 5 * time.Second}

	got := maybeReenrollOnExpiredCert(context.Background(), client, bp, rc, "host", nil)
	if got != client {
		t.Fatal("valid cert must return the unchanged client")
	}
	if hit {
		t.Fatal("register must not be contacted while the cert is still valid")
	}
}

// TestMaybeReenroll_UnreadableCertIsNoop: when no cert exists yet (first-issuance
// is owned by the register path, not this recovery path), the same client is
// returned without contacting the server.
func TestMaybeReenroll_UnreadableCertIsNoop(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	var hit bool
	srv := registerServer(t, caPEM, caKey, caCert, &hit)

	dir := t.TempDir()
	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	bp := bootstrapParams{
		serverURL:   srv.URL,
		enrollToken: "tok",
		certPaths:   comms.CertFilePaths{CertFile: filepath.Join(dir, "missing.crt")},
		certDir:     dir,
	}
	got := maybeReenrollOnExpiredCert(context.Background(), client, bp, renewClientConfig{}, "host", nil)
	if got != client {
		t.Fatal("unreadable cert must return the unchanged client")
	}
	if hit {
		t.Fatal("register must not be contacted when the cert can't be read")
	}
}

// TestMaybeReenroll_ExpiredNoTokenLogsAndKeepsClient: an EXPIRED cert with NO
// enrollment token must not attempt re-enrollment; it keeps the current client
// and records a cert.expired_no_token audit entry (finding offline-7 — a loud,
// actionable error instead of a per-request TLS flood).
func TestMaybeReenroll_ExpiredNoTokenLogsAndKeepsClient(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	var hit bool
	srv := registerServer(t, caPEM, caKey, caCert, &hit)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "device.crt")
	keyFile := filepath.Join(dir, "device.key")
	caFile := filepath.Join(dir, "ca.crt")
	// Cert that lapsed an hour ago.
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(-time.Hour))
	if err := comms.SaveCertificatesAtomicAt(
		comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certs: %v", err)
	}

	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()

	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	bp := bootstrapParams{
		serverURL:   srv.URL,
		enrollToken: "", // no token → cannot self-heal
		certPaths:   comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		certDir:     dir,
	}

	got := maybeReenrollOnExpiredCert(context.Background(), client, bp, renewClientConfig{}, "host", auditLog)
	if got != client {
		t.Fatal("expired-no-token must keep the current client (nothing to swap to)")
	}
	if hit {
		t.Fatal("register must not be contacted with no enrollment token")
	}
	if !hasAuditType(auditEntryTypes(t, auditLog), "cert.expired_no_token") {
		t.Fatal("expected a cert.expired_no_token audit entry")
	}
}

// TestMaybeReenroll_ExpiredWithTokenReenrolls: an EXPIRED cert WITH an enrollment
// token re-runs the bootstrap registration, persists a fresh long-lived cert to
// the resolved cert paths, rebuilds the mTLS client (so a NEW client is
// returned), and records an agent.reenrolled audit entry.  Exercises the full
// maybeReenrollOnExpiredCert → reenrollWithToken → registerAndSaveCerts chain.
func TestMaybeReenroll_ExpiredWithTokenReenrolls(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	var hit bool
	srv := registerServer(t, caPEM, caKey, caCert, &hit)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "device.crt")
	keyFile := filepath.Join(dir, "device.key")
	caFile := filepath.Join(dir, "ca.crt")
	// Seed an already-expired cert; the token path should replace it.
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(-time.Hour))
	if err := comms.SaveCertificatesAtomicAt(
		comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certs: %v", err)
	}

	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	defer auditLog.Close()

	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	certPaths := comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}
	bp := bootstrapParams{
		serverURL:   srv.URL,
		enrollToken: "enroll-tok",
		certPaths:   certPaths,
		certDir:     dir,
	}
	rc := renewClientConfig{serverURL: srv.URL, certFile: certFile, keyFile: keyFile, caFile: caFile, timeout: 5 * time.Second}

	got := maybeReenrollOnExpiredCert(context.Background(), client, bp, rc, "host", auditLog)
	if !hit {
		t.Fatal("register endpoint must be contacted for a token-driven re-enrollment")
	}
	if got == client {
		t.Fatal("a successful re-enrollment must return a rebuilt mTLS client")
	}
	// The on-disk cert must now be the fresh long-lived one, not the expired seed.
	na, err := comms.DeviceCertNotAfterAt(certFile)
	if err != nil {
		t.Fatalf("read re-enrolled cert: %v", err)
	}
	if time.Until(na) < 300*24*time.Hour {
		t.Fatalf("cert not replaced with the re-enrolled long-lived cert; remaining=%v", time.Until(na))
	}
	types := auditEntryTypes(t, auditLog)
	if !hasAuditType(types, "agent.reenrolled") {
		t.Fatalf("expected an agent.reenrolled audit entry, got %v", types)
	}
	if !hasAuditType(types, "agent.registered") {
		t.Fatalf("expected an agent.registered audit entry from registerAndSaveCerts, got %v", types)
	}
	// The server-assigned device id must have been persisted by registerAndSaveCerts.
	if got := comms.LoadDeviceID(dir); got != "dev-reenrolled" {
		t.Fatalf("device id = %q, want dev-reenrolled", got)
	}
}

// TestMaybeReenroll_ExpiredWithTokenFailureKeepsClient: when the register server
// is down, the token path fails, and maybeReenrollOnExpiredCert must keep the
// current (expired) client to retry next cycle rather than dropping it.
func TestMaybeReenroll_ExpiredWithTokenFailureKeepsClient(t *testing.T) {
	caPEM, caKey, caCert := testCA(t)
	// 400 is a hard (non-retryable) rejection, so RegisterWithToken fails fast
	// instead of running the bootstrap client's retry/backoff schedule.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rejected", http.StatusBadRequest)
	}))
	t.Cleanup(down.Close)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "device.crt")
	keyFile := filepath.Join(dir, "device.key")
	caFile := filepath.Join(dir, "ca.crt")
	certPEM, keyPEM := issueDeviceCert(t, caKey, caCert, time.Now().Add(-time.Hour))
	if err := comms.SaveCertificatesAtomicAt(
		comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile},
		caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certs: %v", err)
	}

	client, _ := comms.NewClient(comms.ClientConfig{ServerURL: down.URL, Timeout: 5 * time.Second})
	certPaths := comms.CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}
	bp := bootstrapParams{
		serverURL:   down.URL,
		enrollToken: "enroll-tok",
		certPaths:   certPaths,
		certDir:     dir,
	}
	rc := renewClientConfig{serverURL: down.URL, certFile: certFile, keyFile: keyFile, caFile: caFile, timeout: 5 * time.Second}

	got := maybeReenrollOnExpiredCert(context.Background(), client, bp, rc, "host", nil)
	if got != client {
		t.Fatal("a failed re-enrollment must keep the current client for a later retry")
	}
}
