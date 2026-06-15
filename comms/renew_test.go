package comms

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
	"strings"
	"testing"
	"time"
)

// signCSRWithCA parses a PEM CSR, issues a leaf cert signed by the given CA,
// and returns the cert PEM.  Mirrors what the server's sign_csr does: the CSR
// public key is bound into a fresh leaf signed by the CA.
func signCSRWithCA(t *testing.T, csrPEM []byte, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, notAfter time.Time) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatalf("signCSRWithCA: CSR is not valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newRenewServer returns an httptest server mimicking POST /api/v1/agent/renew:
// it reads the CSR from the request body and signs it with the given CA,
// returning an AgentRegisterResponse-shaped bundle.
func newRenewServer(t *testing.T, caPEM []byte, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/renew" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "renew refused", status)
			return
		}
		var body struct {
			CSR string `json:"csr"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil || body.CSR == "" {
			http.Error(w, "missing csr", http.StatusBadRequest)
			return
		}
		deviceCert := signCSRWithCA(t, []byte(body.CSR), caKey, caCert, "renewed-device", time.Now().Add(365*24*time.Hour))
		resp := RegisterResponse{
			DeviceID:   "dev-1",
			CACert:     string(caPEM),
			DeviceCert: string(deviceCert),
			Message:    "renewed",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// RenewCertificate against a fake /renew that signs the CSR must return the
// new bundle and the new key, and the returned cert must chain to the CA.
func TestRenewCertificate_HappyPath(t *testing.T) {
	caPEM, caKey, caCert := makeCA(t, "ca-renew")
	srv := newRenewServer(t, caPEM, caKey, caCert, http.StatusOK)

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, keyPEM, err := c.RenewCertificate(context.Background(), "host")
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if resp.DeviceID != "dev-1" {
		t.Fatalf("unexpected device_id: %q", resp.DeviceID)
	}
	if len(keyPEM) == 0 {
		t.Fatalf("expected a fresh private key PEM")
	}
	// The returned cert must chain to the returned CA.
	if err := verifyDeviceCertChain([]byte(resp.DeviceCert), []byte(resp.CACert)); err != nil {
		t.Fatalf("renewed bundle should chain: %v", err)
	}
	// The fresh key must match the issued cert.
	if _, err := tlsKeyPairMatches(resp.DeviceCert, keyPEM); err != nil {
		t.Fatalf("fresh key must match renewed cert: %v", err)
	}
}

// A non-200 renew must return an error (caller keeps the current cert) and
// must not panic.
func TestRenewCertificate_NonOKErrors(t *testing.T) {
	caPEM, caKey, caCert := makeCA(t, "ca-renew")
	srv := newRenewServer(t, caPEM, caKey, caCert, http.StatusServiceUnavailable)

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.SetRetryConfig(RetryConfig{MaxAttempts: 1})

	resp, keyPEM, err := c.RenewCertificate(context.Background(), "host")
	if err == nil {
		t.Fatalf("RenewCertificate: want error on non-200, got nil")
	}
	if resp != nil || keyPEM != nil {
		t.Fatalf("on error want nil bundle/key, got %+v keyLen=%d", resp, len(keyPEM))
	}
}

// A renewed bundle whose device cert does not chain to the returned CA must
// be rejected (same guard as registration).
func TestRenewCertificate_RejectsMismatchedChain(t *testing.T) {
	caA, _, _ := makeCA(t, "ca-A")
	_, keyB, certB := makeCA(t, "ca-B")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CSR string `json:"csr"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		// Sign with CA B but return CA A as ca_cert (mismatch).
		deviceCert := signCSRWithCA(t, []byte(body.CSR), keyB, certB, "renewed-device", time.Now().Add(365*24*time.Hour))
		resp := RegisterResponse{
			DeviceID:   "dev-1",
			CACert:     string(caA),
			DeviceCert: string(deviceCert),
			Message:    "renewed",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, _, err = c.RenewCertificate(context.Background(), "host")
	if err == nil {
		t.Fatalf("RenewCertificate: want chain-validation error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "chain") &&
		!strings.Contains(strings.ToLower(err.Error()), "verify") {
		t.Fatalf("error should mention chain/verify failure, got: %v", err)
	}
}

// SaveCertificatesAtomic must write all three files, leave no .tmp residue,
// set 0600 on the key (matching SaveCertificates), and overwrite existing
// files atomically.
func TestSaveCertificatesAtomic_WritesAllNoResidue(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCertificatesAtomic(dir, []byte("ca-data"), []byte("dev-data"), []byte("key-data")); err != nil {
		t.Fatalf("SaveCertificatesAtomic: %v", err)
	}

	for name, want := range map[string]string{
		"ca.crt":     "ca-data",
		"device.crt": "dev-data",
		"device.key": "key-data",
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s content: want %q got %q", name, want, got)
		}
	}

	// Key must be 0600.
	info, err := os.Stat(filepath.Join(dir, "device.key"))
	if err != nil {
		t.Fatalf("stat device.key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("device.key perms: want 0600, got %o", perm)
	}
	// device.crt must be 0600 too (matches SaveCertificates).
	info, err = os.Stat(filepath.Join(dir, "device.crt"))
	if err != nil {
		t.Fatalf("stat device.crt: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("device.crt perms: want 0600, got %o", perm)
	}

	// No .tmp residue must remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

// A second SaveCertificatesAtomic must overwrite existing files in place.
func TestSaveCertificatesAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCertificatesAtomic(dir, []byte("ca-1"), []byte("dev-1"), []byte("key-1")); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := SaveCertificatesAtomic(dir, []byte("ca-2"), []byte("dev-2"), []byte("key-2")); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "device.crt"))
	if err != nil {
		t.Fatalf("read device.crt: %v", err)
	}
	if string(got) != "dev-2" {
		t.Fatalf("device.crt not overwritten: got %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file after overwrite: %s", e.Name())
		}
	}
}

// DeviceCertNotAfter must parse the NotAfter from device.crt.
func TestDeviceCertNotAfter_ParsesNotAfter(t *testing.T) {
	caPEM, caKey, caCert := makeCA(t, "ca-na")
	want := time.Now().Add(100 * 24 * time.Hour).Truncate(time.Second)

	// Issue a device cert with a known NotAfter via a CSR.
	csrPEM, keyPEM, err := buildCSR("host")
	if err != nil {
		t.Fatalf("buildCSR: %v", err)
	}
	_ = keyPEM
	deviceCert := signCSRWithCA(t, csrPEM, caKey, caCert, "host", want)

	dir := t.TempDir()
	if err := SaveCertificatesAtomic(dir, caPEM, deviceCert, []byte("key")); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := DeviceCertNotAfter(dir)
	if err != nil {
		t.Fatalf("DeviceCertNotAfter: %v", err)
	}
	if !got.Equal(want.UTC()) {
		t.Fatalf("NotAfter: want %v got %v", want.UTC(), got)
	}
}

// DeviceCertNotAfter on a missing/invalid cert must return an error, not panic.
func TestDeviceCertNotAfter_MissingErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := DeviceCertNotAfter(dir); err == nil {
		t.Fatalf("want error for missing device.crt, got nil")
	}
}

// buildCSR must produce a CSR a CA can sign and a key that matches the
// resulting cert — i.e. register and renew share the same CSR shape.
func TestBuildCSR_ProducesSignableCSR(t *testing.T) {
	_, caKey, caCert := makeCA(t, "ca-csr")
	csrPEM, keyPEM, err := buildCSR("my-host")
	if err != nil {
		t.Fatalf("buildCSR: %v", err)
	}
	if len(csrPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("empty csr/key")
	}

	// The CN must be the hostname.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatalf("csr not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if csr.Subject.CommonName != "my-host" {
		t.Fatalf("CN: want my-host got %q", csr.Subject.CommonName)
	}

	cert := signCSRWithCA(t, csrPEM, caKey, caCert, "my-host", time.Now().Add(24*time.Hour))
	// The private key must match the issued cert.
	if _, err := tlsKeyPairMatches(string(cert), keyPEM); err != nil {
		t.Fatalf("buildCSR key must match cert it produces: %v", err)
	}
}

// tlsKeyPairMatches verifies the PEM cert and PEM key form a valid keypair by
// loading them as a TLS keypair (which fails on mismatch).
func tlsKeyPairMatches(certPEM string, keyPEM []byte) (bool, error) {
	// Reuse the test EC P-256 key shape; ensure the key parses and matches the
	// cert public key.
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false, errNotPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return false, errNotPEM
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return false, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errNotPEM
	}
	if pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
		return false, errKeyMismatch
	}
	return true, nil
}

var (
	errNotPEM      = errStr("not PEM / unexpected key type")
	errKeyMismatch = errStr("key does not match cert")
)

type errStr string

func (e errStr) Error() string { return string(e) }

// ensure elliptic is referenced (buildCSR uses P256 internally; keep import
// for the parity helper above if needed).
var _ = elliptic.P256
