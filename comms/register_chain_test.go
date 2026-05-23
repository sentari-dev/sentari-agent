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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeCA returns a self-signed CA cert (PEM) and its private key.
func makeCA(t *testing.T, cn string) (caPEM []byte, key *ecdsa.PrivateKey, caCert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, _ = x509.ParseCertificate(der)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return caPEM, key, caCert
}

// signDeviceCert issues a device leaf cert signed by the given CA.
func signDeviceCert(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) []byte {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign device cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newRegServer(t *testing.T, caPEM, deviceCertPEM []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := RegisterResponse{
			DeviceID:   "dev-1",
			CACert:     string(caPEM),
			DeviceCert: string(deviceCertPEM),
			Message:    "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A device cert that does NOT chain to the returned CA must be rejected.
func TestRegisterRejectsMismatchedChain(t *testing.T) {
	// CA A is returned as ca_cert; device cert is signed by CA B (mismatch).
	caA, _, _ := makeCA(t, "ca-A")
	_, keyB, certB := makeCA(t, "ca-B")
	deviceCert := signDeviceCert(t, keyB, certB)

	srv := newRegServer(t, caA, deviceCert)
	c, err := NewClient(ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, _, err = c.RegisterWithToken(context.Background(), "host", "tok")
	if err == nil {
		t.Fatalf("RegisterWithToken: want chain-validation error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "chain") &&
		!strings.Contains(strings.ToLower(err.Error()), "verify") {
		t.Fatalf("error should mention chain/verify failure, got: %v", err)
	}
}

// A device cert correctly signed by the returned CA must be accepted.
func TestRegisterAcceptsValidChain(t *testing.T) {
	caA, keyA, certA := makeCA(t, "ca-A")
	deviceCert := signDeviceCert(t, keyA, certA)

	srv := newRegServer(t, caA, deviceCert)
	c, err := NewClient(ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, keyPEM, err := c.RegisterWithToken(context.Background(), "host", "tok")
	if err != nil {
		t.Fatalf("RegisterWithToken on valid chain: want nil, got %v", err)
	}
	if resp.DeviceID != "dev-1" || len(keyPEM) == 0 {
		t.Fatalf("unexpected response: %+v keyLen=%d", resp, len(keyPEM))
	}
}

// SaveCertificates must write device.crt at 0600 (private-key-adjacent
// secret), not the previous world-readable 0644.
func TestSaveCertificatesDeviceCertPerms(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCertificates(dir, []byte("ca"), []byte("dev"), []byte("key")); err != nil {
		t.Fatalf("SaveCertificates: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "device.crt"))
	if err != nil {
		t.Fatalf("stat device.crt: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("device.crt perms: want 0600, got %o", perm)
	}
}
