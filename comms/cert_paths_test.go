package comms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// leafWithKey issues a device leaf cert (PEM) plus its private key (PEM)
// signed by the given CA — the cert_paths round-trip test needs the key too,
// which signDeviceCert (register_chain_test.go) does not return.
func leafWithKey(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (certPEM, keyPEM []byte) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
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

// TestCertsExistAt_HonorsExplicitPaths: when an operator overrides the cert
// file locations in config, the registration gate must check those exact
// paths, not a fallback <dir>/device.crt convention.  A device with valid
// certs at custom paths must NOT be told to re-register.
func TestCertsExistAt_HonorsExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "custom-device.pem")
	keyFile := filepath.Join(dir, "custom-device.key")
	caFile := filepath.Join(dir, "custom-ca.pem")

	p := CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}

	if CertsExistAt(p) {
		t.Fatal("CertsExistAt must be false before any file is written")
	}

	for _, f := range []string{certFile, keyFile, caFile} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	if !CertsExistAt(p) {
		t.Fatal("CertsExistAt must be true once all three explicit files exist")
	}

	// Removing one file must flip the gate back to false.
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if CertsExistAt(p) {
		t.Fatal("CertsExistAt must be false when a file is missing")
	}
}

// TestSaveAndReadCertificatesAtomicAt_RoundTrip: the atomic saver must write
// the bundle to the explicit override paths (which may be three different
// directories) and DeviceCertNotAfterAt must read the cert back from its
// explicit path.
func TestSaveAndReadCertificatesAtomicAt_RoundTrip(t *testing.T) {
	caPEM, caKey, caCert := makeCA(t, "test-ca")
	certPEM, keyPEM := leafWithKey(t, caKey, caCert)

	// Three distinct directories to prove no <dir>/name derivation is used.
	certDir := t.TempDir()
	keyDir := t.TempDir()
	caDir := t.TempDir()
	certFile := filepath.Join(certDir, "device.pem")
	keyFile := filepath.Join(keyDir, "device.key")
	caFile := filepath.Join(caDir, "ca.pem")

	p := CertFilePaths{CertFile: certFile, KeyFile: keyFile, CAFile: caFile}

	if err := SaveCertificatesAtomicAt(p, caPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("SaveCertificatesAtomicAt: %v", err)
	}

	for _, f := range []string{certFile, keyFile, caFile} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("expected %s to exist: %v", f, err)
		}
	}

	// device cert and key must be 0600.
	for _, f := range []string{certFile, keyFile} {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s too permissive: %v", f, info.Mode().Perm())
		}
	}

	na, err := DeviceCertNotAfterAt(certFile)
	if err != nil {
		t.Fatalf("DeviceCertNotAfterAt: %v", err)
	}
	if na.IsZero() {
		t.Fatalf("unexpected zero NotAfter")
	}
}
