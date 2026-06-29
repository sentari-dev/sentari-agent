package comms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Bootstrap trust precedence tests.
//
// The trust ladder the client must implement:
//  1. CACertFile configured  -> standard chain validation against that pool;
//     never InsecureSkipVerify.
//  2. CACertFile + fingerprint -> chain validation AND fingerprint pin
//     (VerifyConnection runs after chain validation as an additional check).
//  3. Fingerprint only        -> InsecureSkipVerify with manual pin via
//     VerifyConnection (no CA to chain-walk against).
//  4. Neither                 -> OS trust store, but the fallback must be
//     loud: a warning is logged at registration.

// signServerCert issues a TLS server leaf for 127.0.0.1/localhost signed by
// the given CA, returned as a ready-to-serve tls.Certificate plus the leaf
// DER (for fingerprinting).
func signServerCert(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (tls.Certificate, []byte) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen server leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign server cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}, der
}

// newPinnedTLSServer starts an HTTPS test server presenting the given cert.
func newPinnedTLSServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// writeCAFile writes a PEM CA cert to a temp file and returns its path.
func writeCAFile(t *testing.T, caPEM []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

// leafFingerprint returns the lowercase hex SHA-256 of the leaf DER.
func leafFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// tlsConfigOf digs the tls.Config out of a built client so tests can assert
// on the trust-anchor fields directly.
func tlsConfigOf(t *testing.T, c *Client) *tls.Config {
	t.Helper()
	tr, ok := c.HTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.HTTPClient().Transport)
	}
	return tr.TLSClientConfig
}

// 1. CA-configured bootstrap: standard chain validation, no skip-verify.
func TestBootstrapTrust_CAOnly_UsesChainValidation(t *testing.T) {
	caPEM, caKey, caCert := makeCA(t, "trusted-ca")
	serverCert, _ := signServerCert(t, caKey, caCert)
	srv := newPinnedTLSServer(t, serverCert)

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, CACertFile: writeCAFile(t, caPEM), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tc := tlsConfigOf(t, c)
	if tc.InsecureSkipVerify {
		t.Errorf("CA-only config must not set InsecureSkipVerify")
	}
	if tc.RootCAs == nil {
		t.Errorf("CA-only config must set RootCAs")
	}
	if tc.VerifyConnection != nil {
		t.Errorf("CA-only config must not install a VerifyConnection pin")
	}

	resp, err := c.HTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET against CA-signed server: want success, got %v", err)
	}
	resp.Body.Close()

	// A server signed by a different CA must be rejected.
	_, rogueKey, rogueCA := makeCA(t, "rogue-ca")
	rogueCert, _ := signServerCert(t, rogueKey, rogueCA)
	rogueSrv := newPinnedTLSServer(t, rogueCert)
	if resp, err := c.HTTPClient().Get(rogueSrv.URL); err == nil {
		resp.Body.Close()
		t.Fatalf("GET against rogue-CA server: want chain-validation failure, got success")
	}
}

// 2. CA + fingerprint: chain validation stays ON and the pin is enforced on
// top of it — fingerprint mode must not disable RootCAs (CA first,
// fingerprint composes).
func TestBootstrapTrust_CAPlusFingerprint_PinComposesWithChain(t *testing.T) {
	caPEM, caKey, caCert := makeCA(t, "trusted-ca")
	serverCert, leafDER := signServerCert(t, caKey, caCert)
	srv := newPinnedTLSServer(t, serverCert)
	caFile := writeCAFile(t, caPEM)

	// Right pin + right CA -> success.
	c, err := NewClient(ClientConfig{
		ServerURL:            srv.URL,
		CACertFile:           caFile,
		BootstrapFingerprint: leafFingerprint(leafDER),
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tc := tlsConfigOf(t, c)
	if tc.InsecureSkipVerify {
		t.Errorf("CA+fingerprint must keep chain validation on (InsecureSkipVerify=false)")
	}
	if tc.RootCAs == nil {
		t.Errorf("CA+fingerprint must keep RootCAs set")
	}
	if tc.VerifyConnection == nil {
		t.Errorf("CA+fingerprint must still install the VerifyConnection pin")
	}

	resp, err := c.HTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with right pin + right CA: want success, got %v", err)
	}
	resp.Body.Close()

	// Wrong pin + right CA -> the pin must still be enforced.
	wrongPin := strings.Repeat("ab", 32)
	cWrongPin, err := NewClient(ClientConfig{
		ServerURL:            srv.URL,
		CACertFile:           caFile,
		BootstrapFingerprint: wrongPin,
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if resp, err := cWrongPin.HTTPClient().Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatalf("GET with wrong pin: want fingerprint-mismatch failure, got success")
	}

	// Right pin (of the rogue leaf) + wrong CA -> chain validation must
	// reject the connection.  Pre-fix, fingerprint mode set
	// InsecureSkipVerify and a matching pin alone was enough.
	_, rogueKey, rogueCA := makeCA(t, "rogue-ca")
	rogueCert, rogueDER := signServerCert(t, rogueKey, rogueCA)
	rogueSrv := newPinnedTLSServer(t, rogueCert)
	cRogue, err := NewClient(ClientConfig{
		ServerURL:            rogueSrv.URL,
		CACertFile:           caFile, // trusts only "trusted-ca"
		BootstrapFingerprint: leafFingerprint(rogueDER),
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if resp, err := cRogue.HTTPClient().Get(rogueSrv.URL); err == nil {
		resp.Body.Close()
		t.Fatalf("GET against rogue CA with matching pin: want chain-validation failure, got success")
	}
}

// 3. Fingerprint-only: existing bootstrap behavior — manual pin via
// VerifyConnection, chain walking disabled.  This finally covers the
// VerifyConnection callback.
func TestBootstrapTrust_FingerprintOnly_PinEnforced(t *testing.T) {
	_, caKey, caCert := makeCA(t, "any-ca")
	serverCert, leafDER := signServerCert(t, caKey, caCert)
	srv := newPinnedTLSServer(t, serverCert)

	// Colon-separated uppercase form must be normalized and match.
	hexFP := leafFingerprint(leafDER)
	var parts []string
	for i := 0; i < len(hexFP); i += 2 {
		parts = append(parts, strings.ToUpper(hexFP[i:i+2]))
	}
	c, err := NewClient(ClientConfig{
		ServerURL:            srv.URL,
		BootstrapFingerprint: strings.Join(parts, ":"),
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tc := tlsConfigOf(t, c)
	if !tc.InsecureSkipVerify {
		t.Errorf("fingerprint-only must use InsecureSkipVerify + manual pin")
	}
	if tc.VerifyConnection == nil {
		t.Errorf("fingerprint-only must install the VerifyConnection pin")
	}

	resp, err := c.HTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with matching pin: want success, got %v", err)
	}
	resp.Body.Close()

	// Mismatched pin -> handshake must fail with the fingerprint error.
	cBad, err := NewClient(ClientConfig{
		ServerURL:            srv.URL,
		BootstrapFingerprint: strings.Repeat("cd", 32),
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	resp, err = cBad.HTTPClient().Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("GET with mismatched pin: want failure, got success")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("error should mention fingerprint mismatch, got: %v", err)
	}
}

// 4. Neither CA nor fingerprint: registration proceeds on the OS trust
// store, but the fallback must be observable — a warning is logged.
func TestBootstrapTrust_NeitherConfigured_WarnsAtRegistration(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	caPEM, caKey, caCert := makeCA(t, "ca-A")
	deviceCert := signDeviceCert(t, caKey, caCert)
	srv := newRegServer(t, caPEM, deviceCert)

	c, err := NewClient(ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := c.RegisterWithToken(context.Background(), "host", "tok"); err != nil {
		t.Fatalf("RegisterWithToken: %v", err)
	}
	if !strings.Contains(buf.String(), "system trust store") {
		t.Fatalf("registration without CA or fingerprint must warn about the system trust store fallback; log output:\n%s", buf.String())
	}

	// A fingerprint-anchored client must NOT emit the fallback warning.
	buf.Reset()
	cPinned, err := NewClient(ClientConfig{
		ServerURL:            srv.URL,
		BootstrapFingerprint: strings.Repeat("ef", 32),
		Timeout:              5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Plain-HTTP test server: the pin never runs, registration succeeds.
	if _, _, err := cPinned.RegisterWithToken(context.Background(), "host", "tok"); err != nil {
		t.Fatalf("RegisterWithToken (pinned): %v", err)
	}
	if strings.Contains(buf.String(), "system trust store") {
		t.Fatalf("fingerprint-anchored registration must not warn about system trust store; log output:\n%s", buf.String())
	}
}
