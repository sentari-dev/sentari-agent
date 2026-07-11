package comms

import (
	"strings"
	"testing"
	"time"
)

// NewClient must refuse a cleartext http:// URL to a real (non-loopback) host:
// the mTLS charter forbids shipping scan payloads and the client certificate in
// the clear, and the failure must be loud at construction, not silent on the
// wire.
func TestNewClient_RejectsCleartextHTTP(t *testing.T) {
	_, err := NewClient(ClientConfig{ServerURL: "http://sentari.example.com:8000", Timeout: time.Second})
	if err == nil {
		t.Fatalf("NewClient: want error for cleartext http:// to a remote host, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("error should point the operator at https, got: %v", err)
	}
}

// NewClient must accept an https:// URL.
func TestNewClient_AcceptsHTTPS(t *testing.T) {
	c, err := NewClient(ClientConfig{ServerURL: "https://sentari.example.com", Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient(https): unexpected error: %v", err)
	}
	if c == nil {
		t.Fatalf("NewClient(https): got nil client")
	}
}

// NewClient must reject a URL with no scheme so a bare "host:port" config can
// never degrade into a silent cleartext client.
func TestNewClient_RejectsMissingScheme(t *testing.T) {
	if _, err := NewClient(ClientConfig{ServerURL: "sentari.example.com:8000", Timeout: time.Second}); err == nil {
		t.Fatalf("NewClient: want error for missing scheme, got nil")
	}
}

// NewClient must permit http:// to loopback: those bytes never leave the host,
// and the in-process httptest harness (and local dev) depends on it.
func TestNewClient_AllowsLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:8000",
		"http://localhost:8000",
		"http://[::1]:8000",
	} {
		if _, err := NewClient(ClientConfig{ServerURL: raw, Timeout: time.Second}); err != nil {
			t.Fatalf("NewClient(%q): loopback http should be allowed, got: %v", raw, err)
		}
	}
}

// CloseIdleConnections must exist and be safe to call on a client that has
// issued no requests, and safe to call more than once — it is invoked on the
// old client when a new mTLS identity replaces it on renewal/re-enroll.
func TestClient_CloseIdleConnections_Safe(t *testing.T) {
	c, err := NewClient(ClientConfig{ServerURL: "https://sentari.example.com", Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.CloseIdleConnections()
	c.CloseIdleConnections()
}
