package comms

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Server-side install-gate disable signal: 404 + the
// X-Sentari-Install-Gate-Disabled response header set to "true".
// FetchInstallGateMap must return ErrInstallGateServerDisabled in
// that case so the caller can distinguish it from a transient 404
// (which falls through to the existing 7-day fail-open grace).

func TestFetchInstallGateMap_DisabledHeaderReturnsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sentari-Install-Gate-Disabled", "true")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.FetchInstallGateMap(context.Background(), 0)
	if !errors.Is(err, ErrInstallGateServerDisabled) {
		t.Fatalf("expected ErrInstallGateServerDisabled, got %v", err)
	}
}

func TestFetchInstallGateMap_Plain404IsGenericError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.FetchInstallGateMap(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error on plain 404")
	}
	if errors.Is(err, ErrInstallGateServerDisabled) {
		t.Fatalf("plain 404 should NOT be classified as the disable sentinel: %v", err)
	}
}

func TestFetchInstallGateMap_HeaderWithout404IsNotSentinel(t *testing.T) {
	// Defensive: a misbehaving server might leak the header onto a
	// 5xx.  We only treat it as the disable signal on 404 so a brief
	// server-internal-error doesn't tear down host configs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sentari-Install-Gate-Disabled", "true")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, _, err := c.FetchInstallGateMap(context.Background(), 0)
	if errors.Is(err, ErrInstallGateServerDisabled) {
		t.Fatalf("500 + header must not be classified as sentinel: %v", err)
	}
}

func TestIsInstallGateServerDisabled_Predicate(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header string
		want   bool
	}{
		{"404+true", 404, "true", true},
		{"404+false", 404, "false", false},
		{"404+empty", 404, "", false},
		{"200+true", 200, "true", false},
		{"500+true", 500, "true", false},
		{"404+TRUE (case-sensitive on value)", 404, "TRUE", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Response{
				StatusCode: tc.status,
				Header:     http.Header{},
			}
			if tc.header != "" {
				r.Header.Set("X-Sentari-Install-Gate-Disabled", tc.header)
			}
			if got := isInstallGateServerDisabled(r); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	// Nil response — defensive; never happens in practice.
	if isInstallGateServerDisabled(nil) {
		t.Error("nil response must not be classified as disabled")
	}
}
