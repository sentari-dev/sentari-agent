package comms

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// newTestClient wires a comms.Client to a test server URL with an
// aggressive retry budget so the whole suite stays fast.  No TLS: the
// test server is plain HTTP and we set httpClient directly to bypass
// NewClient's mTLS config path.
func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	c := &Client{
		serverURL:  serverURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		retry: &RetryConfig{
			MaxAttempts:  3,
			BaseDelay:    5 * time.Millisecond,
			MaxDelay:     20 * time.Millisecond,
			JitterFactor: 0,
		},
	}
	return c
}

// dnsDialErr wraps a *net.DNSError in the same url.Error→net.OpError
// dial chain http.Client.Do produces when name resolution fails, so the
// classification tests exercise the real errors.As traversal.
func dnsDialErr(dnsErr *net.DNSError) error {
	return &url.Error{
		Op:  "Post",
		URL: "https://server.example/scan",
		Err: &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: dnsErr,
		},
	}
}

func TestIsRetryable_TransientDNSIsRetryable(t *testing.T) {
	// Air-gap link recovery: DNS commonly fails transiently (SERVFAIL,
	// resolver timeout, resolver not yet reachable) for a beat after the
	// link returns.  Those must be retried, not dropped after one attempt.
	cases := []struct {
		name string
		err  *net.DNSError
	}{
		{
			name: "temporary SERVFAIL",
			err:  &net.DNSError{Err: "server misbehaving", Name: "server.example", IsTemporary: true},
		},
		{
			name: "resolver timeout",
			err:  &net.DNSError{Err: "i/o timeout", Name: "server.example", IsTimeout: true},
		},
		{
			name: "resolver-not-found-but-temporary (link recovering)",
			err:  &net.DNSError{Err: "no such host", Name: "server.example", IsNotFound: true, IsTemporary: true},
		},
		{
			name: "generic resolution failure, no flags set",
			err:  &net.DNSError{Err: "lookup failed", Name: "server.example"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !isRetryable(dnsDialErr(tc.err)) {
				t.Fatalf("transient DNS error %q must be retryable", tc.name)
			}
		})
	}
}

func TestIsRetryable_PermanentNXDOMAINIsNotRetryable(t *testing.T) {
	// A definitive NXDOMAIN (IsNotFound, not flagged temporary) is a
	// misconfiguration — the name will not start existing on a retry, so
	// the caller must surface it rather than burn the backoff budget.
	nx := &net.DNSError{
		Err:        "no such host",
		Name:       "typo.server.exmaple",
		IsNotFound: true,
	}
	if isRetryable(dnsDialErr(nx)) {
		t.Fatal("permanent NXDOMAIN must NOT be retryable")
	}
	// Also assert the bare (unwrapped) DNSError classifies the same way,
	// since errors.As should reach it either way.
	if isRetryable(nx) {
		t.Fatal("bare permanent NXDOMAIN must NOT be retryable")
	}
}

func TestDoRequest_RetriesOn503ThenSucceeds(t *testing.T) {
	// The planner-dashboard regression to dodge is "one transient 503
	// from the API pod during a K8s rolling deploy tombstones the
	// whole scan cycle."  Here we prove that after 2×503 the third
	// attempt gets through and the caller sees success.
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	resp, err := c.doRequest(context.Background(), "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&count); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestDoRequest_NoRetryOn400(t *testing.T) {
	// Client errors are not retryable.  Retrying a 400 ("your payload
	// is malformed") would just DDoS the server with the same bad
	// request.  The contract is: doRequest returns the response
	// unchanged on non-retryable statuses (no err, resp non-nil) —
	// the *caller* (UploadScan, PollConfig, etc.) inspects the code.
	// All we verify here is the attempt count: exactly one.
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	resp, err := c.doRequest(context.Background(), "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err != nil {
		t.Fatalf("doRequest should surface the response, not an error: %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 response surfaced to caller, got %+v", resp)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&count); got != 1 {
		t.Fatalf("expected exactly 1 attempt on 400, got %d", got)
	}
}

func TestDoRequest_Honours429RetryAfter(t *testing.T) {
	// The server explicitly asks "wait 1 second before trying again."
	// We honour that instead of the computed backoff.  Checked by
	// timing the gap between attempts.
	var count int32
	var firstAt, secondAt time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		now := time.Now()
		if n == 1 {
			firstAt = now
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		secondAt = now
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	// Force tiny base delay so only Retry-After can cause a ≥ 900 ms gap.
	// MaxDelay is generous (2 s) so the 1 s hint is honoured in full.
	c.retry = &RetryConfig{MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 2 * time.Second}
	resp, err := c.doRequest(context.Background(), "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	gap := secondAt.Sub(firstAt)
	if gap < 900*time.Millisecond {
		t.Fatalf("Retry-After: 1 not honoured — gap %v (expected ≥900ms)", gap)
	}
}

func TestDoRequest_RetryAfterClampedToMaxDelay(t *testing.T) {
	// A hostile/misconfigured server sends an enormous Retry-After.
	// The agent must NOT honour it verbatim — it must clamp the wait to
	// the configured MaxDelay so the server cannot stall a cycle.
	var count int32
	var firstAt, secondAt time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		now := time.Now()
		if n == 1 {
			firstAt = now
			// 3600 s — would stall the agent for an hour if honoured.
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		secondAt = now
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.retry = &RetryConfig{MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 30 * time.Millisecond}
	resp, err := c.doRequest(context.Background(), "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	gap := secondAt.Sub(firstAt)
	// Must be clamped to ~MaxDelay (30 ms), nowhere near 3600 s.  Allow
	// generous slack for scheduling jitter but well under one second.
	if gap > 500*time.Millisecond {
		t.Fatalf("Retry-After: 3600 was not clamped to MaxDelay — gap %v (expected ≪500ms)", gap)
	}
}

func TestClampWaitHint(t *testing.T) {
	cfg := RetryConfig{MaxDelay: 60 * time.Second}
	cases := []struct {
		name string
		hint time.Duration
		want time.Duration
	}{
		{"absent hint passes through as zero", 0, 0},
		{"negative hint passes through as zero", -5 * time.Second, 0},
		{"within cap is honoured", 10 * time.Second, 10 * time.Second},
		{"at cap is honoured", 60 * time.Second, 60 * time.Second},
		{"over cap is clamped", 3600 * time.Second, 60 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampWaitHint(tc.hint, cfg); got != tc.want {
				t.Fatalf("clampWaitHint(%v) = %v, want %v", tc.hint, got, tc.want)
			}
		})
	}
	// Unbounded MaxDelay falls back to the package default ceiling.
	if got := clampWaitHint(time.Hour, RetryConfig{MaxDelay: 0}); got != defaultRetryConfig.MaxDelay {
		t.Fatalf("unbounded MaxDelay: got %v, want default %v", got, defaultRetryConfig.MaxDelay)
	}
}

func TestNextBackoff_ZeroConfigUsesDefaults(t *testing.T) {
	// Finding offline-2: a RetryConfig with a non-positive BaseDelay or
	// MaxDelay (e.g. the bare zero value) must NOT collapse the backoff
	// into a zero-delay retry burst that hammers the server.  Every wait
	// falls back to the package defaults, so it is strictly positive and
	// bounded by the default MaxDelay.
	zero := RetryConfig{} // BaseDelay=0, MaxDelay=0, JitterFactor=0
	for n := 1; n <= 6; n++ {
		got := nextBackoff(n, zero)
		if got <= 0 {
			t.Fatalf("nextBackoff(%d, zero) = %v, want > 0 (no zero-delay burst)", n, got)
		}
		if got > defaultRetryConfig.MaxDelay {
			t.Fatalf("nextBackoff(%d, zero) = %v, exceeds default MaxDelay %v", n, got, defaultRetryConfig.MaxDelay)
		}
	}
	// The first wait uses the default BaseDelay exactly (no jitter here).
	if got := nextBackoff(1, zero); got != defaultRetryConfig.BaseDelay {
		t.Fatalf("nextBackoff(1, zero) = %v, want default BaseDelay %v", got, defaultRetryConfig.BaseDelay)
	}
	// A negative MaxDelay/BaseDelay is treated the same as unbounded/zero.
	neg := RetryConfig{BaseDelay: -1, MaxDelay: -1}
	if got := nextBackoff(3, neg); got <= 0 || got > defaultRetryConfig.MaxDelay {
		t.Fatalf("nextBackoff(3, neg) = %v, want in (0, %v]", got, defaultRetryConfig.MaxDelay)
	}
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	// Finding tests-2: the Retry-After: <HTTP-date> form (RFC 7231) is
	// what an air-gap gateway or hardened server emits instead of
	// delta-seconds.  A future date yields a positive wait; a past date
	// (clock skew / stale header) must yield zero, never a negative
	// duration that would blow past the backoff/clamp logic.
	now := time.Now()
	cases := []struct {
		name    string
		when    time.Time
		wantPos bool // true → positive duration expected; false → zero
	}{
		{"future date yields positive wait", now.Add(45 * time.Second), true},
		{"past date yields zero, never negative", now.Add(-45 * time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// http.TimeFormat is the RFC1123 GMT form http.ParseTime reads.
			hdr := tc.when.UTC().Format(http.TimeFormat)
			got := parseRetryAfter(hdr)
			if got < 0 {
				t.Fatalf("parseRetryAfter(%q) = %v, must never be negative", hdr, got)
			}
			if tc.wantPos {
				if got <= 0 {
					t.Fatalf("future date %q: got %v, want positive", hdr, got)
				}
				// Whatever the header says, clampWaitHint bounds it to MaxDelay.
				const maxDelay = 10 * time.Second
				if clamped := clampWaitHint(got, RetryConfig{MaxDelay: maxDelay}); clamped > maxDelay {
					t.Fatalf("clamped wait %v exceeds MaxDelay %v", clamped, maxDelay)
				}
			} else if got != 0 {
				t.Fatalf("past date %q: got %v, want 0", hdr, got)
			}
		})
	}
}

func TestDoRequest_GivesUpAfterMaxAttempts(t *testing.T) {
	// Perma-503 → caller sees a wrapped error that says which op
	// and how many attempts happened.  The original lastErr stays
	// wrapped so errors.Is/As against our own sentinel types still
	// works.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	_, err := c.doRequest(context.Background(), "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err == nil {
		t.Fatal("expected error after max attempts")
	}
	if !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("expected 'giving up' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "probe") {
		t.Fatalf("expected op name 'probe' in error, got: %v", err)
	}
}

func TestDoRequest_AbortsOnCancelledContext(t *testing.T) {
	// If the caller cancels (agent SIGTERM mid-cycle), abort the
	// retry loop immediately rather than chewing through the full
	// backoff budget — the daemon wants to shut down cleanly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	c := newTestClient(t, srv.URL)
	c.retry = &RetryConfig{MaxAttempts: 20, BaseDelay: 100 * time.Millisecond, MaxDelay: 200 * time.Millisecond}

	_, err := c.doRequest(ctx, "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected context-cancel error, got %v", err)
	}
}

func TestDoRequest_StampsXRequestID(t *testing.T) {
	// The whole point of the logging package: every outbound
	// request must carry the contextvar's request_id so the server
	// log line for "scan received" joins the agent's cycle trace.
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	ctx := logging.WithRequestID(context.Background(), "scan-deadbeef")
	resp, err := c.doRequest(ctx, "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if seen != "scan-deadbeef" {
		t.Fatalf("expected X-Request-ID=scan-deadbeef, server saw %q", seen)
	}
}

func TestDoRequest_OmitsXRequestIDWhenUnbound(t *testing.T) {
	// Conversely: no ID in context → no header, not an empty one.
	// Empty would still be "present" from the server's view and
	// could misleadingly show up in logs as request_id="".
	var seen, present = "", true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Request-ID")
		_, present = r.Header["X-Request-Id"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	resp, err := c.doRequest(context.Background(), "probe",
		func(ctx context.Context) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/", nil)
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if present || seen != "" {
		t.Fatalf("expected no X-Request-ID header, got %q (present=%v)", seen, present)
	}
}

// TestUploadScan_SetsV3PayloadVersionHeader asserts that every
// /scan upload carries `X-Sentari-Payload-Version: 3`.  The
// server's v3 ingest path relies on the header to distinguish
// "agent looked and found nothing" from "agent doesn't speak v3";
// if this regresses, v2 agents and v3 agents become
// indistinguishable on the wire.
func TestUploadScan_SetsV3PayloadVersionHeader(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Sentari-Payload-Version")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result := &scanner.ScanResult{DeviceID: "dev-1"}
	if err := c.UploadScan(context.Background(), result); err != nil {
		t.Fatalf("UploadScan: %v", err)
	}
	if seen != "3" {
		t.Fatalf("expected X-Sentari-Payload-Version: 3, got %q", seen)
	}
}

func TestUploadScan_RetriesOnTransient503(t *testing.T) {
	// End-to-end: UploadScan goes through the retry path.  Two 503s
	// then a 200, caller sees nil error.
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&count, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result := &scanner.ScanResult{DeviceID: "dev-1"}
	if err := c.UploadScan(context.Background(), result); err != nil {
		t.Fatalf("UploadScan after retries: %v", err)
	}
	if got := atomic.LoadInt32(&count); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}
