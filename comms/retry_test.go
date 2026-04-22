package comms

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
	c.retry = &RetryConfig{MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 5 * time.Millisecond}
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
