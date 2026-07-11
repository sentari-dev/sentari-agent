package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// stallingServer sends a few bytes, flushes them, then blocks the
// handler until the returned channel is closed — simulating a link that
// goes silent mid-download.  The caller MUST close the channel (via the
// returned func) before srv.Close() so the blocked handler unwinds.
func stallingServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial-bytes"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-blocked // never make further progress
	}))
	var once bool
	return srv, func() {
		if !once {
			once = true
			close(blocked)
		}
	}
}

// TestDownloadAndVerify_progressStallAborts proves the idle/progress
// watchdog tears down a download that goes silent: with a short stall
// timeout the download errors with errDownloadStalled rather than
// hanging for the whole-request-less client's lifetime.
func TestDownloadAndVerify_progressStallAborts(t *testing.T) {
	srv, unblock := stallingServer(t)
	defer srv.Close()
	defer unblock()

	c := &Client{
		HTTPClient:           http.DefaultClient,
		ServerURL:            srv.URL,
		GOOS:                 runtime.GOOS,
		GOARCH:               runtime.GOARCH,
		downloadStallTimeout: 100 * time.Millisecond,
	}
	plan := &Plan{Platform: PlatformManifest{URL: "/bin", SHA256: "unused"}}
	dest := filepath.Join(t.TempDir(), "out")

	start := time.Now()
	err := c.downloadAndVerify(context.Background(), plan, dest)
	if err == nil || !errors.Is(err, errDownloadStalled) {
		t.Fatalf("expected errDownloadStalled, got %v", err)
	}
	// Must abort near the stall timeout, not hang.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("stall abort took too long: %v", elapsed)
	}
}

// TestDownloadAndVerify_ctxCancelAborts proves an external ctx
// cancellation (operator Ctrl-C / service SIGTERM during shutdown)
// aborts an in-flight download promptly, even though the stall timeout
// is long.
func TestDownloadAndVerify_ctxCancelAborts(t *testing.T) {
	srv, unblock := stallingServer(t)
	defer srv.Close()
	defer unblock()

	c := &Client{
		HTTPClient:           http.DefaultClient,
		ServerURL:            srv.URL,
		GOOS:                 runtime.GOOS,
		GOARCH:               runtime.GOARCH,
		downloadStallTimeout: 30 * time.Second, // long — must NOT be what fires
	}
	plan := &Plan{Platform: PlatformManifest{URL: "/bin", SHA256: "unused"}}
	dest := filepath.Join(t.TempDir(), "out")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := c.downloadAndVerify(ctx, plan, dest)
	if err == nil {
		t.Fatal("expected error on ctx cancel, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ctx cancel abort took too long: %v", elapsed)
	}
}
