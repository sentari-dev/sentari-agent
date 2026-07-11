//go:build enterprise

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/comms"
)

// TestShipAuditLog_StopsOnServerError proves the best-effort contract: when the
// re-anchoring endpoint fails (500), shipAuditLog stops after the failed
// ShipAudit call, does NOT mark anything shipped, and leaves the whole backlog
// queued for the next cycle.  A single request is made (no retry storm at the
// caller level: ShipAudit surfaces the error and the loop breaks).
func TestShipAuditLog_StopsOnServerError(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/audit-log" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requests, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// A 500 is retryable; cap attempts so the single-cycle failure is fast.
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})

	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	defer auditLog.Close()

	const total = 5
	for i := 0; i < total; i++ {
		if err := auditLog.Log("scan.event", fmt.Sprintf("i=%d", i)); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shipAuditLog(context.Background(), client, auditLog, "dev-1", log)

	if got := atomic.LoadInt32(&requests); got < 1 {
		t.Fatalf("expected at least one ShipAudit request, got %d", got)
	}
	// Nothing was marked shipped: the full backlog is still queued.
	leftover, err := auditLog.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(leftover) != total {
		t.Fatalf("after a failed ship: want %d still-unshipped, got %d", total, len(leftover))
	}
}

// TestShipAuditLog_ReadErrorIsNoop proves the read-side guard: if the local
// audit store can't be read (here: closed before the call), shipAuditLog logs
// and returns without contacting the server.
func TestShipAuditLog_ReadErrorIsNoop(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	auditLog, err := audit.NewAuditLog(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	if err := auditLog.Log("e", "d"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// Close so UnshippedEntries fails on the first loop iteration.
	if err := auditLog.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shipAuditLog(context.Background(), client, auditLog, "dev-1", log)

	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("ship requests after a read error = %d, want 0", got)
	}
}
