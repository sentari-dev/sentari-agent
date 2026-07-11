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

// TestShipAuditLogDrainsInBoundedBatches proves shipAuditLog fetches the
// unshipped backlog a batch at a time and marks each batch shipped before
// fetching the next, so a backlog several times the batch size is re-anchored
// over multiple ShipAudit calls (one HTTP request per batch) rather than a
// single giant read. auditShipBatch is the seam: shrinking it makes the request
// count a deterministic function of the backlog size.
func TestShipAuditLogDrainsInBoundedBatches(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/audit-log" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&requests, 1)
		_, _ = io.Copy(io.Discard, r.Body)
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
	defer auditLog.Close()

	const total = 250
	for i := 0; i < total; i++ {
		if err := auditLog.Log("scan.event", fmt.Sprintf("i=%d", i)); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Shrink the batch seam so 250 entries drain over 3 requests (100+100+50).
	orig := auditShipBatch
	auditShipBatch = 100
	defer func() { auditShipBatch = orig }()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shipAuditLog(context.Background(), client, auditLog, "dev-1", log)

	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Fatalf("ship requests = %d, want 3 (ceil(250/100))", got)
	}

	leftover, err := auditLog.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(leftover) != 0 {
		t.Fatalf("after ship: want 0 unshipped, got %d", len(leftover))
	}
}

// TestShipAuditLogNoDeviceIDIsNoop verifies the early return when the device is
// not yet registered: nothing is shipped and no request is made.
func TestShipAuditLogNoDeviceIDIsNoop(t *testing.T) {
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
	defer auditLog.Close()
	if err := auditLog.Log("e", "d"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shipAuditLog(context.Background(), client, auditLog, "", log)

	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("ship requests with empty deviceID = %d, want 0", got)
	}
	// Entries stay unshipped for a later cycle once the device registers.
	leftover, err := auditLog.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	if len(leftover) != 1 {
		t.Fatalf("want 1 still-unshipped entry, got %d", len(leftover))
	}
}
