package comms

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestShipAudit_PostsContractPayloadAndReturnsMaxID proves the agent emits the
// agent-audit-ship-v1 body byte-shape (device_id + typed entries with int
// entry_id) and reports the highest entry_id so the caller can MarkShipped.
func TestShipAudit_PostsContractPayloadAndReturnsMaxID(t *testing.T) {
	var gotPath, gotCT string
	var gotBody auditShipRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	entries := []map[string]string{
		{"id": "1", "event_type": "scan_started", "detail": "envs=3", "content_hash": "a", "prev_hash": "", "created_at": "2026-05-23T10:00:00.000000001Z"},
		{"id": "2", "event_type": "scan_completed", "detail": "packages=42", "content_hash": "b", "prev_hash": "a", "created_at": "2026-05-23T10:00:01.000000002Z"},
	}

	maxID, err := c.ShipAudit(context.Background(), "f1e2d3c4-0000-0000-0000-000000000000", entries)
	if err != nil {
		t.Fatalf("ShipAudit returned error: %v", err)
	}
	if maxID != 2 {
		t.Fatalf("maxID = %d, want 2", maxID)
	}
	if gotPath != "/api/v1/agent/audit-log" {
		t.Fatalf("path = %q, want /api/v1/agent/audit-log", gotPath)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q, want application/json", gotCT)
	}
	if gotBody.DeviceID != "f1e2d3c4-0000-0000-0000-000000000000" {
		t.Fatalf("device_id = %q", gotBody.DeviceID)
	}
	if len(gotBody.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(gotBody.Entries))
	}
	if gotBody.Entries[0].EntryID != 1 || gotBody.Entries[1].EntryID != 2 {
		t.Fatalf("entry_ids = %d,%d", gotBody.Entries[0].EntryID, gotBody.Entries[1].EntryID)
	}
	if gotBody.Entries[0].EventType != "scan_started" || gotBody.Entries[1].ContentHash != "b" {
		t.Fatalf("entry fields not mapped: %+v", gotBody.Entries)
	}
}

func TestShipAudit_EmptyIsNoOp(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	maxID, err := c.ShipAudit(context.Background(), "dev", nil)
	if err != nil || maxID != 0 {
		t.Fatalf("empty ship: maxID=%d err=%v", maxID, err)
	}
	if called {
		t.Fatal("ShipAudit posted to the server for an empty batch")
	}
}

func TestShipAudit_Non202IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	entries := []map[string]string{
		{"id": "1", "event_type": "x", "detail": "", "content_hash": "a", "prev_hash": "", "created_at": "t"},
	}
	if _, err := c.ShipAudit(context.Background(), "dev", entries); err == nil {
		t.Fatal("expected error on HTTP 403, got nil")
	}
}
