package comms

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
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

// TestShipAudit_EmitsHashVersion proves the wire payload carries the per-entry
// hash_version: present values pass through, and an entry whose map omits it
// (older code path / legacy row) defaults to scheme 1 so the server recomputes
// with the legacy encoding.
func TestShipAudit_EmitsHashVersion(t *testing.T) {
	var gotBody auditShipRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	entries := []map[string]string{
		{"id": "1", "event_type": "scan_started", "detail": "envs=3", "content_hash": "a", "prev_hash": "", "created_at": "t1", "hash_version": "2"},
		// No hash_version key -> must default to 1 on the wire.
		{"id": "2", "event_type": "scan_completed", "detail": "pkgs=42", "content_hash": "b", "prev_hash": "a", "created_at": "t2"},
	}

	if _, err := c.ShipAudit(context.Background(), "dev", entries); err != nil {
		t.Fatalf("ShipAudit returned error: %v", err)
	}
	if len(gotBody.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(gotBody.Entries))
	}
	if gotBody.Entries[0].HashVersion != 2 {
		t.Fatalf("entry 1 hash_version = %d, want 2", gotBody.Entries[0].HashVersion)
	}
	if gotBody.Entries[1].HashVersion != 1 {
		t.Fatalf("entry 2 hash_version (default) = %d, want 1", gotBody.Entries[1].HashVersion)
	}
}

// TestShipAudit_BodyValidatesAgainstSharedSchema is the contract-drift guard for
// the audit-ship wire payload. Unlike the other ship tests (which decode the
// captured body back into the production auditShipRequest struct — self-
// referential, so a renamed json tag would still round-trip cleanly and catch
// nothing), this test validates the RAW captured request bytes against the
// shared JSON Schema at docs/contracts/agent-audit-ship-v1.json.
//
// If any json tag on auditShipEntry / auditShipRequest is renamed, dropped, or
// diverges in shape from the schema — or the emitted payload stops satisfying a
// required field, pattern (content_hash 64-hex), or the hash_version bounds —
// this fails immediately rather than shipping bytes the server's ingest path
// quietly 422-rejects. It also proves the recently-added optional hash_version
// field validates.
func TestShipAudit_BodyValidatesAgainstSharedSchema(t *testing.T) {
	schemaPath, err := filepath.Abs(filepath.Join("..", "docs", "contracts", "agent-audit-ship-v1.json"))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	schema, err := jsonschema.NewCompiler().Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}

	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// content_hash / prev_hash must be lowercase 64-hex to satisfy the schema
	// pattern; created_at must be <=64 chars. Entry 1 carries an explicit
	// hash_version=2; entry 2 omits it in the source map so the wire payload
	// defaults it to 1 — both must validate under the optional/additive field.
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	entries := []map[string]string{
		{"id": "1", "event_type": "scan_started", "detail": "envs=3", "content_hash": hashA, "prev_hash": "", "created_at": "2026-05-23T10:00:00.000000001Z", "hash_version": "2"},
		{"id": "2", "event_type": "scan_completed", "detail": "packages=42", "content_hash": hashB, "prev_hash": hashA, "created_at": "2026-05-23T10:00:01.000000002Z"},
	}

	c := newTestClient(t, srv.URL)
	if _, err := c.ShipAudit(context.Background(), "f1e2d3c4-0000-0000-0000-000000000000", entries); err != nil {
		t.Fatalf("ShipAudit returned error: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("server captured no request body")
	}

	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal captured body for validation: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("audit-ship payload failed schema validation: %v\npayload: %s", err, string(raw))
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
