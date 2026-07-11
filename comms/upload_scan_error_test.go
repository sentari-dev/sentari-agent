package comms

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// TestUploadScan_413SurfacesTypedHTTPStatusError verifies that a
// non-retryable 4xx (413 payload-too-large) reaches the caller as a typed
// *HTTPStatusError carrying the status code, so the drain loop can tell a
// permanent rejection apart from a transient failure.
func TestUploadScan_413SurfacesTypedHTTPStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge) // 413
		_, _ = io.WriteString(w, "payload too large")
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	err := c.UploadScan(context.Background(), &scanner.ScanResult{Hostname: "h"})
	if err == nil {
		t.Fatal("expected error on 413, got nil")
	}

	var httpErr *HTTPStatusError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected *HTTPStatusError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("StatusCode: want %d, got %d", http.StatusRequestEntityTooLarge, httpErr.StatusCode)
	}
}

// TestUploadScan_500NotTypedHTTPStatusError verifies that a 5xx (retried and
// exhausted by doRequest) does NOT surface as a *HTTPStatusError — it must be
// treated as transient by the drain loop, not marked permanently dead.
func TestUploadScan_500NotTypedHTTPStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // 500, always
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	err := c.UploadScan(context.Background(), &scanner.ScanResult{Hostname: "h"})
	if err == nil {
		t.Fatal("expected error after 5xx retries exhausted, got nil")
	}
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		t.Fatalf("5xx must not surface as *HTTPStatusError, got %v", httpErr)
	}
}

// TestEnforceScanRecordBudgetTruncatesAndReportsError proves the finding
// concurrency-1 fix: a scan result whose combined variable-cardinality record
// count exceeds the (test-lowered) budget is truncated to the budget and a
// single observable truncation ScanError is appended.  Records are trimmed in
// priority order (Packages first) so the highest-value data survives.
func TestEnforceScanRecordBudgetTruncatesAndReportsError(t *testing.T) {
	orig := maxScanRecords
	maxScanRecords = 5
	defer func() { maxScanRecords = orig }()

	result := &scanner.ScanResult{
		Hostname:           "pathological-host",
		Packages:           make([]scanner.PackageRecord, 4),
		DepEdges:           make([]deptree.DepEdge, 4),
		LicenseEvidence:    make([]deptree.LicenseEvidence, 4),
		SupplyChainSignals: make([]deptree.SupplyChainSignal, 4),
	}

	enforceScanRecordBudget(result)

	total := len(result.Packages) + len(result.DepEdges) +
		len(result.LicenseEvidence) + len(result.SupplyChainSignals)
	if total != 5 {
		t.Fatalf("combined records after truncation = %d, want 5 (the budget)", total)
	}
	// Priority order: Packages fills the budget first, so all 4 survive; the
	// single remaining slot goes to DepEdges; the rest are dropped to zero.
	if len(result.Packages) != 4 {
		t.Fatalf("Packages = %d, want 4 (highest priority, kept)", len(result.Packages))
	}
	if len(result.DepEdges) != 1 {
		t.Fatalf("DepEdges = %d, want 1 (remaining budget)", len(result.DepEdges))
	}
	if len(result.LicenseEvidence) != 0 || len(result.SupplyChainSignals) != 0 {
		t.Fatalf("lower-priority slices should be dropped, got le=%d scs=%d",
			len(result.LicenseEvidence), len(result.SupplyChainSignals))
	}

	// Exactly one truncation ScanError, and it is observable/descriptive.
	var truncErrs int
	for _, e := range result.Errors {
		if strings.Contains(e.Error, "truncated") {
			truncErrs++
		}
	}
	if truncErrs != 1 {
		t.Fatalf("expected exactly one truncation ScanError, got %d (errors: %+v)", truncErrs, result.Errors)
	}
}

// TestEnforceScanRecordBudgetLeavesNormalResultUntouched proves a realistic
// (under-budget) result is not mutated and gains no spurious ScanError.
func TestEnforceScanRecordBudgetLeavesNormalResultUntouched(t *testing.T) {
	result := &scanner.ScanResult{
		Hostname: "normal-host",
		Packages: make([]scanner.PackageRecord, 1000),
		DepEdges: make([]deptree.DepEdge, 5000),
	}

	enforceScanRecordBudget(result)

	if len(result.Packages) != 1000 || len(result.DepEdges) != 5000 {
		t.Fatalf("normal result was mutated: packages=%d dep_edges=%d",
			len(result.Packages), len(result.DepEdges))
	}
	if len(result.Errors) != 0 {
		t.Fatalf("normal result gained a spurious ScanError: %+v", result.Errors)
	}
}

// TestUploadScanAppliesRecordBudget proves the cap is wired into the real upload
// path: the truncation ScanError reaches the wire body the server receives, so
// the truncation is observable end-to-end and never silent.
func TestUploadScanAppliesRecordBudget(t *testing.T) {
	orig := maxScanRecords
	maxScanRecords = 2
	defer func() { maxScanRecords = orig }()

	var received scanner.ScanResult
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	result := &scanner.ScanResult{
		Hostname: "h",
		Packages: make([]scanner.PackageRecord, 10),
	}
	if err := c.UploadScan(context.Background(), result); err != nil {
		t.Fatalf("UploadScan: %v", err)
	}
	if len(received.Packages) != 2 {
		t.Fatalf("server received %d packages, want 2 (budget-truncated)", len(received.Packages))
	}
	var truncated bool
	for _, e := range received.Errors {
		if strings.Contains(e.Error, "truncated") {
			truncated = true
		}
	}
	if !truncated {
		t.Fatalf("server did not receive a truncation ScanError: %+v", received.Errors)
	}
}
