//go:build enterprise

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/comms"
)

// TestClassifyDrainError_MarksDeadOnPayloadPermanent4xx verifies that only a
// genuinely payload-permanent 4xx (surfaced as *comms.HTTPStatusError) tells the
// drain loop to mark the row dead and continue — the head-of-line-block fix.
// These are the codes where retrying THIS payload can never succeed.
func TestClassifyDrainError_MarksDeadOnPayloadPermanent4xx(t *testing.T) {
	cases := []int{400, 413, 415, 422}
	for _, code := range cases {
		err := &comms.HTTPStatusError{Op: "scan upload", StatusCode: code}
		if got := classifyDrainError(err); got != drainMarkDead {
			t.Fatalf("status %d: want drainMarkDead, got %v", code, got)
		}
		// Wrapped in another error, errors.As must still find it.
		wrapped := fmt.Errorf("upload: %w", err)
		if got := classifyDrainError(wrapped); got != drainMarkDead {
			t.Fatalf("wrapped status %d: want drainMarkDead, got %v", code, got)
		}
	}
}

// TestClassifyDrainError_StopsOnAuthStateAndTransient verifies that auth/proxy
// STATE codes (401 mTLS cert not forwarded, 403 rotated proxy secret / expired
// device cert / clock skew, 407 proxy auth) and any OTHER unrecognized 4xx are
// treated as RECOVERABLE (drainStop) — NOT marked dead.  Marking them dead would
// destroy the whole offline backlog on a transient auth/proxy misconfiguration
// that resolves once the operator fixes the environment.  429, 5xx, and plain
// transport errors are likewise transient.
func TestClassifyDrainError_StopsOnAuthStateAndTransient(t *testing.T) {
	// Auth/proxy state codes: recoverable, must keep the backlog queued.
	for _, code := range []int{401, 403, 407} {
		if got := classifyDrainError(&comms.HTTPStatusError{StatusCode: code}); got != drainStop {
			t.Fatalf("auth-state status %d: want drainStop (recoverable), got %v", code, got)
		}
	}
	// An unrecognized 4xx (e.g. 404 not-found, 429 rate-limit, 451) is treated
	// conservatively as transient rather than nuking the backlog.
	for _, code := range []int{404, 429, 451} {
		if got := classifyDrainError(&comms.HTTPStatusError{StatusCode: code}); got != drainStop {
			t.Fatalf("unrecognized 4xx status %d: want drainStop, got %v", code, got)
		}
	}
	// A 5xx typed error (defensive — 5xx normally never surfaces as
	// HTTPStatusError) must also be transient.
	if got := classifyDrainError(&comms.HTTPStatusError{StatusCode: 503}); got != drainStop {
		t.Fatalf("503: want drainStop, got %v", got)
	}
	// A plain transport error is transient.
	if got := classifyDrainError(errors.New("connection refused")); got != drainStop {
		t.Fatalf("transport error: want drainStop, got %v", got)
	}
	if got := classifyDrainError(nil); got != drainStop {
		t.Fatalf("nil: want drainStop, got %v", got)
	}
}

// TestPruneFallbackFiles_CapsToKeep verifies the fallback-file pruner deletes
// the oldest scan-fallback-*.json files so at most `keep` remain, and leaves
// unrelated files untouched.
func TestPruneFallbackFiles_CapsToKeep(t *testing.T) {
	dir := t.TempDir()

	// Eight fallback files with increasing timestamps (oldest first).
	var paths []string
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, fmt.Sprintf("scan-fallback-%d.json", 1000+i))
		if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		paths = append(paths, p)
	}
	// An unrelated file that must survive.
	other := filepath.Join(dir, "device_id")
	if err := os.WriteFile(other, []byte("x"), 0600); err != nil {
		t.Fatalf("write other: %v", err)
	}

	if err := pruneFallbackFiles(dir, 5); err != nil {
		t.Fatalf("pruneFallbackFiles: %v", err)
	}

	remaining, err := filepath.Glob(filepath.Join(dir, "scan-fallback-*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(remaining) != 5 {
		t.Fatalf("want 5 fallback files remaining, got %d", len(remaining))
	}
	// The five newest (timestamps 1003..1007) must be the survivors.
	for i := 3; i < 8; i++ {
		if !contains(remaining, paths[i]) {
			t.Fatalf("newest file %s should have survived", paths[i])
		}
	}
	if !fileExistsT(other) {
		t.Fatal("unrelated file must not be pruned")
	}
}

// TestPruneFallbackFiles_NoopUnderCap verifies pruning is a no-op when already
// at or under the cap.
func TestPruneFallbackFiles_NoopUnderCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("scan-fallback-%d.json", 2000+i))
		if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	if err := pruneFallbackFiles(dir, 5); err != nil {
		t.Fatalf("pruneFallbackFiles: %v", err)
	}
	remaining, _ := filepath.Glob(filepath.Join(dir, "scan-fallback-*.json"))
	if len(remaining) != 3 {
		t.Fatalf("no-op expected: want 3, got %d", len(remaining))
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func fileExistsT(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
