package scanner

import (
	"context"
	"strings"
	"testing"
)

// panickingScanner exists solely to simulate a parser bug / malformed
// fixture that drops a panic out of Scan().  The guarantee we want
// from Runner.scanEnvironment is that this panic becomes a typed
// ScanError instead of aborting the whole scan cycle — otherwise a
// single bad .deb on one host would tombstone every scan that host
// ever does.
type panickingScanner struct{}

func (panickingScanner) EnvType() string { return "test_panic" }

func (panickingScanner) Scan(_ context.Context, _ Environment) ([]PackageRecord, []ScanError) {
	panic("kaboom: pretend parser bug")
}

func TestScanEnvironment_RecoversFromPanic(t *testing.T) {
	// Use Register() directly — the runner's private dispatch path
	// looks up via scannerFor(EnvType), so just pre-register this
	// scanner before calling scanEnvironment.
	//
	// Register() panics on duplicate; env_type "test_panic" must
	// not collide with any builtin.  If this test ever runs twice
	// in the same process (it shouldn't — `go test` forks per
	// package) we'd need to guard; not worth it today.
	Register(panickingScanner{})

	runner := NewRunner(Config{})
	result := runner.scanEnvironment(context.Background(), Environment{
		EnvType: "test_panic",
		Path:    "/fake/path",
	})

	if len(result.packages) != 0 {
		t.Fatalf("expected no packages from panicking scanner, got %d", len(result.packages))
	}
	if len(result.errors) != 1 {
		t.Fatalf("expected exactly 1 ScanError from panic recovery, got %d", len(result.errors))
	}
	got := result.errors[0]
	if got.EnvType != "test_panic" {
		t.Errorf("expected EnvType=test_panic on recovered error, got %q", got.EnvType)
	}
	if got.Path != "/fake/path" {
		t.Errorf("expected Path preserved on recovered error, got %q", got.Path)
	}
	if !strings.Contains(got.Error, "scanner panic") {
		t.Errorf("expected error message to mention 'scanner panic', got %q", got.Error)
	}
	if !strings.Contains(got.Error, "kaboom") {
		t.Errorf("expected recovered panic value in error, got %q", got.Error)
	}
	if got.Timestamp.IsZero() {
		t.Errorf("expected Timestamp set on recovered error")
	}
}
