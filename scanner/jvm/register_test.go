package jvm

import (
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestJVMPluginIsRegistered verifies that the ``init()`` call in
// scanner.go actually lands ``jvm`` in the global registry by checking
// ``scanner.RegisteredScanners()``.  Whether production binaries
// include the blank import is a build-tag / main.go concern — this
// test can only assert that *if* the package is linked in, init()
// registers it.  A regression where init() disappears (refactor
// accident, build-tag slip) shows up here rather than as a silent
// "no Java records in the inventory."
func TestJVMPluginIsRegistered(t *testing.T) {
	var found bool
	for _, s := range scanner.RegisteredScanners() {
		if s.EnvType() == EnvJVM {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("jvm plugin is not in the scanner registry; init() missed or Register returned early")
	}
}

// TestJVMPluginImplementsRootScanner verifies the plugin satisfies
// the scanner.RootScanner interface.  The orchestrator dispatches
// DiscoverAll() only on RootScanner-typed plugins; if this assertion
// fails the plugin's DiscoverAll() wouldn't be called during a real
// scan cycle and every JVM surface would go undiscovered.
func TestJVMPluginImplementsRootScanner(t *testing.T) {
	var s Scanner
	var _ scanner.RootScanner = s // compile-time check would fail on mismatch
}
