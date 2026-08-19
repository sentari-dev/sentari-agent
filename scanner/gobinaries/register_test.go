package gobinaries

import (
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestGoBinariesPluginIsRegistered verifies that init() lands this plugin
// in the global registry. Whether a production binary links the package in
// is a blank-import concern in cmd/sentari-agent; this test asserts that if
// the package is linked, init() registers it. A regression where init()
// disappears shows up here rather than as a silent "no Go binaries in the
// inventory".
func TestGoBinariesPluginIsRegistered(t *testing.T) {
	var found bool
	for _, s := range scanner.RegisteredScanners() {
		if s.EnvType() == EnvGoBinary {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("gobinaries plugin is not in the scanner registry; init() missed or Register returned early")
	}
}

// TestGoBinariesPluginImplementsRootScanner asserts the plugin satisfies
// scanner.RootScanner at compile time. The orchestrator invokes DiscoverAll
// only on RootScanner-typed plugins; a mismatch here would leave every Go
// binary undiscovered during a real scan.
func TestGoBinariesPluginImplementsRootScanner(t *testing.T) {
	var s Scanner
	var _ scanner.RootScanner = s
}
