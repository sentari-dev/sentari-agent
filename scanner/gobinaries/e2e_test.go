package gobinaries

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestFullScanPicksUpGoBinaries drives the real orchestrator (scanner.Runner),
// not the plugin directly, and asserts that go_binary module records reach the
// assembled scan payload. This proves the full production path — registry →
// rootScanners() → DiscoverAll → worker pool → Scan → ScanResult.Packages — so
// a registered-but-unwired detector (a green unit test over dead code) cannot
// pass unnoticed.
func TestFullScanPicksUpGoBinaries(t *testing.T) {
	src := hostFixtureBinary(t)
	binDir := t.TempDir()
	copyFixtureInto(t, src, filepath.Join(binDir, "fixturebin"))

	// Point discovery at the fixture bin dir and isolate env-derived roots so
	// the run is deterministic.
	withRoots(t, []string{binDir}, nil)
	isolate := t.TempDir()
	t.Setenv("GOPATH", filepath.Join(isolate, "nogopath"))
	t.Setenv("HOME", filepath.Join(isolate, "nohome"))
	t.Setenv("USERPROFILE", filepath.Join(isolate, "nohome"))

	// A tiny, empty scan root keeps the filesystem walk from finding anything
	// else; the RootScanner discovery is independent of it.
	scanRoot := t.TempDir()
	runner := scanner.NewRunner(scanner.Config{
		ScanRoot:   scanRoot,
		MaxDepth:   2,
		MaxWorkers: 2,
	})
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("scan run failed: %v", err)
	}

	var found bool
	for _, p := range result.Packages {
		if p.EnvType == EnvGoBinary && p.Name == fixtureMainModule {
			found = true
			if p.InstallPath == "" {
				t.Errorf("go_binary record missing install_path: %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("go_binary records did not reach the scan payload; got %d packages", len(result.Packages))
	}
}
