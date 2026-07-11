package scanner

import (
	"runtime"
	"testing"

	"github.com/sentari-dev/sentari-agent/config"
)

// TestDefaultConfigScanRootResolution verifies the end-to-end contract
// between config.DefaultConfig and scanner.NewRunner: DefaultConfig
// leaves ScanRoot empty, and NewRunner resolves it to the platform
// default (/ on POSIX, C:\ on Windows).  This guards against a
// regression where a hardcoded "/" in DefaultConfig defeated the
// Windows fallback on config-less runs.
func TestDefaultConfigScanRootResolution(t *testing.T) {
	def := config.DefaultConfig()
	if def.Scanner.ScanRoot != "" {
		t.Fatalf("config.DefaultConfig ScanRoot: got %q, want empty so NewRunner resolves the platform default", def.Scanner.ScanRoot)
	}

	r := NewRunner(Config{ScanRoot: def.Scanner.ScanRoot})

	want := "/"
	if runtime.GOOS == "windows" {
		want = "C:\\"
	}
	if r.cfg.ScanRoot != want {
		t.Errorf("effective ScanRoot on %s: got %q, want %q", runtime.GOOS, r.cfg.ScanRoot, want)
	}
}
