//go:build darwin

package osrelease

import (
	"regexp"
	"testing"
)

// TestKernelDarwin_Sysctl exercises the real kern.osrelease sysctl on the
// running macOS host. Best-effort: it must return a non-empty, plausibly
// versioned string (e.g. "24.5.0") without invoking any binary.
func TestKernelDarwin_Sysctl(t *testing.T) {
	got, ok := DetectKernel()
	if !ok {
		t.Fatal("ok = false, want true on darwin")
	}
	if !regexp.MustCompile(`^\d+\.\d+`).MatchString(got) {
		t.Fatalf("kernel %q does not look like a Darwin version", got)
	}
}
