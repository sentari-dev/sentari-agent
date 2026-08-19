//go:build windows

package osrelease

import (
	"regexp"
	"testing"
)

// TestKernelWindows_Format exercises the real RtlGetNtVersionNumbers query on
// the running Windows host. The formatted result must be "<major>.<minor>.<build>"
// (e.g. "10.0.26100"). This test compiles into the GOOS=windows build gate and
// executes only on a Windows runner.
func TestKernelWindows_Format(t *testing.T) {
	got, ok := DetectKernel()
	if !ok {
		t.Fatal("ok = false, want true on windows")
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(got) {
		t.Fatalf("kernel %q is not major.minor.build", got)
	}
}
