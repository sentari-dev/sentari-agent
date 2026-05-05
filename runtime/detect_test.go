package runtime

import (
	"testing"
)

// The K8s env-var probe is the only branch we can deterministically
// test in unit-land — /proc/1/cgroup and /run/.containerenv aren't
// remappable from a Go test.  Those branches get coverage via the
// agent's container-CI integration runs.

func TestDetect_K8sEnvVarTakesPrecedence(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if got := Detect(); got != K8s {
		t.Errorf("got %s, want %s", got, K8s)
	}
}

func TestDetect_ReturnsValidEnum(t *testing.T) {
	// Defensive: regardless of where this test runs (macOS dev
	// box, Linux CI runner, Linux Docker container in CI), Detect
	// must return one of the four enum values.  Catches accidental
	// regressions where a platform branch returns "" or some other
	// non-enum string the server would reject.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	got := Detect()
	valid := map[string]bool{
		BareMetal: true,
		Container: true,
		K8s:       true,
		Unknown:   true,
	}
	if !valid[got] {
		t.Errorf("Detect returned non-enum value %q", got)
	}
}
