package scanner

import "testing"

// --- Finding 1: isPythonPackage token/prefix boundaries --------------------

// TestIsPythonPackage_TokenBoundaries guards the shared isPythonPackage
// predicate (used by both the deb and rpm scanners) against the bare-substring
// "pip" false positive: PipeWire audio-stack packages contain "pip" but are
// NOT Python.  Real Python packages (including pypy3/jython, which carry no
// "python" substring, and the pip tool itself) must still be recognised.
func TestIsPythonPackage_TokenBoundaries(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// PipeWire family + related audio packages — NOT Python.
		{"pipewire", false},
		{"pipewire-bin", false},
		{"pipewire-pulse", false},
		{"libpipewire-0.3-0", false},
		{"gstreamer1.0-pipewire", false},
		// Real Python packages/interpreters/tools — Python.
		{"python3-requests", true},
		{"python3.11", true},
		{"libpython3.11", true},
		{"pip", true},
		{"pip3", true},
		{"pypy3", true},
		{"jython", true},
		{"python3-pip", true},
		// Unrelated system packages — NOT Python.
		{"nginx", false},
		{"curl", false},
	}
	for _, c := range cases {
		if got := isPythonPackage(c.name); got != c.want {
			t.Errorf("isPythonPackage(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
