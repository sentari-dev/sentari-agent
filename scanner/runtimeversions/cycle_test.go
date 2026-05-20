package runtimeversions

import "testing"

func TestCycleFor(t *testing.T) {
	cases := []struct {
		runtime, version, want string
	}{
		{"python", "3.11.5", "3.11"},
		{"python", "3.8.10", "3.8"},
		{"node", "20.10.0", "20"},
		{"jdk", "17.0.5+8", "17"},
		{"jdk", "1.8.0_392", "8"},
		{"python", "garbage", "unknown"},
		{"ruby", "3.2.0", "unknown"},
	}
	for _, c := range cases {
		if got := CycleFor(c.runtime, c.version); got != c.want {
			t.Errorf("CycleFor(%q, %q) = %q, want %q", c.runtime, c.version, got, c.want)
		}
	}
}
