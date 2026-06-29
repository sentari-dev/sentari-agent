package update

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0", "1.0.0", 0, true},
		{"v1.0.0", "1.0.0", 0, true},   // leading v ignored
		{"1.2.0", "1.10.0", -1, true},  // numeric, not lexical
		{"2.0.0", "1.9.9", 1, true},    // major dominates
		{"0.2.0", "0.1.3", 1, true},    // patch/minor
		{"0.1.3", "0.2.0", -1, true},   // reverse
		{"1.0.1", "1.0.0", 1, true},    // patch bump
		{"1.0.0-rc1", "1.0.0", 0, true}, // pre-release suffix ignored on core triple
		{"1.0.0+build5", "1.0.0", 0, true},
		{"1.2", "1.2.0", 0, true}, // missing patch treated as 0
		{"not-a-version", "1.0.0", 0, false},
		{"1.0.0", "garbage", 0, false},
		{"1.x.0", "1.0.0", 0, false},
	}
	for _, c := range cases {
		got, err := compareVersions(c.a, c.b)
		if c.ok && err != nil {
			t.Errorf("compareVersions(%q,%q) unexpected err: %v", c.a, c.b, err)
			continue
		}
		if !c.ok {
			if err == nil {
				t.Errorf("compareVersions(%q,%q) expected parse error, got nil (result=%d)", c.a, c.b, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
