package scanner

import "testing"

func TestSourceNameFromSourceRPM(t *testing.T) {
	cases := map[string]string{
		"openssl-1.1.1k-7.el9.src.rpm":      "openssl",
		"openssl-libs-3.0.7-27.el9.src.rpm": "openssl-libs",
		"glibc-2.34-60.el9.src.rpm":         "glibc",
		"python3.11-3.11.2-2.el9.nosrc.rpm": "python3.11",
		"":                                  "",
		"garbage":                           "",
	}
	for in, want := range cases {
		if got := sourceNameFromSourceRPM(in); got != want {
			t.Errorf("sourceNameFromSourceRPM(%q) = %q, want %q", in, got, want)
		}
	}
}
