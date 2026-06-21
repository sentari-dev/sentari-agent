//go:build enterprise

package main

import "testing"

func TestClampScanIntervalSeconds(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"below floor is raised", 1, minScanIntervalSeconds},
		{"zero is raised to floor", 0, minScanIntervalSeconds},
		{"negative is raised to floor", -10, minScanIntervalSeconds},
		{"at floor unchanged", minScanIntervalSeconds, minScanIntervalSeconds},
		{"in range unchanged", 3600, 3600},
		{"at ceiling unchanged", maxScanIntervalSeconds, maxScanIntervalSeconds},
		{"above ceiling is clamped", 10_000_000, maxScanIntervalSeconds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampScanIntervalSeconds(tc.in); got != tc.want {
				t.Fatalf("clampScanIntervalSeconds(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestClampMaxDepth(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"below floor is raised to 1", 0, 1},
		{"negative is raised to 1", -3, 1},
		{"at floor unchanged", 1, 1},
		{"in range unchanged", 8, 8},
		{"at ceiling unchanged", maxScannerDepth, maxScannerDepth},
		{"above ceiling is clamped", 1000, maxScannerDepth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampMaxDepth(tc.in); got != tc.want {
				t.Fatalf("clampMaxDepth(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
