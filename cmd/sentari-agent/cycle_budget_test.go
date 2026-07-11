//go:build enterprise

package main

import (
	"testing"
	"time"
)

// TestCycleBudget asserts the per-cycle deadline is now a FLOOR — max(interval,
// defaultCycleBudget) — not the old min().  A tight interval must NOT shrink the
// budget below the floor (that turned "scan slower than interval" into permanent
// zero-data, finding offline-6); a longer interval raises the floor so a
// multi-hour-interval host still gets a proportional budget.
func TestCycleBudget(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{"tight interval floored to default", 60 * time.Second, defaultCycleBudget},
		{"interval just under floor floored to default", defaultCycleBudget - time.Minute, defaultCycleBudget},
		{"interval equal to floor stays at floor", defaultCycleBudget, defaultCycleBudget},
		{"long interval wins over floor", 3 * time.Hour, 3 * time.Hour},
		{"zero interval floored to default", 0, defaultCycleBudget},
		{"negative interval floored to default", -5 * time.Second, defaultCycleBudget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cycleBudget(tc.interval); got != tc.want {
				t.Fatalf("cycleBudget(%s) = %s, want %s", tc.interval, got, tc.want)
			}
		})
	}
}

// TestCycleBudgetEscalation asserts consecutive overruns double the next
// cycle's budget (capped at maxCycleBudget) and that a successful cycle resets
// the escalation back to the base floor.  Pure state machine — no clocks.
func TestCycleBudgetEscalation(t *testing.T) {
	interval := 60 * time.Second // base floor = defaultCycleBudget (45m)
	s := &cycleBudgetState{}

	// No overruns yet → base floor.
	if got := s.budget(interval); got != defaultCycleBudget {
		t.Fatalf("initial budget = %s, want %s", got, defaultCycleBudget)
	}

	// Each consecutive overrun doubles the next budget: 45m → 90m → 180m → 360m.
	want := []time.Duration{
		2 * defaultCycleBudget, // after 1 overrun: 90m
		4 * defaultCycleBudget, // after 2: 180m
		8 * defaultCycleBudget, // after 3: 360m
	}
	for i, w := range want {
		s.recordOverrun()
		if got := s.budget(interval); got != w {
			t.Fatalf("after %d overrun(s): budget = %s, want %s", i+1, got, w)
		}
	}

	// Keep overrunning past the cap — the budget must clamp at maxCycleBudget
	// (8h), never grow unbounded.
	for i := 0; i < 10; i++ {
		s.recordOverrun()
	}
	if got := s.budget(interval); got != maxCycleBudget {
		t.Fatalf("budget after many overruns = %s, want cap %s", got, maxCycleBudget)
	}

	// A successful cycle resets the escalation back to the base floor.
	s.recordSuccess()
	if got := s.budget(interval); got != defaultCycleBudget {
		t.Fatalf("budget after recordSuccess = %s, want base %s", got, defaultCycleBudget)
	}
}

// TestCycleBudgetEscalationRespectsLargeBaseFloor asserts that when the base
// floor already exceeds the 8h cap (a very long scan interval), escalation
// never drops the budget below that floor.
func TestCycleBudgetEscalationRespectsLargeBaseFloor(t *testing.T) {
	interval := 12 * time.Hour // base floor = 12h, already > maxCycleBudget (8h)
	s := &cycleBudgetState{}
	if got := s.budget(interval); got != interval {
		t.Fatalf("base budget = %s, want %s", got, interval)
	}
	s.recordOverrun()
	if got := s.budget(interval); got < interval {
		t.Fatalf("escalated budget %s must never drop below the base floor %s", got, interval)
	}
}
