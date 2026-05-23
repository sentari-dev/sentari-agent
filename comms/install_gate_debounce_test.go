package comms

import "testing"

// One disable response must NOT trigger teardown; only N consecutive ones do.
func TestInstallGateDisableDebounce(t *testing.T) {
	d := NewInstallGateDisableDebouncer() // default threshold

	if d.Threshold() < 2 {
		t.Fatalf("debounce threshold should be >= 2, got %d", d.Threshold())
	}

	// First disable: not enough.
	if d.RecordDisabled() {
		t.Fatalf("teardown after a single disable response — debounce not honored")
	}

	// Subsequent disables until just before threshold: still no teardown.
	for i := 2; i < d.Threshold(); i++ {
		if d.RecordDisabled() {
			t.Fatalf("teardown at consecutive count %d (< threshold %d)", i, d.Threshold())
		}
	}

	// The Nth consecutive disable triggers teardown.
	if !d.RecordDisabled() {
		t.Fatalf("no teardown after %d consecutive disable responses", d.Threshold())
	}
}

// A non-disable outcome between disables resets the counter, so transient
// single-disable blips never accumulate into a teardown.
func TestInstallGateDisableResetsOnEnabled(t *testing.T) {
	d := NewInstallGateDisableDebouncer()

	// Almost reach threshold...
	for i := 1; i < d.Threshold(); i++ {
		if d.RecordDisabled() {
			t.Fatalf("premature teardown at %d", i)
		}
	}
	// ...then a healthy (enabled) cycle resets.
	d.Reset()

	// One more disable must NOT immediately tear down — the streak reset.
	if d.RecordDisabled() {
		t.Fatalf("teardown after reset + single disable — counter did not reset")
	}
}
