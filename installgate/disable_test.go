package installgate

import (
	"os"
	"path/filepath"
	"testing"
)

// Marker round-trip: HasServerDisabledMarker should be false on a
// fresh dataDir, true after Write, and false again after Clear.
// Clear on an already-absent marker must be a no-op (idempotent —
// the agent calls Clear on every 200 response).
func TestServerDisabledMarker_RoundTrip(t *testing.T) {
	tmp := t.TempDir()

	if HasServerDisabledMarker(tmp) {
		t.Fatal("fresh dataDir should not have the marker")
	}

	// Clearing a non-existent marker must succeed silently.
	if err := ClearServerDisabledMarker(tmp); err != nil {
		t.Fatalf("ClearServerDisabledMarker on absent marker: %v", err)
	}

	if err := WriteServerDisabledMarker(tmp); err != nil {
		t.Fatalf("WriteServerDisabledMarker: %v", err)
	}
	if !HasServerDisabledMarker(tmp) {
		t.Fatal("marker not detected after Write")
	}

	// File mode should be 0600 — the marker carries no secrets but
	// we still respect the agent's broader "data files live at 0600"
	// convention.
	info, err := os.Stat(MarkerPath(tmp))
	if err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("marker mode: got %o, want 0600", mode)
	}

	if err := ClearServerDisabledMarker(tmp); err != nil {
		t.Fatalf("ClearServerDisabledMarker: %v", err)
	}
	if HasServerDisabledMarker(tmp) {
		t.Fatal("marker still detected after Clear")
	}
}

// MarkerPath should be deterministic (same input → same output) and
// land inside the supplied dataDir — operators chasing "where is
// this file?" via stat() should find it where the function says.
func TestMarkerPath_DeterministicAndInsideDataDir(t *testing.T) {
	tmp := t.TempDir()
	got := MarkerPath(tmp)
	want := filepath.Join(tmp, "install_gate.server_disabled.marker")
	if got != want {
		t.Errorf("MarkerPath: got %q, want %q", got, want)
	}
	if MarkerPath(tmp) != got {
		t.Error("MarkerPath should be deterministic")
	}
}

// WriteServerDisabledMarker on a non-existent dataDir should error
// rather than silently mis-place the file.  Defensive: a typo'd
// dataDir must not become a silent failure.
func TestWriteServerDisabledMarker_NonexistentDirErrors(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "this", "does", "not", "exist")
	if err := WriteServerDisabledMarker(bogus); err == nil {
		t.Error("expected error writing marker into non-existent dataDir")
	}
}

// RemoveAll on a fresh dataDir (no writer-managed files exist
// anywhere on this host) should not error.  The per-writer no-
// endpoint branch already does isSentariManaged() first, returns
// false for absent files, and short-circuits to nil.  So this is a
// regression test that the wiring of RemoveAll → Apply(emptyMap, ...)
// stays no-op-correct on a clean host.
func TestRemoveAll_NoConfigsIsNoop(t *testing.T) {
	// Reroute HOME so per-user writer paths point inside t.TempDir()
	// — guarantees no real ~/.pip/pip.conf etc gets touched on the
	// developer's box.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir()) // Windows fallback (test runs on Linux/macOS but harmless)

	res, errs := RemoveAll(ApplyOptions{})
	if len(errs) > 0 {
		t.Fatalf("RemoveAll on clean host produced errors: %v", errs)
	}
	if res.AnyChanged() {
		t.Errorf("RemoveAll on clean host should be a no-op, got %+v", res)
	}
}
