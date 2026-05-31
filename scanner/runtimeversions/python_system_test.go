package runtimeversions

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// mustMkdir is the package-local test helper used by every
// table-driven layout test below.  Same shape as in scanner/licenses
// and scanner/supplychain so anyone copy-pasting cases between
// packages doesn't have to relearn the helper.
func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// versions extracts and sorts the Version field from every entry so
// table-driven tests can compare via slice equality without caring
// about scan order.
func versions(rts []InstalledRuntime) []string {
	out := make([]string, 0, len(rts))
	for _, r := range rts {
		out = append(out, r.Version)
	}
	sort.Strings(out)
	return out
}

func TestDetectAllSystemPythons_homebrewCellar(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Cellar")
	// Apple Silicon layout: <root>/python@<series>/<full-version>/.
	mustMkdir(t, filepath.Join(root, "python@3.13", "3.13.7"))
	mustMkdir(t, filepath.Join(root, "python@3.12", "3.12.4"))
	// Side-by-side same series with a rev suffix — Homebrew uses ``_N``
	// to mark a re-build; we strip that for the canonical version.
	mustMkdir(t, filepath.Join(root, "python@3.12", "3.12.5_1"))
	// Noise that must be ignored: a non-formula sibling, and a stray
	// file inside the formula dir.
	mustMkdir(t, filepath.Join(root, "ruby@3.3", "3.3.0"))
	if err := os.WriteFile(filepath.Join(root, "python@3.13", "INSTALL_RECEIPT.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	assertVersions(t, versions(DetectAllSystemPythons([]string{root})), []string{"3.12.4", "3.12.5", "3.13.7"})
}

// assertVersions checks the detected version list both in length AND
// content.  Pre-PR-#43-fix the layout tests only asserted len() — a
// regression that returned three garbage strings would have passed
// silently.  Centralising the deep-equal check here keeps the
// individual tests readable.
func assertVersions(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("versions = %v, want %v", got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestDetectAllSystemPythons_pythonFramework(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Python.framework", "Versions")
	mustMkdir(t, filepath.Join(root, "3.11"))
	mustMkdir(t, filepath.Join(root, "3.12"))
	// Framework "Current" symlink-style alias — directory exists but
	// the name doesn't match X.Y so we shouldn't emit a duplicate.
	mustMkdir(t, filepath.Join(root, "Current"))
	// Stale Versions/3 dir from older python.org installers — single
	// component, also not a series, ignore.
	mustMkdir(t, filepath.Join(root, "3"))

	assertVersions(t, versions(DetectAllSystemPythons([]string{root})), []string{"3.11", "3.12"})
}

func TestDetectAllSystemPythons_distroLib(t *testing.T) {
	// /usr/lib layout: <root>/python<X.Y>/ alongside non-python siblings.
	root := filepath.Join(t.TempDir(), "lib")
	mustMkdir(t, filepath.Join(root, "python3.10"))
	mustMkdir(t, filepath.Join(root, "python3.11"))
	mustMkdir(t, filepath.Join(root, "perl5")) // ignored
	mustMkdir(t, filepath.Join(root, "python2.7"))
	// Nested ``python3.11/site-packages`` — must NOT be re-emitted; the
	// walker only matches the top level.
	mustMkdir(t, filepath.Join(root, "python3.11", "site-packages"))

	assertVersions(t, versions(DetectAllSystemPythons([]string{root})), []string{"2.7", "3.10", "3.11"})
}

func TestDetectAllSystemPythons_windowsLayout(t *testing.T) {
	// Windows: ``<ProgramFiles>\Python311\`` — flattened ``XY``.
	root := filepath.Join(t.TempDir(), "Python")
	mustMkdir(t, filepath.Join(root, "Python310"))
	mustMkdir(t, filepath.Join(root, "Python311"))
	mustMkdir(t, filepath.Join(root, "Python313"))
	// Junk siblings that don't match the regex must be skipped.
	mustMkdir(t, filepath.Join(root, "Common Files"))
	mustMkdir(t, filepath.Join(root, "Python3-tools")) // 'Python3-…' doesn't match Python<XY>

	assertVersions(t, versions(DetectAllSystemPythons([]string{root})), []string{"3.10", "3.11", "3.13"})
}

// Direct per-machine ProgramFiles layout: each ``Python<XY>\`` is a
// sibling of ProgramFiles itself, not under an umbrella ``Python/``
// parent.  v3_enrich.go now globs those siblings and feeds each one
// directly — which triggers the detector's ``HasPrefix(base,
// "Python")`` branch.  Exercise that path so the regression doesn't
// silently revert.
func TestDetectAllSystemPythons_directPython311Root(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Python311")
	mustMkdir(t, root)
	assertVersions(t, versions(DetectAllSystemPythons([]string{root})), []string{"3.11"})
}

func TestDetectAllSystemPythons_unknownRootSkipped(t *testing.T) {
	// A root that doesn't end in any of the recognised anchors must be
	// silently ignored — don't try every layout against every root or
	// we hit false positives.
	root := filepath.Join(t.TempDir(), "random")
	mustMkdir(t, filepath.Join(root, "python@3.13", "3.13.7"))
	got := DetectAllSystemPythons([]string{root})
	if len(got) != 0 {
		t.Errorf("expected 0 runtimes for unknown root, got %+v", got)
	}
}

func TestDetectAllSystemPythons_cycleDerivation(t *testing.T) {
	// Verify the Cycle field is the X.Y series, not the raw input —
	// that's what the server's runtime_eol_cycle.py keys on.
	root := filepath.Join(t.TempDir(), "Cellar")
	mustMkdir(t, filepath.Join(root, "python@3.13", "3.13.7"))
	got := DetectAllSystemPythons([]string{root})
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Cycle != "3.13" {
		t.Errorf("Cycle = %q, want 3.13", got[0].Cycle)
	}
	if got[0].Version != "3.13.7" {
		t.Errorf("Version = %q, want 3.13.7", got[0].Version)
	}
}
