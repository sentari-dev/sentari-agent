package scanner

import (
	"strings"
	"testing"
)

// TestWindowsNodeCandidateBinaries checks the Windows node.exe candidate
// enumeration covers the common install methods (MSI, nvm-windows, fnm,
// Scoop, Chocolatey).  It exercises the pure path-building logic and runs on
// any host — filepath.Glob simply returns no matches for managers that aren't
// present, which is the intended behaviour.
func TestWindowsNodeCandidateBinaries(t *testing.T) {
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)
	t.Setenv("ChocolateyInstall", `C:\choco`)
	// Clear manager dirs so the glob branches are deterministic (no matches).
	t.Setenv("APPDATA", "")
	t.Setenv("FNM_DIR", "")
	t.Setenv("LOCALAPPDATA", "")

	got := windowsNodeCandidateBinaries()
	joined := strings.Join(got, "\n")

	mustContain := []string{
		`C:\Program Files/nodejs/node.exe`,
		`C:\Program Files (x86)/nodejs/node.exe`,
		`C:\choco/bin/node.exe`,
	}
	for _, want := range mustContain {
		if !strings.Contains(joined, want) {
			t.Errorf("windowsNodeCandidateBinaries missing %q\ngot:\n%s", want, joined)
		}
	}
}

// TestWindowsNodeCandidateChocoDefault verifies the Chocolatey shim falls
// back to the well-known default path when ChocolateyInstall is unset.
func TestWindowsNodeCandidateChocoDefault(t *testing.T) {
	t.Setenv("ChocolateyInstall", "")
	t.Setenv("ProgramFiles", "")
	t.Setenv("ProgramFiles(x86)", "")
	t.Setenv("APPDATA", "")
	t.Setenv("FNM_DIR", "")
	t.Setenv("LOCALAPPDATA", "")

	got := windowsNodeCandidateBinaries()
	found := false
	for _, c := range got {
		if strings.Contains(c, `chocolatey`) && strings.HasSuffix(c, "node.exe") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Chocolatey default node.exe path, got %v", got)
	}
}
