package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Workspace Phase 5 §A — DOTNET_ROOT is honoured as an install-root override,
// and only existing directories are returned.
func TestDotnetCandidateRoots_honoursDotnetRootEnv(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("DOTNET_ROOT", custom)

	roots := dotnetCandidateRoots()
	found := false
	for _, r := range roots {
		if r == filepath.Clean(custom) || r == custom {
			found = true
		}
	}
	if !found {
		t.Errorf("dotnetCandidateRoots did not include DOTNET_ROOT=%q: %v", custom, roots)
	}
}

func TestDotnetCandidateRoots_dropsNonexistentDotnetRoot(t *testing.T) {
	t.Setenv("DOTNET_ROOT", filepath.Join(os.TempDir(), "definitely-not-here-xyz"))
	for _, r := range dotnetCandidateRoots() {
		if _, err := os.Stat(r); err != nil {
			t.Errorf("dotnetCandidateRoots returned a non-existent dir: %q", r)
		}
	}
}
