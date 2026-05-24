package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// mkProtected creates the named subfolders under home; those whose name is in
// nonEmpty get a sentinel file so they read as non-empty.
func mkProtected(t *testing.T, home string, folders []string, nonEmpty map[string]bool) {
	t.Helper()
	for _, name := range folders {
		dir := filepath.Join(home, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if nonEmpty[name] {
			if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// All protected folders present and empty → strong TCC signal → true.
func TestHomeLikelyTCCBlocked_AllProtectedEmpty(t *testing.T) {
	home := t.TempDir()
	mkProtected(t, home, []string{"Documents", "Desktop", "Downloads"}, nil)
	if !homeLikelyTCCBlocked(home) {
		t.Error("expected TCC-blocked when all protected folders exist and are empty")
	}
}

// One protected folder has content → not a uniform empty signal → false.
func TestHomeLikelyTCCBlocked_OneNonEmpty(t *testing.T) {
	home := t.TempDir()
	mkProtected(t, home, []string{"Documents", "Desktop", "Downloads"}, map[string]bool{"Desktop": true})
	if homeLikelyTCCBlocked(home) {
		t.Error("expected NOT blocked when a protected folder has content")
	}
}

// Only a single protected folder exists and is empty → weak signal (could be
// genuinely empty) → false, to avoid the false-positive warning.
func TestHomeLikelyTCCBlocked_SingleEmptyFolderIsWeak(t *testing.T) {
	home := t.TempDir()
	mkProtected(t, home, []string{"Documents"}, nil)
	if homeLikelyTCCBlocked(home) {
		t.Error("expected NOT blocked when only one protected folder exists (weak signal)")
	}
}

// No protected folders at all → false.
func TestHomeLikelyTCCBlocked_NoneExist(t *testing.T) {
	home := t.TempDir()
	if homeLikelyTCCBlocked(home) {
		t.Error("expected NOT blocked when no protected folders exist")
	}
}
