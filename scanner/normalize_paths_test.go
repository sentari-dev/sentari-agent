package scanner

import (
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/runtimeversions"
)

// TestNormalizePaths verifies Windows-style backslash paths in every
// path-bearing field are rewritten to forward slashes, that POSIX paths are
// left untouched, and that non-path labels are never mangled.
func TestNormalizePaths(t *testing.T) {
	res := &ScanResult{
		Packages: []PackageRecord{
			{
				Name:        "requests",
				InstallPath: `C:\Users\alice\AppData\Local\Programs\Python\Python311\Lib\site-packages\requests`,
				Environment: `C:\venvs\app`,
				EnvType:     "pip", // label — must not change
			},
			{
				Name:        "flask",
				InstallPath: "/usr/lib/python3/dist-packages/flask", // already POSIX
				Environment: "/usr/lib/python3",
			},
		},
		Errors: []ScanError{
			{Path: `C:\Windows\System32\config`, EnvType: "venv"},
		},
		Lockfiles: []deptree.LockfileMeta{
			{Path: `C:\repo\poetry.lock`, Format: "poetry"},
		},
		InstalledRuntimes: []runtimeversions.InstalledRuntime{
			{Name: "node", InstallPath: `C:\Program Files\nodejs`},
		},
	}

	NormalizePaths(res)

	wantPkg0 := "C:/Users/alice/AppData/Local/Programs/Python/Python311/Lib/site-packages/requests"
	if got := res.Packages[0].InstallPath; got != wantPkg0 {
		t.Errorf("Packages[0].InstallPath = %q, want %q", got, wantPkg0)
	}
	if got := res.Packages[0].Environment; got != "C:/venvs/app" {
		t.Errorf("Packages[0].Environment = %q, want C:/venvs/app", got)
	}
	if got := res.Packages[0].EnvType; got != "pip" {
		t.Errorf("EnvType label mutated: %q", got)
	}
	if got := res.Packages[1].InstallPath; got != "/usr/lib/python3/dist-packages/flask" {
		t.Errorf("POSIX path mutated: %q", got)
	}
	if got := res.Errors[0].Path; got != "C:/Windows/System32/config" {
		t.Errorf("Errors[0].Path = %q", got)
	}
	if got := res.Lockfiles[0].Path; got != "C:/repo/poetry.lock" {
		t.Errorf("Lockfiles[0].Path = %q", got)
	}
	if got := res.InstalledRuntimes[0].InstallPath; got != "C:/Program Files/nodejs" {
		t.Errorf("InstalledRuntimes[0].InstallPath = %q", got)
	}
}

// TestNormalizePathsNil ensures a nil result is handled gracefully.
func TestNormalizePathsNil(t *testing.T) {
	NormalizePaths(nil) // must not panic
}
