package containers

import (
	"os"
	"runtime"
)

// userHome returns the current user's home directory using the
// platform-appropriate env var.  Returns "" when HOME/USERPROFILE
// is unset (unusual on real deployments, common in minimal CI
// containers).  Mirrors the helper in scanner/jvm/scanner.go so
// callers don't need to import across plugins.
func userHome() string {
	if runtime.GOOS == "windows" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			return up
		}
	}
	return os.Getenv("HOME")
}

// dirExists returns true iff path is a directory on disk.
func dirExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.IsDir()
}
