package aiagents

import (
	"os"
	"runtime"
)

// userHome returns the current user's home directory using the
// platform-appropriate env var.  "" when HOME/USERPROFILE is unset
// (rare on real deployments, common on minimal CI images).
//
// Local to this package rather than shared with scanner/jvm to keep
// each plugin's import surface small and self-contained — the
// cross-plugin coupling cost is one tiny helper per package, which
// is cheaper than an internal-utilities module everyone imports.
func userHome() string {
	if runtime.GOOS == "windows" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			return up
		}
	}
	return os.Getenv("HOME")
}

// dirExists returns true iff path names a directory on disk.
func dirExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.IsDir()
}
