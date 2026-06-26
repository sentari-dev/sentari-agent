//go:build !windows

package secureperm

import "os"

// restrict re-asserts the restrictive POSIX mode bits.  The agent already
// creates these objects with the right mode (0700 dirs, 0600 files), so this
// is belt-and-braces against an umask or a future caller that forgot — and it
// keeps the cross-platform call sites uniform.
func restrict(path string, isDir bool) error {
	mode := os.FileMode(0o600)
	if isDir {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}
