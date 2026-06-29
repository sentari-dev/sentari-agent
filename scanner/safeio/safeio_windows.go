//go:build windows

package safeio

import (
	"fmt"
	"os"
)

// openNoFollow on Windows uses Lstat to detect symbolic-link leaves
// (``os.ModeSymlink``) and refuses before opening.  Windows does not
// have a direct O_NOFOLLOW equivalent; the ``os.Open`` call that
// follows transparently resolves any symlinks at the leaf.  By
// explicitly checking Lstat first we close the same hole the Unix
// O_NOFOLLOW path closes.  There is a small TOCTOU window between
// Lstat and Open — accepted: the attacker would need write access to
// the same directory, at which point the scanner's trust model
// already assumes the worst.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, path)
	}
	return os.Open(path)
}
