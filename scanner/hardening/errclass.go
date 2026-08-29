package hardening

import (
	"errors"
	"io/fs"
	"os"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// isNotExist reports whether err means the source file is absent.
func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist)
}

// isPermission reports whether err means the source was present but unreadable
// for permission reasons — including safeio's symlink refusal, which is a
// deliberate read-refusal rather than an absence.
func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, safeio.ErrSymlink) ||
		errors.Is(err, safeio.ErrNotRegular)
}
