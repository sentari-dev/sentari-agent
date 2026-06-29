package aiagents

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// readFileWithMTime reads up to maxSize bytes from ``path`` and
// returns the bytes plus the file's mtime.  Both values are
// derived from the same open file descriptor so there is no
// path-based TOCTOU window between the read and the stat — this
// matters when a layer later uses the mtime as an install-date
// proxy (MCP configs, VS Code extension manifests).
//
// Leaf-symlink refusal + size cap are enforced the same way as
// ``safeio.ReadFile``; this helper exists solely to return the
// mtime atomically with the read.  If callers only need the
// bytes, ``safeio.ReadFile`` is the right entry point.
//
// Returns os.ErrNotExist unchanged when the path doesn't exist
// so callers can keep their ``errors.Is(err, os.ErrNotExist)``
// branching.
func readFileWithMTime(path string, maxSize int64) ([]byte, time.Time, error) {
	if maxSize <= 0 {
		return nil, time.Time{}, fmt.Errorf("invalid max size %d", maxSize)
	}
	f, err := safeio.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if info.IsDir() {
		return nil, time.Time{}, fmt.Errorf("%q is a directory, not a regular file", path)
	}
	if info.Size() > maxSize {
		return nil, time.Time{}, fmt.Errorf("%w: %d > %d at %s",
			safeio.ErrTooLarge, info.Size(), maxSize, path)
	}
	// Cap +1 defence-in-depth: detect a post-stat growth instead
	// of silent truncation.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if int64(len(data)) > maxSize {
		return nil, time.Time{}, fmt.Errorf("%w: grew past cap at %s",
			safeio.ErrTooLarge, path)
	}
	return data, info.ModTime().UTC(), nil
}

// Alias so call sites can ``errors.Is(err, errNotExist)`` without
// importing os.
var errNotExist = os.ErrNotExist

// isNotExist reports whether err wraps os.ErrNotExist.  Separate
// helper so callers don't repeat the errors.Is boilerplate.
func isNotExist(err error) bool { return errors.Is(err, errNotExist) }
