// Package safeio provides symlink-refusing file reads for scanner
// parsers.
//
// Every metadata file the agent parses (dpkg status, /usr/share/doc/*/
// copyright, conda-meta/*.json, dist-info/METADATA, poetry.lock,
// Pipfile.lock, pyvenv.cfg, …) sits on the filesystem alongside
// package-manager-installed content.  A malicious .deb or similarly-
// installed package can ship its own "copyright" as a symlink to
// /etc/shadow; the scanner used to follow it and quietly upload the
// password hash into a scan payload.  Every such read is now routed
// through ReadFile below.
//
// Policy:
//   - Refuse to read a path whose leaf entry is a symbolic link.
//   - Refuse to read a file larger than maxSize — the caller-supplied
//     budget is a hard ceiling; we never return a partial file.
//   - On Linux / macOS / BSD the kernel enforces the symlink refusal
//     via O_NOFOLLOW (returns ELOOP at open time).  On Windows we
//     Lstat first and bail if ModeSymlink is set.
//
// Known residual risk: intermediate directory components that are
// symbolic links.  The leaf check alone does not catch
// ``/usr/share/doc/mypkg -> /etc`` followed by a benign leaf; a fully
// resolved-beneath variant would require openat2 on Linux 5.6+ and
// equivalent primitives elsewhere.  In practice the threat model we
// care about is the single-leaf symlink attack, which the leaf check
// fully covers.  See docs/ when that stronger primitive lands.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrSymlink is the sentinel error returned when a path or its leaf
// entry is a symbolic link.  Callers use errors.Is(err, ErrSymlink)
// to emit a specific ScanError so operators can audit blocked reads.
var ErrSymlink = errors.New("safeio: path is a symbolic link; refusing to read")

// ErrTooLarge is returned when a file exceeds the caller-supplied
// size cap.  Distinct from io.ErrShortBuffer so callers can tell the
// difference between a parser that got cut off and a file that was
// too big to read at all.
var ErrTooLarge = errors.New("safeio: file exceeds size cap")

// ReadFile reads up to maxSize bytes from path, refusing to follow a
// symbolic link at the leaf.  maxSize must be positive; passing 0 or
// a negative value returns ErrTooLarge regardless of file content.
//
// If path is a symlink, returns (nil, ErrSymlink).  If the file
// exceeds maxSize, returns (nil, ErrTooLarge) and never exposes any
// of the file's bytes to the caller — an attacker cannot drop a
// giant payload and force us to read its head.
func ReadFile(path string, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		return nil, fmt.Errorf("%w: non-positive size cap %d", ErrTooLarge, maxSize)
	}

	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Stat via the file descriptor — avoids a TOCTOU where the path
	// is swapped to a symlink between openNoFollow and a path-based
	// stat.  On platforms where openNoFollow returns a valid *os.File
	// on a directory, Stat() reports ModeDir and we reject below.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("safeio: %q is a directory, not a regular file", path)
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("%w: %d > %d at %s", ErrTooLarge, info.Size(), maxSize, path)
	}

	// Cap the read with a LimitReader as defence-in-depth — in the
	// extraordinary case that the file grows between Stat and Read
	// (e.g. a log file being appended to), we still refuse to take
	// more than maxSize bytes into memory.  +1 so we can detect a
	// post-stat growth and return ErrTooLarge rather than silent
	// truncation.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%w: grew past cap at %s", ErrTooLarge, path)
	}
	return data, nil
}

// Open opens path for reading, refusing to follow a symbolic link at
// the leaf.  The returned file MUST be closed by the caller.  Prefer
// ReadFile when the whole file fits in a bounded buffer; Open is for
// line-by-line streaming readers (dpkg status, pyvenv.cfg) where the
// caller enforces its own per-line bounds.
func Open(path string) (*os.File, error) {
	return openNoFollow(path)
}
