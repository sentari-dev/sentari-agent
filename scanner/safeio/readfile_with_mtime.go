package safeio

import (
	"fmt"
	"io"
	"time"
)

// ReadFileWithMTime reads up to maxSize bytes from path and
// returns both the bytes and the file's mtime, derived from the
// same open file descriptor so callers don't have to follow up
// with a path-based `os.Stat` (which reintroduces the TOCTOU
// window this package exists to prevent).
//
// Use when the caller needs an install-date / first-seen proxy
// alongside the file content.  Scanner plugins (aiagents MCP
// configs, npm package.json, VS Code extension manifests) all
// stamp `PackageRecord.InstallDate` from the manifest mtime;
// doing it via a separate stat() after `ReadFile` would let a
// hostile symlink swap between the two operations change which
// file's mtime we reported.  A single fd closes that window.
//
// All policy that applies to `ReadFile` applies here too — this
// function is `ReadFile` plus an atomically-derived mtime:
// leaf-symlink refusal, non-positive size-cap rejection, size cap,
// non-regular-file (directory / FIFO / device / socket) refusal via
// ErrNotRegular, and `os.ErrNotExist` passthrough so callers'
// `errors.Is(err, os.ErrNotExist)` branching still works.
func ReadFileWithMTime(path string, maxSize int64) ([]byte, time.Time, error) {
	if maxSize <= 0 {
		return nil, time.Time{}, fmt.Errorf("%w: non-positive size cap %d", ErrTooLarge, maxSize)
	}

	f, err := openNoFollow(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()

	// Stat via the file descriptor — avoids a TOCTOU where the path
	// is swapped to a symlink between openNoFollow and a path-based
	// stat.  Same policy sequence as ReadFile.
	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if info.IsDir() {
		// Wrap ErrNotRegular (a directory is a non-regular file) so
		// errors.Is(err, ErrNotRegular) is reliable and consistent with
		// ReadFile/Open; keep the specific "directory" detail.
		return nil, time.Time{}, fmt.Errorf("%w: %q is a directory", ErrNotRegular, path)
	}
	if !info.Mode().IsRegular() {
		// FIFO, device node, or socket.  Reject before reading: a
		// device could stream unbounded bytes and a FIFO has no
		// meaningful size.
		return nil, time.Time{}, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	if info.Size() > maxSize {
		return nil, time.Time{}, fmt.Errorf("%w: %d > %d at %s", ErrTooLarge, info.Size(), maxSize, path)
	}

	// Cap+1 defence-in-depth, mirroring ReadFile: detect a post-stat
	// growth and return ErrTooLarge rather than silently truncating.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if int64(len(data)) > maxSize {
		return nil, time.Time{}, fmt.Errorf("%w: grew past cap at %s", ErrTooLarge, path)
	}
	return data, info.ModTime().UTC(), nil
}
