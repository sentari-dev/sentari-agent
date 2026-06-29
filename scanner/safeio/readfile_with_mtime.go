package safeio

import (
	"fmt"
	"io"
	"time"
)

// ReadFileWithMTime reads up to maxSize bytes from path and
// returns both the bytes and the file's mtime, derived from the
// same open file descriptor so callers don't have to follow up
// with a path-based ``os.Stat`` (which reintroduces the TOCTOU
// window this package exists to prevent).
//
// Use when the caller needs an install-date / first-seen proxy
// alongside the file content.  Scanner plugins (aiagents MCP
// configs, npm package.json, VS Code extension manifests) all
// stamp ``PackageRecord.InstallDate`` from the manifest mtime;
// doing it via a separate stat() after ``ReadFile`` would let a
// hostile symlink swap between the two operations change which
// file's mtime we reported.  A single fd closes that window.
//
// All policy that applies to ``ReadFile`` applies here too:
// leaf-symlink refusal, size cap, ``io.ErrNotExist`` passthrough
// so callers' ``os.IsNotExist`` branching still works.
func ReadFileWithMTime(path string, maxSize int64) ([]byte, time.Time, error) {
	if maxSize <= 0 {
		return nil, time.Time{}, fmt.Errorf("%w: non-positive size cap %d", ErrTooLarge, maxSize)
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if info.IsDir() {
		return nil, time.Time{}, fmt.Errorf("safeio: %q is a directory, not a regular file", path)
	}
	if info.Size() > maxSize {
		return nil, time.Time{}, fmt.Errorf("%w: %d > %d at %s", ErrTooLarge, info.Size(), maxSize, path)
	}

	// Cap+1 defence-in-depth, mirroring ReadFile.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if int64(len(data)) > maxSize {
		return nil, time.Time{}, fmt.Errorf("%w: grew past cap at %s", ErrTooLarge, path)
	}
	return data, info.ModTime().UTC(), nil
}
