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
//   - Refuse to read a path whose leaf entry is a symbolic link — and,
//     on Linux 5.6+, a symbolic link at ANY path component (see below).
//   - Refuse to read a file larger than maxSize — the caller-supplied
//     budget is a hard ceiling; we never return a partial file.
//   - Refuse a non-regular file (directory, FIFO, device node, socket).
//
// Symlink refusal is enforced by validating the object we actually
// opened, never a prior path lookup, so there is no check-then-open
// TOCTOU window.  The exact primitive differs per platform:
//   - Linux (primary): openat2(2) with RESOLVE_NO_SYMLINKS refuses a
//     symlink at EVERY component atomically in the kernel — leaf and
//     intermediate directories alike.  See safeio_linux.go.
//   - Linux (fallback) / macOS / BSD: no openat2, so O_NOFOLLOW refuses
//     a symlink at the LEAF only (the kernel returns ELOOP/EMLINK at
//     open).  Linux degrades to this only on pre-5.6 kernels or when a
//     seccomp filter blocks openat2.  See safeio_unix.go.
//   - Windows: there is no O_NOFOLLOW.  CreateFile with
//     FILE_FLAG_OPEN_REPARSE_POINT opens the leaf itself rather than
//     following it, then GetFileInformationByHandle inspects the handle
//     we already hold; a FILE_ATTRIBUTE_REPARSE_POINT leaf is refused.
//     This handle-validated check-after-open replaces an earlier
//     Lstat-then-open approach that carried a TOCTOU window (a leaf
//     swapped between the stat and the open would have been followed).
//     See safeio_windows.go.
//
// Residual risk (fallback / macOS / BSD / Windows ONLY): a symlinked
// INTERMEDIATE directory component is still resolved on those paths, so
// `/usr/share/doc/mypkg -> /etc` followed by a benign leaf would be
// followed.  The Linux openat2 primary path closes this gap entirely; a
// fully resolved-beneath variant elsewhere would need a per-component
// handle walk (no portable primitive exists).  The threat model we care
// about — the single-leaf symlink swap — is fully covered on every
// platform.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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

// ErrNotRegular is returned when a path resolves to something other
// than a regular file — a FIFO, device node, socket, or directory.
// O_NOFOLLOW refuses a symlink leaf but says nothing about these: a
// blocking open() of a writer-less FIFO hangs forever and a device
// node can stream unbounded bytes, so a malicious package shipping a
// metadata file as a special file would otherwise wedge the scanner.
var ErrNotRegular = errors.New("safeio: path is not a regular file; refusing to read")

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
		// Wrap ErrNotRegular (a directory is a non-regular file) so
		// errors.Is(err, ErrNotRegular) is reliable and consistent with
		// Open(); keep the specific "directory" detail in the message.
		return nil, fmt.Errorf("%w: %q is a directory", ErrNotRegular, path)
	}
	if !info.Mode().IsRegular() {
		// FIFO, device node, or socket.  Reject before reading: a
		// device could stream unbounded bytes and a FIFO has no
		// meaningful size.
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, path)
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

// ReadDir reads the named directory, refusing to follow a symbolic
// link at the leaf.  It is the directory-listing analogue of ReadFile:
// a malicious package could install a version directory in ~/.m2 as a
// symlink pointing at an arbitrary path; following it with os.ReadDir
// would enumerate that target instead.
//
// Like ReadFile, the symlink refusal is enforced on the object we
// actually opened, never a prior path lookup: openNoFollowDir opens the
// directory with a symlink-refusing primitive (Linux openat2 with
// RESOLVE_NO_SYMLINKS as the primary, O_NOFOLLOW fallback; Windows
// FILE_FLAG_OPEN_REPARSE_POINT), we fstat the HELD fd to confirm it is a
// real directory, and we enumerate that same fd via (*os.File).ReadDir.
// The type check and the listing therefore operate on one inode with no
// second path resolution — closing the check-then-use TOCTOU window that
// the earlier Lstat-then-os.ReadDir implementation left open (a leaf
// swapped for a symlink between the Lstat and the ReadDir would have been
// followed).
//
// If path's leaf is a symlink, returns (nil, ErrSymlink).  If path is not
// a directory, returns (nil, ErrNotRegular) so callers can distinguish
// "absent" from "wrong type".  On success the entries are sorted by name
// (matching the os.ReadDir contract — (*os.File).ReadDir returns them in
// directory order, so we sort here).
//
// Scope of the refusal — same per-platform split as ReadFile (see the
// package doc):
//   - Linux (primary): openat2 with RESOLVE_NO_SYMLINKS refuses a symlink
//     at ANY path component — leaf and intermediate directories alike, so
//     an ancestor symlink can no longer redirect the enumeration.
//   - Linux fallback (pre-5.6 / openat2-blocked), macOS/BSD, Windows:
//     the leaf-only O_NOFOLLOW / reparse-point guard refuses only a
//     symlinked leaf; ancestor components are still resolved through any
//     symlinks they contain.  This residual is identical to ReadFile's
//     fallback residual — there is no portable resolve-beneath primitive
//     for enumeration on these platforms.
//
// When to use ReadDir vs a raw os.ReadDir — a deliberate, per-callsite
// judgment in the scanner tree:
//   - Use ReadDir for a freshly-constructed package-manager metadata or
//     version directory that is NEVER legitimately a symlink (e.g. an
//     ~/.m2 groupId/artifactId dir, a conda-meta dir).  A planted
//     symlink there can only be an attacker redirecting enumeration.
//   - Do NOT use ReadDir for locations that are commonly REAL symlinks
//     in the wild — venv/site-packages, pnpm's virtual store, Homebrew
//     Cellar, JDK homes, pyenv/asdf/nvm version roots, usr-merge system
//     dirs (/usr/lib64 -> lib), Docker data-roots, or an operator-
//     supplied scan/data root.  Refusing those would reintroduce the
//     false-negative (missed-package) class.  Such sites instead
//     enumerate with os.ReadDir and skip symlinked ENTRIES per item
//     (see the npm/nuget plugins), which guards traversal without
//     refusing a legitimately-symlinked container directory.  Leaf FILE
//     reads under any of these already go through ReadFile/Open, so the
//     residual exfil risk of enumerating one is limited to filenames.
func ReadDir(path string) ([]os.DirEntry, error) {
	f, err := openNoFollowDir(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Confirm the object we opened is a directory by inspecting the HELD
	// fd — never a second path lookup.  On unix openNoFollowDir already
	// passes O_DIRECTORY (a non-dir fails ENOTDIR at open), so this is
	// defence-in-depth there; on Windows it is the primary type check for
	// a FIFO/file/device planted at the path.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrNotRegular, path)
	}

	// Enumerate the SAME fd: no path is resolved a second time, so a swap
	// to a symlink after the open cannot redirect the listing.
	// (*os.File).ReadDir(-1) returns entries in directory order; sort by
	// name to preserve the os.ReadDir contract callers depend on.
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// Open opens path for reading, refusing to follow a symbolic link at
// the leaf.  The returned file MUST be closed by the caller.  Prefer
// ReadFile when the whole file fits in a bounded buffer; Open is for
// line-by-line streaming readers (dpkg status, pyvenv.cfg) where the
// caller enforces its own per-line bounds.
func Open(path string) (*os.File, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	// Reject non-regular files (FIFO/device/socket/dir) so a streaming
	// caller cannot be made to block forever or read an unbounded
	// device.  Stat via the fd to avoid a path-based TOCTOU.
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	return f, nil
}
