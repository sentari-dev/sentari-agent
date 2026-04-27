// Package installgate writes the native package-manager config files
// that route ``pip install``, ``npm install``, ``mvn`` etc. through
// Sentari-Proxy.  Phase B of the install-gate feature; per-ecosystem
// writers register themselves with this package and the agent
// orchestrator (lands later) calls ``Apply`` once per scan cycle
// with the verified policy-map.
//
// Why a top-level package and not a subdir of ``scanner/``: scanner
// is the read side of the agent (discovers installed packages).
// installgate is the write side — it changes how the host's package
// managers behave on the next install.  Conflating the two would
// blur the agent's threat model: a scanner-only audit can declare
// "this binary never modifies host configuration" today, and that
// claim survives only if the writer code lives somewhere a reviewer
// can clearly identify by package boundary.
//
// Common writer invariants (per design doc §4):
//
//  1. **Atomic replace.**  Write to ``<path>.sentari-tmp``, fsync,
//     rename.  A crash mid-write must never leave a truncated
//     config file.
//  2. **Sentari-managed marker.**  Every written file begins with
//     a comment block (syntax adapted per file format) that
//     identifies the file as Sentari-managed and warns operators
//     against hand-edits.
//  3. **Backup on first write.**  The first time the agent writes
//     to a path that already exists, the previous content is
//     preserved at ``<path>.sentari-backup-<RFC3339-timestamp>``.
//     Operators can ``mv`` the backup back to fully revert if they
//     decide to disable the gate.

package installgate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// MaxConfigFileBytes is the upper bound this package will ever
// write to a single config file.  Pip / npm / Maven configs are a
// few KiB at most in practice; a payload bigger than this would be
// either a programmer error or a malicious envelope that slipped
// past the policy-map size cap.  Refuse rather than write.
const MaxConfigFileBytes = 256 * 1024 // 256 KiB

// MarkerFields is the data the ``// Managed by Sentari (...)``
// comment block embeds.  The agent uses the version + key_id to
// confirm a config was written by *this* policy-map (not an older
// cached one) when reasoning about drift; the timestamp is a human
// debugging aid.
type MarkerFields struct {
	Version int
	KeyID   string
	Applied time.Time
}

// WriteOptions controls one ``WriteAtomic`` call.  Constructed by
// the per-ecosystem writers, not directly by callers, so the
// invariants stay consistent across pip / npm / Maven / NuGet etc.
type WriteOptions struct {
	// Path is the final destination of the file (e.g.
	// ``/etc/pip.conf``).  Parent directories are created with
	// mode 0755 if absent — pip / npm / Maven all expect their
	// config dirs to be world-readable so non-root tooling can
	// inspect them, and a tighter mode would break common
	// debugging flows.
	Path string

	// Content is the canonical bytes to write.  Must already
	// include the ``Managed by Sentari`` marker — RenderManagedHeader
	// does that for the writer.
	Content []byte

	// FileMode is the mode applied to the rendered file.  Pip
	// configs at 0644 (world-readable, owner-writable); apt / yum
	// repo files the same.  The user-vs-system scope decision lives
	// upstream in the per-ecosystem writer.
	FileMode os.FileMode

	// BackupSuffix lets the per-ecosystem writer override the
	// default ``.sentari-backup-<timestamp>`` suffix when the
	// upstream tool dislikes wildcards.  Empty → default.
	BackupSuffix string

	// Now is the timestamp to embed in the backup filename.
	// Injectable so tests get deterministic output.
	Now time.Time
}

// WriteAtomic implements the three writer invariants.  Returns
// ``true`` if the file was created or updated, ``false`` when the
// existing content already matches Content (idempotent re-write —
// no I/O, no audit-noise).
//
// Errors are typed (via ``%w``-wrapping standard ``os`` errors)
// so callers can distinguish "permission denied" (operator needs
// root) from genuine bugs.
func WriteAtomic(opts WriteOptions) (bool, error) {
	if opts.Path == "" {
		return false, errors.New("installgate.WriteAtomic: empty path")
	}
	if len(opts.Content) > MaxConfigFileBytes {
		return false, fmt.Errorf(
			"installgate.WriteAtomic: content exceeds max size (%d > %d)",
			len(opts.Content), MaxConfigFileBytes,
		)
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.FileMode == 0 {
		opts.FileMode = 0o644
	}

	// Cleanup any stranded ``.sentari-tmp`` from a prior run that
	// crashed between fsync and rename.  Best-effort — a permission
	// error here doesn't block the normal write path because the
	// final ``os.Rename`` will fail anyway with a clearer message.
	tmpPath := opts.Path + ".sentari-tmp"
	_ = os.Remove(tmpPath)

	// Idempotency check.  If the path exists and its bytes already
	// match what we are about to write, skip the rename + fsync —
	// every applied policy would otherwise rewrite identical files
	// once per scan cycle and bury the genuine "config changed"
	// signal in mtime noise.
	if existing, err := readBoundedIfExists(opts.Path); err == nil && existing != nil {
		if bytesEqual(existing, opts.Content) {
			return false, nil
		}
		// Content differs — back up the existing file before we
		// overwrite it.  Subsequent rewrites land idempotency above
		// and skip the backup branch entirely (so we never produce
		// a backup-of-a-backup).
		if err := backupOriginal(opts.Path, opts.Now, opts.BackupSuffix); err != nil {
			return false, fmt.Errorf("backup original: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect existing %s: %w", opts.Path, err)
	}

	// Ensure parent dir exists.  Pip / npm / Maven all use
	// world-readable config dirs (0755) so debugging tools can
	// inspect them as a non-root user.
	parent := filepath.Dir(opts.Path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return false, fmt.Errorf("create config dir %s: %w", parent, err)
	}

	// Atomic write: tmpfile in same dir → fsync → rename → fsync
	// parent.  Same dir matters: ``rename`` is atomic only inside
	// one filesystem, and ``filepath.Dir(opts.Path)`` is the
	// filesystem we already know we have permission to write to.
	if err := writeAndSync(tmpPath, opts.Content, opts.FileMode); err != nil {
		// Best-effort cleanup; ignoring removal errors here is OK
		// because the next scan cycle's first write attempt does
		// the same dance and the rename target is the same.
		_ = os.Remove(tmpPath)
		return false, err
	}
	if err := os.Rename(tmpPath, opts.Path); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("rename %s -> %s: %w", tmpPath, opts.Path, err)
	}
	// fsync the parent directory so the rename's metadata change
	// hits disk before we declare success.  Without this, ext4 / xfs
	// can lose the rename across a power cut even though the file
	// data was synced.  Best-effort + POSIX-only — Windows file
	// systems don't support directory fsync, so the helper is a
	// no-op there (see syncDir_*.go).
	if err := syncDir(parent); err != nil {
		// Surface as a warning-level error wrap rather than failing
		// the apply: the file IS visible at this point, and the
		// trade-off "config not durable across crash" is dramatically
		// better than "agent crashes every apply on a filesystem
		// that doesn't support O_DIRECTORY syncs".
		return true, fmt.Errorf("fsync parent %s: %w", parent, err)
	}
	return true, nil
}

// validateEndpoint refuses URL strings that contain bytes which
// would let a tampered (or pathologically misconfigured) policy-map
// inject additional config directives into a rendered file.  The
// per-ecosystem renderers interpolate ``endpoint`` directly into a
// line-oriented config (pip's ``index-url = ...``, npm's
// ``registry=...``), so a CR or LF in the endpoint produces a
// well-formed file with extra lines — for npm that means an
// attacker-chosen ``registry=`` overrides ours; for pip an
// extra ``[section]`` could disable the proxy entirely.
//
// Defence-in-depth: the policy-map signature has already been
// verified upstream and the operator vetted the URL via the
// dashboard, so injection requires server compromise + signature
// forgery.  Even so, every renderer routes through this gate so
// a future config path that's less protected (e.g. a local-file
// override for dev) inherits the same guarantee.
func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("empty endpoint")
	}
	// Reject CR/LF and any other ASCII control byte (0x00–0x1F or
	// 0x7F).  Spaces are also rejected because pip + npm both
	// silently truncate at the first whitespace and an embedded
	// space would produce a half-applied URL.
	for i := 0; i < len(endpoint); i++ {
		c := endpoint[i]
		if c < 0x20 || c == 0x7F || c == ' ' {
			return fmt.Errorf("endpoint contains forbidden byte 0x%02x at offset %d", c, i)
		}
	}
	return nil
}

// sentariManagedSentinel is the byte sequence every rendered config
// begins with.  Per design §4 every writer prepends a ``Managed by
// Sentari`` comment block; matching the literal bytes here keeps
// the marker check syntax-agnostic across the # / <!-- variants
// because both share this prefix.
var sentariManagedSentinel = []byte("# Managed by Sentari")
var sentariManagedSentinelXML = []byte("<!-- Managed by Sentari")

// isSentariManaged reports whether ``path`` exists AND carries
// the Sentari-managed marker within its first ``markerSearchBytes``
// bytes.  Returns:
//
//   - ``(false, nil)`` for absent files (the writer treats this as
//     "no Sentari ownership claim", same as the operator-curated
//     case below).
//   - ``(false, nil)`` for files that exist but lack the marker
//     (operator-curated pre-Sentari config, or hand-edited).
//   - ``(true, nil)`` when the marker is present.
//   - ``(false, err)`` on permission/IO errors so the caller can
//     refuse to act under uncertainty.
//
// 1 KiB is enough to decide.  The hash-marker variant (pip / npm /
// apt / yum) sits at offset zero, so a tiny prefix-check would be
// fine for those — but the XML-marker variant (Maven, NuGet) sits
// AFTER the ``<?xml ...?>`` declaration on line 2, so we need a
// substring scan rather than a prefix match.  ``bytes.Contains``
// is fine; the read is bounded, the search is linear.
const markerSearchBytes = 1024

func isSentariManaged(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	head := make([]byte, markerSearchBytes)
	n, err := f.Read(head)
	if err != nil && err != io.EOF {
		return false, err
	}
	head = head[:n]
	if bytesContains(head, sentariManagedSentinel) || bytesContains(head, sentariManagedSentinelXML) {
		return true, nil
	}
	return false, nil
}

// bytesContains returns true iff ``needle`` appears anywhere in
// ``haystack``.  We hand-roll this rather than importing ``bytes``
// to keep this package's import surface auditable — three other
// helpers (``bytesEqual``, ``bytesPrefix``, ``bytesContains``)
// share the same minimalist trade-off.
func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Remove deletes a previously-written Sentari-managed config file.
// Used by the fail-open code path: when the policy disappears from
// the server (or the agent has been told to disable install-gate)
// the writer reverts the host to "no Sentari proxy" state by
// removing the file.  No backup is produced — callers that wanted
// to preserve the pre-Sentari state already have ``.sentari-backup-*``
// from the original write.
//
// Returns ``(false, nil)`` if the path doesn't exist (fresh host or
// already removed) so the caller can no-op idempotently.
func Remove(path string) (bool, error) {
	if path == "" {
		return false, errors.New("installgate.Remove: empty path")
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("remove %s: %w", path, err)
	}
	return true, nil
}

// readBoundedIfExists returns the file contents capped at
// ``MaxConfigFileBytes+1``.  A ``nil`` return paired with a ``nil``
// error means the file does not exist (caller's idempotency branch
// short-circuits to "first write").
func readBoundedIfExists(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxConfigFileBytes+1))
}

// bytesEqual returns true iff two byte slices carry the same bytes.
// Replaces ``bytes.Equal`` only because we want one less import in
// the public API surface of this package — nothing fancy.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeAndSync writes data to path and fsyncs before returning.
// Without the fsync, a kernel crash between rename and journal
// flush could leave us with a renamed-but-empty file.
func writeAndSync(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open tmp %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write tmp %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync tmp %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp %s: %w", path, err)
	}
	// Tighten the mode after the file exists — OpenFile honours
	// umask, so the explicit Chmod ensures the rendered config
	// matches ``opts.FileMode`` regardless of the agent's umask
	// (root-installed agents typically inherit umask 022, which
	// happens to match 0644, but we don't rely on that).
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod tmp %s: %w", path, err)
	}
	return nil
}

// backupOriginal copies the existing file to
// ``<path>.sentari-backup-<RFC3339-timestamp>`` (or to
// ``<path><customSuffix>`` when supplied).  Mode is preserved from
// the source via an explicit ``os.Chmod`` after create — relying
// on ``os.OpenFile``'s perm argument alone is umask-subject and
// would quietly drop bits the operator had set on the original.
//
// The copy is bounded by ``MaxConfigFileBytes``: a pre-existing
// pip.conf bigger than that is almost certainly malicious or
// pathological, and copying it to a backup would (a) waste disk
// proportional to the attacker's input and (b) recur every time we
// rewrote the config.  Refuse rather than back up.
//
// Idempotent at the byte level: if a backup with the same
// destination name somehow already exists (clock-skew + same-
// second double-call), it's left alone — never overwritten — so an
// operator who has hand-curated a backup file doesn't lose it.
func backupOriginal(path string, now time.Time, customSuffix string) error {
	suffix := customSuffix
	if suffix == "" {
		// Replace ":" with "-" so the file name is portable on
		// Windows (NTFS rejects colons in filenames).
		ts := now.UTC().Format("2006-01-02T15-04-05Z")
		suffix = ".sentari-backup-" + ts
	}
	dest := path + suffix
	if _, err := os.Stat(dest); err == nil {
		// Backup already exists from a prior run in this same
		// second; preserve it rather than clobbering.
		return nil
	}

	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open original %s: %w", path, err)
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat original %s: %w", path, err)
	}
	if srcInfo.Size() > MaxConfigFileBytes {
		return fmt.Errorf(
			"original %s exceeds backup size cap (%d > %d)",
			path, srcInfo.Size(), MaxConfigFileBytes,
		)
	}

	// O_EXCL — refuse to clobber, just in case the Stat-then-Open
	// raced with another writer (vanishingly rare, but free safety).
	dst, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, srcInfo.Mode().Perm())
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("open backup %s: %w", dest, err)
	}
	defer dst.Close()

	// Bounded copy.  +1 lets us distinguish "exactly at cap" (legal,
	// allowed via the Stat check above) from "grew between Stat and
	// Copy" (refuse).
	if _, err := io.Copy(dst, io.LimitReader(src, MaxConfigFileBytes+1)); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", path, dest, err)
	}
	if err := dst.Sync(); err != nil {
		return fmt.Errorf("fsync backup %s: %w", dest, err)
	}
	// OpenFile honours the process umask; a clean readable backup
	// at mode 0644 on a host with umask 027 would otherwise land at
	// 0640 silently.  Explicit Chmod brings the backup back to the
	// source's permission bits regardless.
	if err := os.Chmod(dest, srcInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("chmod backup %s: %w", dest, err)
	}
	return nil
}
