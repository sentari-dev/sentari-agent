// Package containers implements container-image discovery and the
// virtual overlay-walker that stitches layer rootfs into a single
// merged tree for scanner plugins to consume.  See
// docs/superpowers/plans/2026-04-23-container-image-scanner.md for
// the full design.
//
// This file is the OCI-whiteout parser: when an image layer wants to
// "remove" a path from a lower layer without actually touching that
// lower layer, it places a marker file alongside — we translate those
// markers back into "skip these paths during merged walk."
package containers

import (
	"strings"
)

// WhiteoutKind enumerates the marker conventions OCI / aufs agreed on
// to encode deletions across a stack of read-only layers.  The merged-
// tree walker (merged_tree.go) consults this to decide, for a given
// layer entry, whether to (a) drop an earlier layer's same-named path,
// or (b) drop an earlier layer's entire subtree.
type WhiteoutKind int

const (
	// NotWhiteout — a regular file/dir; no whiteout semantics.
	NotWhiteout WhiteoutKind = iota

	// PlainWhiteout — ``.wh.<name>`` hides ``<name>`` (file or dir) in
	// the same directory from every lower layer.  The whiteout file
	// itself is NOT emitted in the merged view — it's a marker, not
	// content.
	PlainWhiteout

	// OpaqueDirWhiteout — ``.wh..wh..opq`` placed inside directory
	// ``d`` means "everything lower layers put under ``d`` is gone."
	// Any entries the current (or newer) layers place under ``d``
	// survive; lower-layer entries do not.
	OpaqueDirWhiteout

	// HardlinkWhiteout — ``.wh..wh..plnk.<hash>``.  Signals a hardlink
	// was removed.  Rare in the wild; we recognise it so we can skip
	// the marker cleanly rather than treat it as content.  We do NOT
	// attempt to rehydrate the link's lower-layer target set — that
	// would require reading every lower layer's inode table.  For
	// scanning purposes dropping the marker is sufficient; a stray
	// hardlink target remaining visible is a benign over-report.
	HardlinkWhiteout
)

// Whiteout marker prefixes / names, lifted from the OCI Image Spec
// (image-spec/layer.md § Whiteouts) and aufs / overlayfs kernel docs.
const (
	whiteoutPrefix    = ".wh."
	whiteoutMetaPrefix = ".wh..wh." // both opaque + hardlink start here
	whiteoutOpaqueBase = ".wh..wh..opq"
	whiteoutHardlinkPrefix = ".wh..wh..plnk."
)

// ParseWhiteoutMarker inspects the basename of a layer entry and
// returns its whiteout role, plus the target base name (for plain
// whiteouts) or "" otherwise.
//
// Invariants:
//   - Called with a basename ONLY, never a full path.  Callers do
//     ``filepath.Base(entry)`` first.
//   - Order matters: opaque + hardlink share the ``.wh..wh.`` prefix
//     that would also match the plain-whiteout check, so the meta-
//     markers are tested first.
func ParseWhiteoutMarker(name string) (kind WhiteoutKind, target string) {
	// Opaque-dir marker — exact match.
	if name == whiteoutOpaqueBase {
		return OpaqueDirWhiteout, ""
	}
	// Hardlink whiteout — ``.wh..wh..plnk.<hash>``.  The hash is
	// opaque to us; we surface the marker kind and let the walker
	// drop it.
	if strings.HasPrefix(name, whiteoutHardlinkPrefix) {
		return HardlinkWhiteout, ""
	}
	// Any remaining ``.wh..wh.`` entry is an unknown meta-marker —
	// treat as non-content so we don't mis-emit it, but don't claim
	// plain-whiteout semantics (target would be bogus).
	if strings.HasPrefix(name, whiteoutMetaPrefix) {
		return HardlinkWhiteout, ""
	}
	// Plain whiteout — ``.wh.<target>`` hides ``<target>``.
	if strings.HasPrefix(name, whiteoutPrefix) {
		return PlainWhiteout, name[len(whiteoutPrefix):]
	}
	return NotWhiteout, ""
}
