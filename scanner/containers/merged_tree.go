package containers

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MergedTree represents the stacked-layer view a process inside a
// container would see.  Layers are listed bottom-to-top: index 0 is
// the image's base layer (oldest), the final index is the top (for
// image-only targets: the last image layer; for a running container:
// the container's upper-dir overlay).
//
// Each layer path is the absolute host-filesystem path to that
// layer's rootfs — e.g. for Docker's overlay2 driver,
// ``/var/lib/docker/overlay2/<layer-id>/diff``.
//
// MergedTree is stateless: Walk() derives the merged view on demand
// so a caller can snapshot layer paths once and re-walk if needed
// (e.g. after a whiteout-set change in a live container).
type MergedTree struct {
	Layers []string
}

// MergedEntry is a single path in the merged view, with the winning
// layer identified so callers can correlate back to "which image
// layer introduced this file?"
type MergedEntry struct {
	// Path is the entry's path relative to the merged root, using
	// forward slashes regardless of OS.  Never starts with ``/``.
	Path string
	// Abs is the absolute host-filesystem path where the winning
	// content lives.  Plugins read from this via safeio.
	Abs string
	// IsDir is true for directory entries.
	IsDir bool
	// LayerIdx is the index into MergedTree.Layers that won for this
	// path.  Useful for "which layer introduced the CVE-bearing
	// package?" queries.
	LayerIdx int
}

// Walk iterates the merged view in lexicographic path order and
// invokes fn for each entry.  Whiteout markers are applied (hidden
// paths never reach fn) but never emitted themselves.  Symbolic
// links are skipped entirely — we never emit them and never follow
// them — which neutralises the common "symlink planted in layer N
// points at /etc/shadow on the host" escape without needing
// openat2 RESOLVE_BENEATH.  Layer content is still subject to the
// scanner's existing safeio policy when plugins later read it.
//
// Returning a non-nil error from fn stops iteration and returns
// that error.  Use fs.SkipDir (not supported yet — returns from
// Walk) is reserved for a follow-up; for Phase A the callback
// simply returns nil on uninteresting entries.
//
// Order of operations:
//  1. Walk layers top-to-bottom collecting the effective set of
//     entries: top-layer wins on collisions; whiteouts in layer N
//     hide paths from layers 0..N-1 (plain whiteouts hide a single
//     path; opaque-dir markers hide the entire subtree).
//  2. Sort the collected entries by path for deterministic output.
//  3. Invoke fn on each.
//
// The walk is purely filesystem-based and makes no assumption about
// overlayfs being mounted — this lets the agent run without
// CAP_SYS_ADMIN and on macOS/Windows hosts too.
func (m *MergedTree) Walk(fn func(MergedEntry) error) error {
	if len(m.Layers) == 0 {
		return nil
	}

	seen := map[string]MergedEntry{}
	hidden := map[string]struct{}{}
	opaque := map[string]struct{}{}

	for i := len(m.Layers) - 1; i >= 0; i-- {
		root := m.Layers[i]
		// Pass 1 — collect this layer's whiteouts.  Layer N's
		// whiteouts hide paths in layers 0..N-1 only, so we stage
		// them in per-layer maps and merge into ``hidden`` / ``opaque``
		// after this layer's own content has been emitted.
		layerHidden := map[string]struct{}{}
		layerOpaque := map[string]struct{}{}

		err := walkLayer(root, func(relPath string, d fs.DirEntry) error {
			if !d.Type().IsRegular() && !d.IsDir() {
				return nil
			}
			kind, target := ParseWhiteoutMarker(filepath.Base(relPath))
			switch kind {
			case PlainWhiteout:
				if target == "" {
					return nil
				}
				hiddenPath := joinRel(filepath.Dir(relPath), target)
				layerHidden[hiddenPath] = struct{}{}
			case OpaqueDirWhiteout:
				// The opaque marker lives inside the directory whose
				// contents it opacifies — ``foo/.wh..wh..opq`` → foo.
				dir := filepath.Dir(relPath)
				if dir == "." || dir == "" {
					// Root-level opaque marker: drop everything from
					// lower layers.  Represent as empty-string key.
					layerOpaque[""] = struct{}{}
				} else {
					layerOpaque[dir] = struct{}{}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Pass 2 — walk non-whiteout entries and claim paths not
		// already won by a higher layer, not hidden, and not under
		// an opaque dir from a higher layer.
		err = walkLayer(root, func(relPath string, d fs.DirEntry) error {
			base := filepath.Base(relPath)
			// Skip whiteout markers themselves — they're metadata,
			// not content.  Every kind (plain / opaque / hardlink /
			// unknown-meta) is filtered here.
			if kind, _ := ParseWhiteoutMarker(base); kind != NotWhiteout {
				return nil
			}
			// Skip symlinks.  A symlink inside a layer may point
			// outside the layer root (e.g. to ``/etc/shadow`` on the
			// host); following it would exfiltrate host content into
			// a container-tagged scan record.  We treat symlinks as
			// non-content; a lower layer's regular file at the same
			// path, if any, can still surface.
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if _, taken := seen[relPath]; taken {
				return nil
			}
			if _, blocked := hidden[relPath]; blocked {
				return nil
			}
			if underAnyOpaque(relPath, opaque) {
				return nil
			}
			seen[relPath] = MergedEntry{
				Path:     relPath,
				Abs:      filepath.Join(root, relPath),
				IsDir:    d.IsDir(),
				LayerIdx: i,
			}
			return nil
		})
		if err != nil {
			return err
		}

		// Merge this layer's whiteouts into the carry-over sets
		// that get applied against layers 0..i-1 in the next
		// iteration.
		for p := range layerHidden {
			hidden[p] = struct{}{}
		}
		for p := range layerOpaque {
			opaque[p] = struct{}{}
		}
	}

	// Deterministic emission order simplifies tests and gives
	// plugins a stable walk ordering across runs.
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := fn(seen[p]); err != nil {
			return err
		}
	}
	return nil
}

// walkLayer iterates a single layer's filesystem tree and invokes fn
// for each entry with its path relative to the layer root.  Uses
// os.Lstat semantics so symlinks are reported as symlinks, not
// followed.  Errors on individual entries are surfaced (the caller
// can translate into ScanError if needed); a completely unreadable
// root is a hard failure.
func walkLayer(root string, fn func(relPath string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A permission-denied on a subdirectory must not kill the
			// whole layer walk; skip the subtree and continue.  At
			// the root itself, propagate up.
			if path == root {
				return err
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path == root {
			// The root itself is the merged view's ``/`` — we never
			// emit it (nothing to scan at the empty path) but we do
			// descend into it.
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Normalise separators so the merged view uses forward
		// slashes even on Windows.  The downstream plugins key
		// off ``/``-paths (``META-INF/MANIFEST.MF`` etc.) so any
		// platform divergence would silently miss entries.
		rel = filepath.ToSlash(rel)
		return fn(rel, d)
	})
}

// joinRel joins a relative directory with a basename, handling the
// root-level ``.`` case so we don't produce ``./foo`` entries.
// Normalises to forward slashes.
func joinRel(dir, base string) string {
	if dir == "." || dir == "" {
		return base
	}
	return filepath.ToSlash(filepath.Join(dir, base))
}

// underAnyOpaque reports whether ``rel`` is inside any of the
// opaque-marked directories.  An empty-string key means "root is
// opaque" (every lower-layer path is dropped).  A concrete key
// ``foo/bar`` drops ``foo/bar`` itself and every descendant, but
// leaves siblings alone.
func underAnyOpaque(rel string, opaque map[string]struct{}) bool {
	if _, rootOpaque := opaque[""]; rootOpaque {
		return true
	}
	for dir := range opaque {
		if rel == dir {
			return true
		}
		if strings.HasPrefix(rel, dir+"/") {
			return true
		}
	}
	return false
}
