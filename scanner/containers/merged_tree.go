package containers

import (
	"context"
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
// `/var/lib/docker/overlay2/<layer-id>/diff`.
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
	// forward slashes regardless of OS.  Never starts with `/`.
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
// Walk returns truncated=true when the cumulative entry budget
// (walkLayerMaxEntries, shared across every layer and both walk passes
// of the image) was exhausted before every layer was fully scanned.
// The emitted set is still coherent — it is simply a prefix of the
// full merged view — so callers materialise what they got and record a
// non-fatal ScanError rather than aborting.
//
// ctx bounds the whole walk, not just the caller's fn.  The
// layer-collection passes that precede and feed emission poll ctx.Err()
// (see walkCtxCheckInterval) so a pathological image — millions of
// entries before the entry cap trips, or slow layer directories — is
// cut off by the per-container deadline instead of running unbounded.
// A cancelled/expired context aborts the walk and Walk returns
// ctx.Err(); this is distinct from truncation (truncated stays false,
// because the merged view is incomplete for a reason the caller must
// treat as fatal, not as a partial-but-coherent prefix).
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
func (m *MergedTree) Walk(ctx context.Context, fn func(MergedEntry) error) (truncated bool, err error) {
	if len(m.Layers) == 0 {
		return false, nil
	}
	// Fail fast on an already-cancelled context so we don't touch the
	// filesystem at all; mid-flight cancellation is caught by the
	// per-batch poll inside walkLayer.
	if cerr := ctx.Err(); cerr != nil {
		return false, cerr
	}

	seen := map[string]MergedEntry{}
	hidden := map[string]struct{}{}
	opaque := map[string]struct{}{}

	// entries is the cumulative walk counter, shared across every layer
	// AND both per-layer passes (whiteout collection + content), so a
	// fan-out spread thinly across many layers is bounded the same as
	// one giant layer.  walkLayer increments it via the pointer and
	// signals when the budget is hit.
	entries := 0

	for i := len(m.Layers) - 1; i >= 0; i-- {
		root := m.Layers[i]
		// Pass 1 — collect this layer's whiteouts.  Layer N's
		// whiteouts hide paths in layers 0..N-1 only, so we stage
		// them in per-layer maps and merge into `hidden` / `opaque`
		// after this layer's own content has been emitted.
		layerHidden := map[string]struct{}{}
		layerOpaque := map[string]struct{}{}

		trunc, err := walkLayer(ctx, root, &entries, func(relPath string, d fs.DirEntry) error {
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
				// contents it opacifies — `foo/.wh..wh..opq` → foo.
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
			return truncated, err
		}
		if trunc {
			truncated = true
		}

		// Pass 2 — walk non-whiteout entries and claim paths not
		// already won by a higher layer, not hidden, and not under
		// an opaque dir from a higher layer.
		trunc, err = walkLayer(ctx, root, &entries, func(relPath string, d fs.DirEntry) error {
			base := filepath.Base(relPath)
			// Skip whiteout markers themselves — they're metadata,
			// not content.  Every kind (plain / opaque / hardlink /
			// unknown-meta) is filtered here.
			if kind, _ := ParseWhiteoutMarker(base); kind != NotWhiteout {
				return nil
			}
			// Skip symlinks.  A symlink inside a layer may point
			// outside the layer root (e.g. to `/etc/shadow` on the
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
			return truncated, err
		}
		if trunc {
			truncated = true
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
	for i, p := range paths {
		// Poll ctx during emission too: the collected set can be up to
		// walkLayerMaxEntries wide, and fn (e.g. Materialize's copy loop)
		// may itself be slow, so the per-container deadline must bound
		// this phase as well.  Cheap modulo keeps ctx.Err() off the hot
		// path.
		if i%walkCtxCheckInterval == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return truncated, cerr
			}
		}
		if err := fn(seen[p]); err != nil {
			return truncated, err
		}
	}
	return truncated, nil
}

// Layer-walk bounds.  A container rootfs is legitimately deep
// (system Python at `usr/lib/python3.12/site-packages/<pkg>/...`
// already sits ~6 levels in, and nested vendored deps go deeper),
// so the depth cap is generous-but-finite rather than the 4-level
// cap the host-side scanners use.  A hostile image that nests
// directories thousands deep — or fans out millions of entries in
// one layer — would otherwise drive `filepath.WalkDir` into
// CPU/memory exhaustion (walkLayer runs twice per layer per image).
// walkLayerMaxDepth caps how far below the layer root we descend,
// measured as path components below root (root's direct children are
// depth 1).  64 clears any realistic rootfs nesting while neutralising
// an adversarial deep chain.
const walkLayerMaxDepth = 64

// walkLayerMaxEntries bounds the CUMULATIVE number of entries the walk
// visits across every layer of an image (and both per-layer passes),
// not per walkLayer call — an earlier per-call cap let a fan-out spread
// thinly over many layers evade the bound entirely.  A real image is
// well under this; 1_000_000 neutralises the pathological
// millions-of-tiny-files case while still clearing any legitimate
// rootfs.  On breach the walk stops short and Walk reports
// truncated=true so the caller records a ScanError instead of silently
// under-scanning.  A var (not const) only so tests can lower it to
// exercise truncation without materialising a million files.
var walkLayerMaxEntries = 1_000_000

// walkCtxCheckInterval bounds how often a layer walk (and the emission
// loop) polls ctx.Err().  The per-container deadline must bound the
// layer-collection passes that precede and feed Materialize's copy
// loop — not just the copy loop — or a pathological image (millions of
// entries before the cap trips, slow layer directories) walks unbounded.
// Polling every entry would drop ctx.Err()'s mutex acquisition onto the
// hot path; every 1024 callbacks keeps cancellation prompt (roughly a
// directory batch, not a whole image) while staying cheap.  A var (not
// const) only so tests can lower it to force a mid-flight check without
// materialising thousands of files.
var walkCtxCheckInterval = 1024

// walkLayer iterates a single layer's filesystem tree and invokes fn
// for each entry with its path relative to the layer root.  Uses
// os.Lstat semantics so symlinks are reported as symlinks, not
// followed.  Errors on individual entries are surfaced (the caller
// can translate into ScanError if needed); a completely unreadable
// root is a hard failure.
//
// The walk is bounded on two axes (walkLayerMaxDepth /
// walkLayerMaxEntries): directories at or below the depth cap have
// their children skipped (fs.SkipDir), and the pass stops descending
// once the entry budget is exhausted.  Both bounds protect against a
// hostile image; neither trims a realistic rootfs.
//
// entries points at the CUMULATIVE entry counter the caller shares
// across every layer and both passes of the image, so the bound holds
// against a fan-out spread thinly across many layers.  walkLayer
// returns truncated=true when it stopped short on the entry budget.
//
// ctx bounds the walk itself: every walkCtxCheckInterval callbacks the
// walk polls ctx.Err() and, on cancellation/expiry, stops and returns
// that error (distinct from the truncated=true entry-cap path).  This
// makes the per-container deadline cover the collection walks that feed
// Materialize, not only Materialize's own copy loop.
func walkLayer(ctx context.Context, root string, entries *int, fn func(relPath string, d fs.DirEntry) error) (truncated bool, err error) {
	calls := 0
	werr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Context poll — cheap modulo on a per-walk callback counter so
		// the check fires regularly regardless of how the entry counter
		// advances.  Returning ctx.Err() aborts WalkDir promptly.
		calls++
		if calls%walkCtxCheckInterval == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
		}
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
			// The root itself is the merged view's `/` — we never
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
		// off `/`-paths (`META-INF/MANIFEST.MF` etc.) so any
		// platform divergence would silently miss entries.
		rel = filepath.ToSlash(rel)

		// Total-entry bound.  Once the cumulative budget is spent, stop
		// the walk outright: the terminating fs.SkipAll halts WalkDir
		// cleanly and we flag truncation so the caller can surface it.
		if *entries >= walkLayerMaxEntries {
			truncated = true
			return fs.SkipAll
		}

		// Depth bound.  `depth` is the number of path components
		// below root (a direct child is depth 1).  When a directory
		// is at the cap, skip its contents — emit the directory entry
		// itself (so the merged view still records the dir) but don't
		// descend into it.
		depth := strings.Count(rel, "/") + 1
		if depth >= walkLayerMaxDepth && d.IsDir() {
			*entries++
			if ferr := fn(rel, d); ferr != nil {
				return ferr
			}
			return fs.SkipDir
		}

		*entries++
		return fn(rel, d)
	})
	return truncated, werr
}

// joinRel joins a relative directory with a basename, handling the
// root-level `.` case so we don't produce `./foo` entries.
// Normalises to forward slashes.
func joinRel(dir, base string) string {
	if dir == "." || dir == "" {
		return base
	}
	return filepath.ToSlash(filepath.Join(dir, base))
}

// underAnyOpaque reports whether `rel` is inside any of the
// opaque-marked directories.  An empty-string key means "root is
// opaque" (every lower-layer path is dropped).  A concrete key
// `foo/bar` drops `foo/bar` itself and every descendant, but
// leaves siblings alone.
//
// Rather than scan every opaque dir per entry — O(#opaque-dirs), which
// goes quadratic on a whiteout-heavy hostile image (10k opaque dirs ×
// 1M entries) — we decompose `rel` into itself plus its ancestor
// directories and probe the opaque map for each.  That is O(depth-of-rel),
// bounded by walkLayerMaxDepth (≤64) and independent of #opaque-dirs.
// The map is already the lookup structure (a full-path trie); walking
// `rel`'s ancestors is the trie query.
//
// Path-boundary correctness: we only ever split on '/', so `rel` is
// under `dir` iff `dir == rel` or `dir` is a slash-delimited ancestor
// of `rel`.  A sibling-prefix such as "a/bc" decomposes to {"a/bc", "a"}
// and therefore never matches an opaque "a/b".
func underAnyOpaque(rel string, opaque map[string]struct{}) bool {
	if len(opaque) == 0 {
		return false
	}
	if _, rootOpaque := opaque[""]; rootOpaque {
		return true
	}
	// `rel` itself may be an opaque dir.
	if _, ok := opaque[rel]; ok {
		return true
	}
	// Each '/' in `rel` marks an ancestor directory (`rel[:i]`); probe
	// each.  Scanning from the front lets us stop at the first match.
	for i := 1; i < len(rel); i++ {
		if rel[i] != '/' {
			continue
		}
		if _, ok := opaque[rel[:i]]; ok {
			return true
		}
	}
	return false
}
