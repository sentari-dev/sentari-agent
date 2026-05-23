package containers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// copyRegularFileMaxBytes is the per-file ceiling for materialising a
// layer file into the temp tree.  A hostile (or merely huge) layer
// file — a multi-GB blob, a sparse-file balloon — would otherwise be
// byte-copied whole on the cross-fs/EXDEV fallback path and exhaust
// the host's disk.  512 MiB comfortably covers the largest artefacts
// any scanner plugin reads (vendored wheels, fat JARs) while bounding
// the worst case; files above it are skipped and recorded as a
// non-fatal ScanError rather than copied.
const copyRegularFileMaxBytes int64 = 512 << 20 // 512 MiB

// Materialize walks the given MergedTree and reconstructs it inside
// ``dest`` as a single coherent directory tree that the normal
// scanner walker can consume.  Directories are created mkdir-p style;
// regular files are attached via hardlinks where possible (so the
// materialisation doesn't duplicate bytes on disk) and fall back to
// byte-copy when the source and destination live on different
// filesystems or hardlinking is unsupported.
//
// Why materialise instead of teaching the walker about MergedTree:
// the scanner's walker is filesystem-native and every Scanner
// plugin already knows how to find its markers through os.ReadDir.
// Rewriting every plugin to consume a virtual-tree iterator would
// touch ~15 files and have its own test matrix; materialising the
// merged view is a ~100-line helper that reuses all existing code.
// Trade-off: opening N hardlinks per merged path costs O(N) inode
// updates.  On Linux that's fast; the container-scanner is opt-in
// and capped at 100 targets per cycle, so the budget holds.
//
// Invariant: Materialize never follows a symlink.  The Phase-A
// walker drops them, so ``dest`` contains only regular files and
// directories.  safeio's leaf-symlink refusal still applies when
// plugins read from ``dest``.
// Materialize returns the list of non-fatal ScanErrors it accumulated
// (oversize files skipped, individual copy failures) plus a single
// fatal error for an unrecoverable condition (dest unmakeable, Walk
// abort).  Oversize files are skipped — never attached to ``dest`` —
// so a multi-GB layer file can't exhaust the host's disk; each skip
// is recorded as a ScanError so operators see why a path is absent.
func Materialize(tree *MergedTree, dest string) ([]scanner.ScanError, error) {
	if tree == nil || len(tree.Layers) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir dest: %w", err)
	}
	var errs []scanner.ScanError
	walkErr := tree.Walk(func(e MergedEntry) error {
		target := filepath.Join(dest, filepath.FromSlash(e.Path))
		if e.IsDir {
			return os.MkdirAll(target, 0o755)
		}
		// Regular file.  Ensure the parent dir exists — the Walk
		// emits dirs too, but it's cheaper to MkdirAll unconditionally
		// than to order-check for every file.
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir parent of %s: %w", target, err)
		}
		// Per-file size ceiling, enforced BEFORE link/copy so the
		// outcome is deterministic regardless of hardlink support: a
		// file above the ceiling is skipped and recorded, never
		// attached to ``dest``.  Lstat (not Stat) so a symlink that
		// the walker should already have dropped can't redirect the
		// size check at a small decoy — though the walker never emits
		// symlinks, this keeps the guard self-contained.
		info, err := os.Lstat(e.Abs)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      e.Abs,
				EnvType:   "container",
				Error:     fmt.Sprintf("materialise: stat layer file: %v", err),
				Timestamp: time.Now().UTC(),
			})
			return nil
		}
		if info.Size() > copyRegularFileMaxBytes {
			errs = append(errs, scanner.ScanError{
				Path:      e.Abs,
				EnvType:   "container",
				Error:     fmt.Sprintf("materialise: layer file exceeds size ceiling (%d > %d bytes); skipped", info.Size(), copyRegularFileMaxBytes),
				Timestamp: time.Now().UTC(),
			})
			return nil
		}
		// Try hardlink first — cheap, no bytes moved.
		if err := os.Link(e.Abs, target); err == nil {
			return nil
		}
		// Fall back to copy.  Cross-device links (EXDEV) and
		// filesystems that don't support linking (FAT, SMB without
		// posix) land here.  A per-file failure (including the copy's
		// own oversize guard) is non-fatal — recorded and skipped so
		// one bad file doesn't abort the whole materialisation.
		if err := copyRegularFile(e.Abs, target); err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      e.Abs,
				EnvType:   "container",
				Error:     fmt.Sprintf("materialise: copy layer file: %v", err),
				Timestamp: time.Now().UTC(),
			})
			// Remove any partial output the copy may have left behind.
			_ = os.Remove(target)
		}
		return nil
	})
	return errs, walkErr
}

// copyRegularFile writes ``src`` to ``dst`` byte-for-byte, preserving
// the mode bits, refusing any source above copyRegularFileMaxBytes.
// Materialize enforces the same ceiling before calling here; this is
// defence-in-depth so a direct caller (or a file that grows between
// Materialize's stat and this open) still can't balloon ``dst`` to an
// arbitrary size.  The io.Copy is itself bounded with a LimitReader
// (+1) so a post-stat growth is detected rather than streamed whole.
func copyRegularFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat src: %w", err)
	}
	if info.Size() > copyRegularFileMaxBytes {
		return fmt.Errorf("src exceeds size ceiling (%d > %d bytes)", info.Size(), copyRegularFileMaxBytes)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("open dst: %w", err)
	}
	defer out.Close()
	// LimitReader to ceiling+1: if the file grew past the ceiling
	// after the stat above, we copy ceiling+1 bytes, detect the
	// overflow, and fail rather than stream an unbounded file.
	n, err := io.Copy(out, io.LimitReader(in, copyRegularFileMaxBytes+1))
	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	if n > copyRegularFileMaxBytes {
		return fmt.Errorf("src grew past size ceiling (%d bytes) during copy", copyRegularFileMaxBytes)
	}
	return nil
}
