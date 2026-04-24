package containers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

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
func Materialize(tree *MergedTree, dest string) error {
	if tree == nil || len(tree.Layers) == 0 {
		return nil
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("mkdir dest: %w", err)
	}
	return tree.Walk(func(e MergedEntry) error {
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
		// Try hardlink first — cheap, no bytes moved.
		if err := os.Link(e.Abs, target); err == nil {
			return nil
		}
		// Fall back to copy.  Cross-device links (EXDEV) and
		// filesystems that don't support linking (FAT, SMB without
		// posix) land here.  Permission-denied stays as an error —
		// the caller can surface it as ScanError.
		return copyRegularFile(e.Abs, target)
	})
}

// copyRegularFile writes ``src`` to ``dst`` byte-for-byte, preserving
// the mode bits.  Bounded by safeio's source-side file cap in theory,
// but we don't want to impose scanner-specific caps here — bounded
// already by the merged-tree walker never emitting oversize files
// beyond the per-layer walkLayer limits.
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
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("open dst: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}
