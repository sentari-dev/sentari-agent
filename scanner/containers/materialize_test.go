package containers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMaterialize_OversizeFileSkipped — Fix #2.  The cross-fs copy
// fallback (copyRegularFile) byte-copies layer files into a temp
// tree.  Without a per-file ceiling a multi-GB layer file exhausts
// the host's disk.  We force the copy path (the source lives on a
// different temp tree than the dest, but on the same fs hardlink
// usually succeeds — so we drive copyRegularFile directly) and assert
// a file above the ceiling is skipped, recorded as a ScanError, and
// NOT written whole to the destination.
func TestMaterialize_OversizeFileSkipped(t *testing.T) {
	// A file one byte over the per-file ceiling.
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "huge.bin")
	big := make([]byte, copyRegularFileMaxBytes+1)
	if err := os.WriteFile(src, big, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "huge.bin")

	err := copyRegularFile(src, dst)
	if err == nil {
		t.Fatalf("expected copyRegularFile to refuse oversize file, got nil error")
	}
	// The destination must not contain the whole (or any partial)
	// payload — we refuse before/at the ceiling, never leaving a
	// giant file on disk.
	if info, statErr := os.Stat(dst); statErr == nil {
		if info.Size() > copyRegularFileMaxBytes {
			t.Errorf("destination holds %d bytes, exceeding ceiling %d", info.Size(), copyRegularFileMaxBytes)
		}
	}
}

// TestMaterialize_OversizeFileRecordedAsScanError — Fix #2, end-to-end
// through Materialize.  A layer carrying an oversize regular file must
// surface a ScanError (non-fatal) and still materialise the rest of
// the tree.  This pins the Materialize signature change (it now
// returns the skipped-file ScanErrors).
func TestMaterialize_OversizeFileRecordedAsScanError(t *testing.T) {
	layer := t.TempDir()
	// One normal file + one oversize file in the same layer.
	if err := os.WriteFile(filepath.Join(layer, "ok.txt"), []byte("fine"), 0o644); err != nil {
		t.Fatalf("write ok: %v", err)
	}
	big := make([]byte, copyRegularFileMaxBytes+1)
	if err := os.WriteFile(filepath.Join(layer, "huge.bin"), big, 0o644); err != nil {
		t.Fatalf("write huge: %v", err)
	}

	tree := &MergedTree{Layers: []string{layer}}
	dest := t.TempDir()

	// The oversize ceiling is enforced in Materialize BEFORE the
	// hardlink/copy step, so the result is deterministic regardless of
	// whether the host filesystem supports hardlinks: the oversize
	// file is always skipped and recorded, never attached to dest.
	errs, err := Materialize(tree, dest)
	if err != nil {
		t.Fatalf("Materialize returned fatal error: %v", err)
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Error, "exceeds") || strings.Contains(e.Error, "cap") || strings.Contains(e.Error, "ceiling") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an oversize/cap ScanError for huge.bin, got: %+v", errs)
	}

	// The oversize file must NOT be present in the materialised tree.
	if _, statErr := os.Stat(filepath.Join(dest, "huge.bin")); statErr == nil {
		t.Errorf("oversize huge.bin should have been skipped, but exists in dest")
	}

	// The normal file must always be present.
	if _, statErr := os.Stat(filepath.Join(dest, "ok.txt")); statErr != nil {
		t.Errorf("normal file ok.txt missing from materialised tree: %v", statErr)
	}
}
