package containers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestMaterialize_CumulativeByteBudgetExceeded — P0-15.2.  Two files,
// each comfortably under the per-file ceiling, but whose sum exceeds a
// (test-lowered) cumulative byte budget.  Materialisation must abort
// with a fatal error mentioning the budget, so the caller tears the
// partial tree down rather than sub-scanning a disk/RAM-ballooning
// extract.
func TestMaterialize_CumulativeByteBudgetExceeded(t *testing.T) {
	layer := t.TempDir()
	// Two 4 KiB files → 8 KiB total.
	for _, name := range []string{"a.bin", "b.bin"} {
		if err := os.WriteFile(filepath.Join(layer, name), make([]byte, 4096), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	tree := &MergedTree{Layers: []string{layer}}
	dest := t.TempDir()

	// Budget of 6 KiB: the first file fits, the second breaches.
	_, err := Materialize(context.Background(), tree, dest, 6*1024)
	if err == nil {
		t.Fatalf("expected fatal error on cumulative byte-budget breach, got nil")
	}
	if !strings.Contains(err.Error(), "budget") {
		t.Errorf("expected a byte-budget error, got: %v", err)
	}
}

// TestMaterialize_ContextCancelledStopsCopy — P0-15.2.  A cancelled
// context aborts the copy loop promptly with ctx.Err(), rather than
// materialising the whole tree.
func TestMaterialize_ContextCancelledStopsCopy(t *testing.T) {
	layer := t.TempDir()
	for i := 0; i < 8; i++ {
		if err := os.WriteFile(filepath.Join(layer, "f"+string(rune('a'+i))+".txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	tree := &MergedTree{Layers: []string{layer}}
	dest := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the first entry

	_, err := Materialize(ctx, tree, dest, 0)
	if err == nil {
		t.Fatalf("expected Materialize to abort on cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// TestMergedTree_CumulativeEntryCapTruncates — P0-15.3.  Proves the
// entry counter is CUMULATIVE across layers (and both per-layer walk
// passes): with two files per layer, no single walkLayer pass reaches a
// cap of 5, yet the second layer pushes the shared counter over it, so
// Walk must report truncated=true.  A per-pass-reset counter (the old
// behaviour) would never truncate this fixture.
func TestMergedTree_CumulativeEntryCapTruncates(t *testing.T) {
	orig := walkLayerMaxEntries
	walkLayerMaxEntries = 5
	defer func() { walkLayerMaxEntries = orig }()

	mk := func(files ...string) string {
		dir := t.TempDir()
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
				t.Fatalf("write %s: %v", f, err)
			}
		}
		return dir
	}
	// Two layers, two files each.  Per layer (either pass) visits 2
	// entries — below the cap of 5 — so truncation can only arise from
	// the cumulative count spanning both layers.
	l0 := mk("a.txt", "b.txt")
	l1 := mk("c.txt", "d.txt")
	tree := &MergedTree{Layers: []string{l0, l1}}

	truncated, err := tree.Walk(context.Background(), func(MergedEntry) error { return nil })
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !truncated {
		t.Fatalf("expected truncated=true from cumulative entry cap, got false")
	}
}

// TestMaterialize_TruncationSurfacedAsScanError — P0-15.3.  When the
// merged-tree walk truncates, Materialize records a non-fatal ScanError
// (so operators see the container view is partial) while still
// returning what it materialised.
func TestMaterialize_TruncationSurfacedAsScanError(t *testing.T) {
	orig := walkLayerMaxEntries
	walkLayerMaxEntries = 1
	defer func() { walkLayerMaxEntries = orig }()

	layer := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(layer, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	tree := &MergedTree{Layers: []string{layer}}
	dest := t.TempDir()

	errs, err := Materialize(context.Background(), tree, dest, 0)
	if err != nil {
		t.Fatalf("Materialize returned fatal error: %v", err)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error, "truncated") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a truncation ScanError, got: %+v", errs)
	}
}

// TestScanOneTarget_MaterialisesUnderDataDir — P0-15.1.  When the
// scanner config carries a DataDir, the per-container temp tree is
// created under <DataDir>/container-scan (never os.TempDir(), which on
// modern distros is tmpfs/RAM).  We drive the real scanOneTarget path
// with an image-only target and assert the container-scan base dir was
// created under the configured data dir.
func TestScanOneTarget_MaterialisesUnderDataDir(t *testing.T) {
	// A one-layer image fixture with a single file.
	layer := t.TempDir()
	if err := os.WriteFile(filepath.Join(layer, "marker.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	target := ContainerTarget{
		Runtime:      RuntimeDocker,
		ImageID:      "sha256:deadbeef",
		MergedRootFS: MergedTree{Layers: []string{layer}},
	}

	dataDir := t.TempDir()
	baseCfg := scanner.Config{
		ScanRoot:   "/", // overridden per-target to the temp tree
		MaxDepth:   2,
		MaxWorkers: 1,
		DataDir:    dataDir,
	}
	result := &scanner.ScanResult{}

	scanOneTarget(context.Background(), target, baseCfg, 30*time.Second, result)

	// The per-target temp dir is removed by scanOneTarget's deferred
	// RemoveAll, but its parent (the container-scan base) persists and
	// must live under the configured DataDir.
	base := filepath.Join(dataDir, "container-scan")
	if info, err := os.Stat(base); err != nil || !info.IsDir() {
		t.Fatalf("expected container-scan base dir under DataDir at %s (err=%v)", base, err)
	}
}
