package containers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// buildPodmanFixture lays out a Podman storage root that exercises
// the images.json + layers.json + overlay/<id>/diff chain used by
// the discoverer.  Kept minimal — deliberately avoids the real
// Podman's richer metadata (user-ns map, mounts, health, …) which
// the discoverer ignores.
type podmanFixtureImage struct {
	ID     string   // unprefixed hex; discoverer adds sha256:
	Digest string   // "sha256:abc..." or "" (then fallbackID is used)
	Names  []string // ["docker.io/library/python:3.12", ...]
	Layers []string // layer IDs, bottom-to-top
	// LayerDiffDigests is the per-layer diff-digest, parallel to
	// Layers (bottom-to-top).  A nil slice means "no diff-digest on
	// any layer" (legacy store); an entry left as "" marks a single
	// digest-less layer, used to exercise the all-or-nothing rule.
	LayerDiffDigests []string
}

type podmanFixtureContainer struct {
	ID      string
	Name    string
	ImageID string
	LayerID string // top layer of the container's own stack
}

func buildPodmanFixture(t *testing.T, images []podmanFixtureImage, containers []podmanFixtureContainer) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{
		filepath.Join(root, "overlay-images"),
		filepath.Join(root, "overlay-layers"),
		filepath.Join(root, "overlay"),
		filepath.Join(root, "overlay-containers"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", d, err)
		}
	}

	var imgRecs []podmanImageRecord
	var layerRecs []podmanLayerRecord
	for _, img := range images {
		imgRecs = append(imgRecs, podmanImageRecord{
			ID:     img.ID,
			Digest: img.Digest,
			Names:  img.Names,
			Layer:  img.Layers[len(img.Layers)-1], // top of the image's chain
		})
		// Build the layer chain with parent pointers.
		var parent string
		for i, id := range img.Layers {
			rec := podmanLayerRecord{ID: id, Parent: parent}
			if i < len(img.LayerDiffDigests) {
				rec.DiffDigest = img.LayerDiffDigests[i]
			}
			layerRecs = append(layerRecs, rec)
			parent = id
			// Plant the physical diff dir + a marker file.
			diff := filepath.Join(root, "overlay", id, "diff")
			if err := os.MkdirAll(diff, 0o755); err != nil {
				t.Fatalf("mkdir diff: %v", err)
			}
			if err := os.WriteFile(filepath.Join(diff, "layer-"+id+".txt"), []byte("content"), 0o644); err != nil {
				t.Fatalf("write marker: %v", err)
			}
		}
	}

	// Container layer chain: each container's own top layer builds
	// atop the image's top.  Tests pass LayerID explicitly.
	var ctrRecs []podmanContainerRecord
	for _, c := range containers {
		ctrRecs = append(ctrRecs, podmanContainerRecord{
			ID:      c.ID,
			Names:   []string{c.Name},
			ImageID: c.ImageID,
			LayerID: c.LayerID,
		})
		// Make sure the container's layer exists in layers.json with
		// parent = image's top layer.  Find the image.
		var parentLayerID string
		for _, img := range images {
			if img.ID == c.ImageID {
				parentLayerID = img.Layers[len(img.Layers)-1]
				break
			}
		}
		layerRecs = append(layerRecs, podmanLayerRecord{ID: c.LayerID, Parent: parentLayerID})
		diff := filepath.Join(root, "overlay", c.LayerID, "diff")
		if err := os.MkdirAll(diff, 0o755); err != nil {
			t.Fatalf("mkdir ctr diff: %v", err)
		}
		if err := os.WriteFile(filepath.Join(diff, "ctr-install.txt"), []byte("dropped-in-container"), 0o644); err != nil {
			t.Fatalf("write ctr marker: %v", err)
		}
	}

	if err := writeJSON(filepath.Join(root, "overlay-images", "images.json"), imgRecs); err != nil {
		t.Fatalf("write images.json: %v", err)
	}
	if err := writeJSON(filepath.Join(root, "overlay-layers", "layers.json"), layerRecs); err != nil {
		t.Fatalf("write layers.json: %v", err)
	}
	if len(ctrRecs) > 0 {
		if err := writeJSON(filepath.Join(root, "overlay-containers", "containers.json"), ctrRecs); err != nil {
			t.Fatalf("write containers.json: %v", err)
		}
	}

	return root
}

// TestDiscoverPodman_NoRoot: no storage root = no error, no targets.
func TestDiscoverPodman_NoRoot(t *testing.T) {
	targets, errs := discoverPodman([]string{filepath.Join(t.TempDir(), "absent")})
	if len(targets) != 0 || len(errs) != 0 {
		t.Fatalf("expected (nil, nil), got (%+v, %+v)", targets, errs)
	}
}

// TestDiscoverPodman_SingleImage: one image with 2 layers produces
// a target with bottom-to-top MergedRootFS ordering and the tags
// pulled from overlay-images/images.json.
func TestDiscoverPodman_SingleImage(t *testing.T) {
	img := podmanFixtureImage{
		ID:     "abcdef0123456789",
		Digest: "sha256:abcdef0123456789",
		Names:  []string{"docker.io/library/python:3.12", "python:3.12"},
		Layers: []string{"layer-base", "layer-top"},
	}
	root := buildPodmanFixture(t, []podmanFixtureImage{img}, nil)

	targets, errs := discoverPodman([]string{root})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Runtime != RuntimePodman {
		t.Errorf("Runtime: got %q, want podman", got.Runtime)
	}
	if got.ImageID != "sha256:abcdef0123456789" {
		t.Errorf("ImageID: got %q", got.ImageID)
	}
	if len(got.MergedRootFS.Layers) != 2 {
		t.Fatalf("expected 2 layers, got %d: %v", len(got.MergedRootFS.Layers), got.MergedRootFS.Layers)
	}
	// Bottom-to-top: base first, top last.  Compare separator-agnostically
	// since the product builds paths with filepath.Join (OS separator) while
	// the expected suffixes use forward slashes.
	if !hasSuffix(filepath.ToSlash(got.MergedRootFS.Layers[0]), "layer-base/diff") {
		t.Errorf("layer 0 should be the base; got %q", got.MergedRootFS.Layers[0])
	}
	if !hasSuffix(filepath.ToSlash(got.MergedRootFS.Layers[1]), "layer-top/diff") {
		t.Errorf("layer 1 should be the top; got %q", got.MergedRootFS.Layers[1])
	}
}

// TestDiscoverPodman_ContainerAppendsLayer: a container on top of
// an image emits its own target with an extra layer on top of the
// image's chain.
func TestDiscoverPodman_ContainerAppendsLayer(t *testing.T) {
	img := podmanFixtureImage{
		ID:     "img1",
		Digest: "sha256:img1",
		Names:  []string{"python:3.12"},
		Layers: []string{"base"},
	}
	ctr := podmanFixtureContainer{
		ID:      "ctr1",
		Name:    "happy_curie",
		ImageID: "img1",
		LayerID: "ctr-layer",
	}
	root := buildPodmanFixture(t, []podmanFixtureImage{img}, []podmanFixtureContainer{ctr})

	targets, errs := discoverPodman([]string{root})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	// Expect 1 image target + 1 container target.
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d: %+v", len(targets), targets)
	}
	var ctrTarget *ContainerTarget
	for i := range targets {
		if targets[i].ContainerID != "" {
			ctrTarget = &targets[i]
			break
		}
	}
	if ctrTarget == nil {
		t.Fatalf("no container target emitted: %+v", targets)
	}
	if ctrTarget.ContainerName != "happy_curie" {
		t.Errorf("ContainerName: got %q", ctrTarget.ContainerName)
	}
	// Chain walks up parent pointers: base -> ctr-layer → 2 layers.
	if len(ctrTarget.MergedRootFS.Layers) != 2 {
		t.Errorf("expected 2 layers in ctr target; got %d: %v",
			len(ctrTarget.MergedRootFS.Layers), ctrTarget.MergedRootFS.Layers)
	}
}

// TestDiscoverPodman_ImageCarriesLayerDigests: an image whose layer
// records all carry a diff-digest yields a bottom-to-top digest chain
// on the image target (order preserved, never sorted).
func TestDiscoverPodman_ImageCarriesLayerDigests(t *testing.T) {
	img := podmanFixtureImage{
		ID:     "digest-img",
		Digest: "sha256:digestimg",
		Names:  []string{"python:3.12"},
		Layers: []string{"dl-base", "dl-top"},
		LayerDiffDigests: []string{
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	root := buildPodmanFixture(t, []podmanFixtureImage{img}, nil)

	targets, errs := discoverPodman([]string{root})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0].LayerDigests
	if len(got) != len(img.LayerDiffDigests) {
		t.Fatalf("LayerDigests len: got %d, want %d: %v", len(got), len(img.LayerDiffDigests), got)
	}
	for i := range img.LayerDiffDigests {
		if got[i] != img.LayerDiffDigests[i] {
			t.Errorf("LayerDigests[%d]: got %q, want %q (bottom-to-top order must be preserved)",
				i, got[i], img.LayerDiffDigests[i])
		}
	}
}

// TestDiscoverPodman_AllOrNothingMissingDigest: if any layer in the
// chain lacks a diff-digest, the whole LayerDigests list is empty —
// a partial/misaligned chain is worse than none.
func TestDiscoverPodman_AllOrNothingMissingDigest(t *testing.T) {
	img := podmanFixtureImage{
		ID:     "partial-img",
		Digest: "sha256:partialimg",
		Names:  []string{"python:3.12"},
		Layers: []string{"pl-base", "pl-mid", "pl-top"},
		LayerDiffDigests: []string{
			"sha256:ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"", // digest-less middle layer → all-or-nothing kicks in
			"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		},
	}
	root := buildPodmanFixture(t, []podmanFixtureImage{img}, nil)

	targets, errs := discoverPodman([]string{root})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	if len(targets[0].LayerDigests) != 0 {
		t.Errorf("expected empty LayerDigests (all-or-nothing), got %v", targets[0].LayerDigests)
	}
}

// TestDiscoverPodman_ContainerInheritsImageDigests: the container
// target inherits the IMAGE's digest chain, not the container's own
// writable layer (which has no diff-digest).
func TestDiscoverPodman_ContainerInheritsImageDigests(t *testing.T) {
	img := podmanFixtureImage{
		ID:     "ci-img",
		Digest: "sha256:ciimg",
		Names:  []string{"python:3.12"},
		Layers: []string{"ci-base"},
		LayerDiffDigests: []string{
			"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}
	ctr := podmanFixtureContainer{
		ID:      "ci-ctr",
		Name:    "happy_curie",
		ImageID: "ci-img",
		LayerID: "ci-ctr-layer", // RW layer, no diff-digest
	}
	root := buildPodmanFixture(t, []podmanFixtureImage{img}, []podmanFixtureContainer{ctr})

	targets, errs := discoverPodman([]string{root})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	var ctrTarget *ContainerTarget
	for i := range targets {
		if targets[i].ContainerID != "" {
			ctrTarget = &targets[i]
			break
		}
	}
	if ctrTarget == nil {
		t.Fatalf("no container target emitted: %+v", targets)
	}
	if len(ctrTarget.LayerDigests) != 1 || ctrTarget.LayerDigests[0] != img.LayerDiffDigests[0] {
		t.Errorf("container LayerDigests: got %v, want %v (image chain, not RW layer)",
			ctrTarget.LayerDigests, img.LayerDiffDigests)
	}
}

// TestDiscoverPodman_RootsDedupe: two storage roots pointing at the
// same underlying state (common when operators symlink rootless
// storage into the system path) should NOT emit duplicate
// (Runtime, ImageID, ContainerID) tuples.
func TestDiscoverPodman_RootsDedupe(t *testing.T) {
	// Build one root, pass it twice.  dedupeTargets in scanner.go
	// is what normally handles this; the discoverer itself may emit
	// duplicates.  We assert at the Scanner level instead.
	img := podmanFixtureImage{
		ID:     "dup1",
		Digest: "sha256:dup1",
		Layers: []string{"only"},
	}
	root := buildPodmanFixture(t, []podmanFixtureImage{img}, nil)

	s := &Scanner{cfg: Config{PodmanRoots: []string{root, root}}}
	targets, _ := s.DiscoverTargets(context.Background())
	if len(targets) != 1 {
		t.Errorf("expected dedupe to collapse 2 identical emissions; got %d: %+v", len(targets), targets)
	}
}

// hasSuffix mirrors strings.HasSuffix — avoids an import for one use.
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
