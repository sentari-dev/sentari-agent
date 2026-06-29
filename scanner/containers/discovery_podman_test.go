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
		for _, id := range img.Layers {
			layerRecs = append(layerRecs, podmanLayerRecord{ID: id, Parent: parent})
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
	// Bottom-to-top: base first, top last.
	if !hasSuffix(got.MergedRootFS.Layers[0], "layer-base/diff") {
		t.Errorf("layer 0 should be the base; got %q", got.MergedRootFS.Layers[0])
	}
	if !hasSuffix(got.MergedRootFS.Layers[1], "layer-top/diff") {
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
