package containers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Podman's on-disk format (shared with CRI-O) is documented at
// github.com/containers/storage. Layout under a storage root:
//
//   overlay-images/images.json       JSON array of image records
//   overlay-images/<id>/             per-image dir (config, manifest)
//   overlay-layers/layers.json       JSON array of layer records (parent chain)
//   overlay/<layer-id>/diff/         layer rootfs
//   overlay-containers/containers.json  container list (running + stopped)
//
// Both system-level (root-run) and rootless ($HOME/.local/share)
// stores follow the same layout, which is why one discoverer covers
// both via configurable roots.

// podmanImageRecord — subset of the JSON under overlay-images/
// images.json we consume.  Undocumented fields are ignored.
type podmanImageRecord struct {
	ID     string   `json:"id"`
	Names  []string `json:"names"`  // ["docker.io/library/python:3.12", ...]
	Layer  string   `json:"layer"`  // top layer ID (lookup key into layers.json)
	Digest string   `json:"digest"` // "sha256:..."
}

// podmanLayerRecord — subset of overlay-layers/layers.json.
type podmanLayerRecord struct {
	ID     string `json:"id"`
	Parent string `json:"parent"` // empty for the base layer
}

// podmanContainerRecord — subset of overlay-containers/containers.json.
type podmanContainerRecord struct {
	ID       string   `json:"id"`
	Names    []string `json:"names"`
	ImageID  string   `json:"image"`
	LayerID  string   `json:"layer"`
	Metadata string   `json:"metadata"` // ignored; present in real data
}

// discoverPodman probes each candidate storage root and returns
// one ContainerTarget per image and per container.  Roots that
// don't exist are silently skipped — this lets the caller pass
// the rootless ``$HOME/...`` path alongside the system path without
// emitting spurious "not found" errors on single-mode hosts.
func discoverPodman(roots []string) ([]ContainerTarget, []scanner.ScanError) {
	var (
		targets []ContainerTarget
		errs    []scanner.ScanError
	)
	for _, root := range roots {
		if !dirExists(root) {
			continue
		}
		t, e := discoverPodmanRoot(root)
		targets = append(targets, t...)
		errs = append(errs, e...)
	}
	return targets, errs
}

func discoverPodmanRoot(root string) ([]ContainerTarget, []scanner.ScanError) {
	var (
		targets []ContainerTarget
		errs    []scanner.ScanError
	)

	// Read the layer index first so we can resolve image and
	// container layer-chains by walking parent pointers.
	layers, layerErr := readPodmanLayers(filepath.Join(root, "overlay-layers", "layers.json"))
	if layerErr != nil {
		// A hard failure here means we can't resolve any image;
		// emit one error and bail on this root.
		errs = append(errs, scanner.ScanError{
			Path:    filepath.Join(root, "overlay-layers", "layers.json"),
			EnvType: "container",
			Error:   fmt.Sprintf("podman layers.json: %v", layerErr),
		})
		return targets, errs
	}

	// Images.
	images, imgErr := readPodmanImages(filepath.Join(root, "overlay-images", "images.json"))
	if imgErr != nil && !os.IsNotExist(imgErr) {
		errs = append(errs, scanner.ScanError{
			Path:    filepath.Join(root, "overlay-images", "images.json"),
			EnvType: "container",
			Error:   fmt.Sprintf("podman images.json: %v", imgErr),
		})
	}
	// Deterministic target ordering across runs.
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
	for _, img := range images {
		layerChain := resolvePodmanLayerChain(root, img.Layer, layers)
		if len(layerChain) == 0 {
			// No resolvable layers — skip rather than emit an
			// empty MergedTree.  A ScanError surfaces why.
			errs = append(errs, scanner.ScanError{
				Path:    filepath.Join(root, "overlay-images", img.ID),
				EnvType: "container",
				Error:   fmt.Sprintf("podman image %s has no resolvable layers", img.ID),
			})
			continue
		}
		targets = append(targets, ContainerTarget{
			Runtime:      RuntimePodman,
			ImageID:      ensureSHA256Prefix(img.Digest, img.ID),
			ImageTags:    img.Names,
			MergedRootFS: MergedTree{Layers: layerChain},
		})
	}

	// Containers.  We include both running AND stopped here
	// because podman's on-disk state doesn't carry a "Running"
	// flag the way Docker's config.v2.json does — the daemon
	// doesn't exist, so state is derived at query time via
	// process lookups.  Matching Docker's "running only" gate
	// would require proc-table walking; for now we emit every
	// container with a writable upper layer and tag them by
	// container_id so operators can filter.
	containers, ctrErr := readPodmanContainers(filepath.Join(root, "overlay-containers", "containers.json"))
	if ctrErr != nil && !os.IsNotExist(ctrErr) {
		errs = append(errs, scanner.ScanError{
			Path:    filepath.Join(root, "overlay-containers", "containers.json"),
			EnvType: "container",
			Error:   fmt.Sprintf("podman containers.json: %v", ctrErr),
		})
	}
	// Index images by ID so we can stitch the image's base
	// layer chain + the container's own upper-dir.
	imageByID := map[string]podmanImageRecord{}
	for _, img := range images {
		imageByID[img.ID] = img
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
	for _, c := range containers {
		img, ok := imageByID[c.ImageID]
		if !ok {
			// Container whose image has been removed but the
			// container record lingers — emit what we can, tagged
			// with the image ID we have.
			errs = append(errs, scanner.ScanError{
				Path:    filepath.Join(root, "overlay-containers", c.ID),
				EnvType: "container",
				Error:   fmt.Sprintf("podman container %s references unknown image %s", c.ID, c.ImageID),
			})
			continue
		}
		// The container's own layer id is the top of its layer
		// stack (built atop the image's top layer).
		layerChain := resolvePodmanLayerChain(root, c.LayerID, layers)
		if len(layerChain) == 0 {
			// Fall back to the image's chain alone so at least
			// the base image content surfaces in inventory.
			layerChain = resolvePodmanLayerChain(root, img.Layer, layers)
		}
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}
		targets = append(targets, ContainerTarget{
			Runtime:       RuntimePodman,
			ImageID:       ensureSHA256Prefix(img.Digest, img.ID),
			ImageTags:     img.Names,
			ContainerID:   c.ID,
			ContainerName: name,
			MergedRootFS:  MergedTree{Layers: layerChain},
		})
	}

	return targets, errs
}

// resolvePodmanLayerChain walks the parent-pointer chain from a top
// layer ID down to the base layer, then reverses so the returned
// slice is bottom-to-top (matching MergedTree's convention).
// Missing layers produce a silent truncation: the bottom-most
// resolvable layers are returned.  A completely unresolvable chain
// returns nil so callers can emit a scoped ScanError.
func resolvePodmanLayerChain(root, topID string, layers map[string]podmanLayerRecord) []string {
	if topID == "" {
		return nil
	}
	var chain []string // top-to-bottom during walk
	current := topID
	// Depth cap protects against a malformed index with a cycle;
	// real images rarely exceed 50 layers.
	for i := 0; i < 200 && current != ""; i++ {
		layer, ok := layers[current]
		if !ok {
			break
		}
		dir := filepath.Join(root, "overlay", layer.ID, "diff")
		if !dirExists(dir) {
			// Layer metadata claims it exists but the physical
			// dir is gone — skip; the rest of the chain may
			// still be intact.
			current = layer.Parent
			continue
		}
		chain = append(chain, dir)
		current = layer.Parent
	}
	if len(chain) == 0 {
		return nil
	}
	// Reverse to bottom-to-top for MergedTree.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// readPodmanImages parses images.json; missing file = empty set.
func readPodmanImages(path string) ([]podmanImageRecord, error) {
	data, err := readCappedFile(path, 10<<20) // 10 MiB cap
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, err
	}
	var out []podmanImageRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return out, nil
}

// readPodmanLayers parses layers.json into an id-keyed map.
func readPodmanLayers(path string) (map[string]podmanLayerRecord, error) {
	data, err := readCappedFile(path, 50<<20) // 50 MiB — layers.json can be large on image-dense hosts
	if err != nil {
		if os.IsNotExist(err) {
			// No layers means no images to scan — not an error.
			return map[string]podmanLayerRecord{}, nil
		}
		return nil, err
	}
	var list []podmanLayerRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	out := make(map[string]podmanLayerRecord, len(list))
	for _, l := range list {
		out[l.ID] = l
	}
	return out, nil
}

// readPodmanContainers parses containers.json.
func readPodmanContainers(path string) ([]podmanContainerRecord, error) {
	data, err := readCappedFile(path, 10<<20)
	if err != nil {
		return nil, err
	}
	var out []podmanContainerRecord
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return out, nil
}

// ensureSHA256Prefix normalises to ``sha256:<hex>`` form.  Podman's
// images.json carries an unprefixed 64-char hex ID and a separate
// ``digest`` field; we prefer the digest if present, otherwise
// synthesise the prefix.
func ensureSHA256Prefix(digest, fallbackID string) string {
	if digest != "" {
		return digest
	}
	if strings.HasPrefix(fallbackID, "sha256:") {
		return fallbackID
	}
	return "sha256:" + fallbackID
}
