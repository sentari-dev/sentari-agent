package containers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// defaultDockerRoot is the well-known Docker data-root on Linux.
// Overridable via Config.DockerRoot for tests or for hosts where
// the daemon was configured with ``--data-root=/mnt/docker``.
const defaultDockerRoot = "/var/lib/docker"

// dockerImageConfig mirrors the subset of the Docker image config
// JSON we consume.  Docker writes the full OCI image config (plus a
// few Docker-specific fields) under
// ``image/overlay2/imagedb/content/sha256/<image-id>``; we only need
// the layer chain and a couple of metadata fields for tagging.
type dockerImageConfig struct {
	RootFS struct {
		Type    string   `json:"type"`     // expect "layers"
		DiffIDs []string `json:"diff_ids"` // bottom-to-top, e.g. "sha256:..."
	} `json:"rootfs"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// dockerRepositoriesFile is the top-level tag → digest index that
// Docker keeps consistent with its imagedb.  Shape:
//
//	{
//	  "Repositories": {
//	    "python": {"python:3.12": "sha256:abc...", "python:latest": "sha256:abc..."}
//	  }
//	}
type dockerRepositoriesFile struct {
	Repositories map[string]map[string]string `json:"Repositories"`
}

// dockerContainerConfig is the subset of
// ``containers/<id>/config.v2.json`` we consume.
type dockerContainerConfig struct {
	ID    string `json:"ID"`
	Name  string `json:"Name"` // leading ``/`` in docker's layout
	Image string `json:"Image"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
}

// discoverDocker walks the Docker storage tree under ``root`` (or
// the default) and returns one ContainerTarget per image and per
// running container.  A non-existent root is not an error — simply
// no Docker on this host.
//
// Invariant: every returned target has a MergedTree whose layer
// order matches rootfs.diff_ids bottom-to-top, and running
// containers have the writable upper-dir appended as the top layer.
func discoverDocker(root string) ([]ContainerTarget, []scanner.ScanError) {
	if root == "" {
		root = defaultDockerRoot
	}
	if !dirExists(root) {
		return nil, nil
	}

	var (
		targets []ContainerTarget
		errs    []scanner.ScanError
	)

	// ``image/<driver>/`` — ``overlay2`` is default since 2017.
	// Accept ``overlay`` and ``aufs`` as legacy fallbacks so the
	// discoverer doesn't silently miss an old host.
	imageDir := filepath.Join(root, "image", "overlay2")
	if !dirExists(imageDir) {
		for _, driver := range []string{"overlay", "aufs"} {
			candidate := filepath.Join(root, "image", driver)
			if dirExists(candidate) {
				imageDir = candidate
				break
			}
		}
	}
	// Collect image → layer-paths map so containers can reuse it.
	imageLayers, repoTagsByID, imgErrs := buildDockerImageIndex(root, imageDir)
	errs = append(errs, imgErrs...)

	// Emit image-only targets for every image the engine has on
	// disk — whether currently running or not.  Running containers
	// get a SEPARATE target below with the upper-dir appended.
	imageIDs := sortedKeys(imageLayers)
	for _, imageID := range imageIDs {
		targets = append(targets, ContainerTarget{
			Runtime:   RuntimeDocker,
			ImageID:   imageID,
			ImageTags: repoTagsByID[imageID],
			MergedRootFS: MergedTree{
				Layers: imageLayers[imageID],
			},
		})
	}

	// Running containers: walk ``containers/`` and for each one
	// that has the writable upper-dir metadata in layerdb/mounts,
	// emit a second target with that dir appended.
	cTargets, cErrs := discoverDockerContainers(root, imageLayers, repoTagsByID)
	targets = append(targets, cTargets...)
	errs = append(errs, cErrs...)

	return targets, errs
}

// buildDockerImageIndex reads imagedb + layerdb + repositories.json
// to produce:
//
//   - imageLayers[imageID] = []physical layer path, bottom-to-top
//   - repoTagsByID[imageID] = []string (tags pointing at this image)
//
// A malformed image config surfaces as a ScanError; the rest of the
// index still populates so one corrupt image doesn't block every
// other container from being scanned.
func buildDockerImageIndex(root, imageDir string) (
	map[string][]string, map[string][]string, []scanner.ScanError,
) {
	imageLayers := map[string][]string{}
	repoTagsByID := map[string][]string{}
	var errs []scanner.ScanError

	// Tags first — lets us attribute ``python:3.12`` back to its
	// sha256 even when the image was loaded via ``docker load``.
	if tags, err := readRepositories(filepath.Join(imageDir, "repositories.json")); err == nil {
		for imageID, ts := range tags {
			sort.Strings(ts)
			repoTagsByID[imageID] = ts
		}
	}
	// (Missing repositories.json is fine — just means no tags
	// known; image IDs still surface.  readRepositories returns
	// nil, nil in that case.)

	// Walk imagedb/content/sha256/*; every entry is one image
	// config keyed by the sha256 of its contents.
	contentDir := filepath.Join(imageDir, "imagedb", "content", "sha256")
	entries, err := os.ReadDir(contentDir)
	if err != nil {
		// No content dir means no images on this host — not an
		// error for us, just "nothing to scan."
		return imageLayers, repoTagsByID, errs
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		imageID := "sha256:" + e.Name()
		configPath := filepath.Join(contentDir, e.Name())
		cfg, err := readDockerImageConfig(configPath)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    configPath,
				EnvType: "container",
				Error:   fmt.Sprintf("docker image config: %v", err),
			})
			continue
		}
		if cfg.RootFS.Type != "layers" {
			// Schema-2 images always use "layers"; anything else is
			// an unsupported old format.
			continue
		}
		layers, lErrs := resolveDockerLayerPaths(root, imageDir, cfg.RootFS.DiffIDs)
		errs = append(errs, lErrs...)
		if len(layers) == 0 {
			// All layers unresolved — skip the image entirely
			// rather than emit an empty MergedTree that would
			// produce zero records with a misleading imageID.
			continue
		}
		imageLayers[imageID] = layers
	}
	return imageLayers, repoTagsByID, errs
}

// resolveDockerLayerPaths turns the image config's bottom-to-top
// ``diff_ids`` list into a bottom-to-top list of physical layer
// rootfs paths (``overlay2/<cache-id>/diff``) via the chainID →
// cacheID → diff-dir hop.
//
// Chain-ID computation (from docker/distribution's source):
//
//	chainID[0] = diff_ids[0]
//	chainID[i] = sha256("<chainID[i-1]> <diff_ids[i]>")
//
// The ``sha256:`` prefix is dropped during hashing and re-added for
// layerdb lookup (the directory name omits the prefix).
func resolveDockerLayerPaths(root, imageDir string, diffIDs []string) ([]string, []scanner.ScanError) {
	if len(diffIDs) == 0 {
		return nil, nil
	}
	var (
		out  []string
		errs []scanner.ScanError
	)
	layerdb := filepath.Join(imageDir, "layerdb", "sha256")
	chainID := stripSHA256(diffIDs[0])
	for i, diffID := range diffIDs {
		if i > 0 {
			// chainID_i = sha256("chainID_{i-1} diffID_i")
			h := sha256.Sum256([]byte("sha256:" + chainID + " " + diffID))
			chainID = hex.EncodeToString(h[:])
		}
		cacheIDPath := filepath.Join(layerdb, chainID, "cache-id")
		cacheID, err := os.ReadFile(cacheIDPath)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    cacheIDPath,
				EnvType: "container",
				Error:   fmt.Sprintf("docker layer cache-id missing (chainID=%s): %v", chainID, err),
			})
			continue
		}
		id := strings.TrimSpace(string(cacheID))
		if id == "" {
			continue
		}
		// overlay2 storage driver layout.
		dir := filepath.Join(root, filepath.Base(imageDir), id, "diff")
		if !dirExists(dir) {
			// Dangling layer — the overlay2 dir was garbage-
			// collected but the layerdb entry survives.  Skip
			// rather than emit a non-existent path.
			errs = append(errs, scanner.ScanError{
				Path:    dir,
				EnvType: "container",
				Error:   "docker layer diff dir missing; image skipped (dangling layer)",
			})
			return nil, errs
		}
		out = append(out, dir)
	}
	return out, errs
}

// discoverDockerContainers enumerates running containers and emits
// one target per, with the image's layers + the container's
// writable upper-dir appended.  Stopped containers are intentionally
// skipped: their upper-dir is still on disk, but scanning it surfaces
// state that's no longer actively used — tends to mislead operators
// investigating active CVEs.
func discoverDockerContainers(root string, imageLayers, repoTagsByID map[string][]string) (
	[]ContainerTarget, []scanner.ScanError,
) {
	containersDir := filepath.Join(root, "containers")
	if !dirExists(containersDir) {
		return nil, nil
	}
	entries, err := os.ReadDir(containersDir)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:    containersDir,
			EnvType: "container",
			Error:   fmt.Sprintf("docker containers dir: %v", err),
		}}
	}
	var (
		targets []ContainerTarget
		errs    []scanner.ScanError
	)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cid := e.Name()
		configPath := filepath.Join(containersDir, cid, "config.v2.json")
		cfg, err := readDockerContainerConfig(configPath)
		if err != nil {
			// Not every entry under containers/ is a valid
			// config — stopped-forever or partially-cleaned-up
			// entries may lack the JSON.  Skip silently.
			continue
		}
		if !cfg.State.Running {
			continue
		}
		baseLayers, ok := imageLayers[cfg.Image]
		if !ok {
			errs = append(errs, scanner.ScanError{
				Path:    configPath,
				EnvType: "container",
				Error:   fmt.Sprintf("running container %s references unknown image %s", cid, cfg.Image),
			})
			continue
		}
		// Writable upper-dir lives at
		// ``image/overlay2/layerdb/mounts/<cid>/mount-id`` → UUID.
		upperDir, err := dockerContainerUpperDir(root, cid)
		if err != nil {
			// Best-effort: emit the image layers only.  A
			// ScanError tells operators why the upper-dir wasn't
			// included.
			errs = append(errs, scanner.ScanError{
				Path:    configPath,
				EnvType: "container",
				Error:   fmt.Sprintf("docker container %s upper-dir not resolvable: %v", cid, err),
			})
		}
		layers := append([]string{}, baseLayers...)
		if upperDir != "" {
			layers = append(layers, upperDir)
		}
		name := strings.TrimPrefix(cfg.Name, "/")
		targets = append(targets, ContainerTarget{
			Runtime:       RuntimeDocker,
			ImageID:       cfg.Image,
			ImageTags:     repoTagsByID[cfg.Image],
			ContainerID:   cid,
			ContainerName: name,
			MergedRootFS:  MergedTree{Layers: layers},
		})
	}
	return targets, errs
}

// dockerContainerUpperDir returns the physical path to the
// container's writable top layer, or "" (+ error) if the mount
// metadata is absent.
func dockerContainerUpperDir(root, cid string) (string, error) {
	// Try overlay2 first (default since 2017); fall back to other
	// drivers if needed.
	for _, driver := range []string{"overlay2", "overlay", "aufs"} {
		mountIDPath := filepath.Join(root, "image", driver, "layerdb", "mounts", cid, "mount-id")
		b, err := os.ReadFile(mountIDPath)
		if err != nil {
			continue
		}
		mountID := strings.TrimSpace(string(b))
		if mountID == "" {
			continue
		}
		dir := filepath.Join(root, driver, mountID, "diff")
		if dirExists(dir) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no mount-id found for container %s under any known driver", cid)
}

// readRepositories parses Docker's ``repositories.json`` and
// returns imageID → []tags, or nil if the file is absent.
func readRepositories(path string) (map[string][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var parsed dockerRepositoriesFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse repositories.json: %w", err)
	}
	out := map[string][]string{}
	for _, byTag := range parsed.Repositories {
		for tag, imageID := range byTag {
			out[imageID] = append(out[imageID], tag)
		}
	}
	return out, nil
}

// readDockerImageConfig parses one imagedb config.  Bounded read:
// image configs are typically < 10 KiB; 1 MiB is a safe ceiling
// against a hostile file.
func readDockerImageConfig(path string) (dockerImageConfig, error) {
	data, err := readCappedFile(path, 1<<20)
	if err != nil {
		return dockerImageConfig{}, err
	}
	var cfg dockerImageConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return dockerImageConfig{}, fmt.Errorf("parse: %w", err)
	}
	return cfg, nil
}

// readDockerContainerConfig parses containers/<id>/config.v2.json.
// These can grow (logs, env vars) — 5 MiB cap.
func readDockerContainerConfig(path string) (dockerContainerConfig, error) {
	data, err := readCappedFile(path, 5<<20)
	if err != nil {
		return dockerContainerConfig{}, err
	}
	var cfg dockerContainerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return dockerContainerConfig{}, fmt.Errorf("parse: %w", err)
	}
	return cfg, nil
}

// readCappedFile reads up to ``max`` bytes; returns an error if the
// file exceeds the cap rather than silently truncating.
func readCappedFile(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s exceeds cap (%d > %d bytes)", path, info.Size(), max)
	}
	return os.ReadFile(path)
}

// stripSHA256 returns the hex portion of a ``sha256:<hex>`` digest
// string, passing through the string unchanged if no prefix is
// present.
func stripSHA256(s string) string {
	return strings.TrimPrefix(s, "sha256:")
}

// sortedKeys returns map keys sorted lexicographically.  Used to
// produce a deterministic ContainerTarget order across runs so
// tests and operators see a stable output.
func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
