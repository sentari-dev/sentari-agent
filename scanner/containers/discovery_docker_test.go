package containers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildDockerFixture crafts a minimal but valid /var/lib/docker tree
// for unit testing the discoverer.  Each image in ``images`` produces
// an imagedb config, layerdb entries for every chainID, and an
// overlay2 diff dir per layer with a marker file inside so the
// Phase-A walker has something to emit.
type dockerFixtureImage struct {
	ID      string   // "sha256:abcdef..." (64-char hex body)
	Tags    []string // ["python:3.12", ...]
	DiffIDs []string // bottom-to-top
}

type dockerFixtureContainer struct {
	ID      string
	Name    string // "happy_curie" (no leading slash in the test form)
	ImageID string // matches one of the images
	Running bool
}

func buildDockerFixture(t *testing.T, images []dockerFixtureImage, containers []dockerFixtureContainer) string {
	t.Helper()
	root := t.TempDir()

	imageDir := filepath.Join(root, "image", "overlay2")
	contentDir := filepath.Join(imageDir, "imagedb", "content", "sha256")
	layerdb := filepath.Join(imageDir, "layerdb", "sha256")
	overlay2 := filepath.Join(root, "overlay2")

	for _, d := range []string{contentDir, layerdb, overlay2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", d, err)
		}
	}

	// repositories.json — aggregate tag → image ID across all images.
	repos := dockerRepositoriesFile{
		Repositories: map[string]map[string]string{},
	}
	for _, img := range images {
		// Docker stores tags grouped by repo name (the bit before
		// ``:tag``).  Keep it simple here: put every image under a
		// "fixture" repo.  The discoverer only consumes the inner
		// map, so grouping doesn't matter for the assertions.
		repos.Repositories["fixture"] = map[string]string{}
		for _, tag := range img.Tags {
			repos.Repositories["fixture"][tag] = img.ID
		}
	}
	if err := writeJSON(filepath.Join(imageDir, "repositories.json"), repos); err != nil {
		t.Fatalf("write repositories.json: %v", err)
	}

	for _, img := range images {
		// imagedb config.
		cfg := dockerImageConfig{}
		cfg.RootFS.Type = "layers"
		cfg.RootFS.DiffIDs = img.DiffIDs
		cfgPath := filepath.Join(contentDir, stripSHA256(img.ID))
		if err := writeJSON(cfgPath, cfg); err != nil {
			t.Fatalf("write image config: %v", err)
		}

		// layerdb + overlay2/diff for each chain ID in the chain.
		chainID := stripSHA256(img.DiffIDs[0])
		for i, diffID := range img.DiffIDs {
			if i > 0 {
				h := sha256.Sum256([]byte("sha256:" + chainID + " " + diffID))
				chainID = hex.EncodeToString(h[:])
			}
			cacheID := "cache-" + chainID[:12]

			chainDir := filepath.Join(layerdb, chainID)
			if err := os.MkdirAll(chainDir, 0o755); err != nil {
				t.Fatalf("mkdir chain: %v", err)
			}
			if err := os.WriteFile(filepath.Join(chainDir, "cache-id"), []byte(cacheID), 0o644); err != nil {
				t.Fatalf("write cache-id: %v", err)
			}
			diffDir := filepath.Join(overlay2, cacheID, "diff")
			if err := os.MkdirAll(diffDir, 0o755); err != nil {
				t.Fatalf("mkdir diff: %v", err)
			}
			// Plant a marker file so the walker sees content.
			marker := filepath.Join(diffDir, "layer-"+chainID[:8]+".txt")
			if err := os.WriteFile(marker, []byte("content"), 0o644); err != nil {
				t.Fatalf("write marker: %v", err)
			}
		}
	}

	if len(containers) > 0 {
		cDir := filepath.Join(root, "containers")
		mountsDir := filepath.Join(imageDir, "layerdb", "mounts")
		for _, c := range containers {
			cid := c.ID
			cPath := filepath.Join(cDir, cid)
			if err := os.MkdirAll(cPath, 0o755); err != nil {
				t.Fatalf("mkdir container dir: %v", err)
			}
			cfg := dockerContainerConfig{
				ID:    cid,
				Name:  "/" + c.Name,
				Image: c.ImageID,
			}
			cfg.State.Running = c.Running
			if err := writeJSON(filepath.Join(cPath, "config.v2.json"), cfg); err != nil {
				t.Fatalf("write container config: %v", err)
			}

			if c.Running {
				mountID := "mount-" + cid[:8]
				md := filepath.Join(mountsDir, cid)
				if err := os.MkdirAll(md, 0o755); err != nil {
					t.Fatalf("mkdir mount dir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(md, "mount-id"), []byte(mountID), 0o644); err != nil {
					t.Fatalf("write mount-id: %v", err)
				}
				upperDir := filepath.Join(overlay2, mountID, "diff")
				if err := os.MkdirAll(upperDir, 0o755); err != nil {
					t.Fatalf("mkdir upper diff: %v", err)
				}
				// Container-specific file — something pip install
				// might have dropped.
				if err := os.WriteFile(filepath.Join(upperDir, "container-install.txt"), []byte("dropped-in-container"), 0o644); err != nil {
					t.Fatalf("write container marker: %v", err)
				}
			}
		}
	}

	return root
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// TestDiscoverDocker_NoRoot: no docker root on this host — discoverer
// returns nil, nil rather than a spurious error.  Core invariant:
// discovering is best-effort; missing runtime = "nothing to scan."
func TestDiscoverDocker_NoRoot(t *testing.T) {
	targets, errs := discoverDocker(filepath.Join(t.TempDir(), "absent"))
	if len(targets) != 0 || len(errs) != 0 {
		t.Fatalf("expected (nil, nil), got (%+v, %+v)", targets, errs)
	}
}

// TestDiscoverDocker_SingleImage: a minimal fixture with one image
// (two layers) produces exactly one ContainerTarget whose
// MergedRootFS carries the layers in the right order and tags
// match repositories.json.
func TestDiscoverDocker_SingleImage(t *testing.T) {
	img := dockerFixtureImage{
		ID:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tags:    []string{"python:3.12"},
		DiffIDs: []string{
			"sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"sha256:2222222222222222222222222222222222222222222222222222222222222222",
		},
	}
	root := buildDockerFixture(t, []dockerFixtureImage{img}, nil)

	targets, errs := discoverDocker(root)
	if len(errs) != 0 {
		t.Fatalf("unexpected ScanErrors: %+v", errs)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d: %+v", len(targets), targets)
	}
	got := targets[0]
	if got.Runtime != RuntimeDocker {
		t.Errorf("Runtime: got %q, want %q", got.Runtime, RuntimeDocker)
	}
	if got.ImageID != img.ID {
		t.Errorf("ImageID: got %q, want %q", got.ImageID, img.ID)
	}
	if len(got.ImageTags) != 1 || got.ImageTags[0] != "python:3.12" {
		t.Errorf("ImageTags: got %v, want [python:3.12]", got.ImageTags)
	}
	if len(got.MergedRootFS.Layers) != 2 {
		t.Errorf("expected 2 layers in MergedRootFS, got %d: %v", len(got.MergedRootFS.Layers), got.MergedRootFS.Layers)
	}
	if got.ContainerID != "" {
		t.Errorf("ContainerID should be empty for image-only target; got %q", got.ContainerID)
	}
}

// TestDiscoverDocker_RunningContainerAppendsUpperDir: a running
// container yields a SECOND target (the image-only one is still
// emitted) whose layer list has the upper-dir appended on top.
func TestDiscoverDocker_RunningContainerAppendsUpperDir(t *testing.T) {
	img := dockerFixtureImage{
		ID: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		DiffIDs: []string{
			"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		},
	}
	containers := []dockerFixtureContainer{{
		ID:      "container-abcdefabcdef",
		Name:    "happy_curie",
		ImageID: img.ID,
		Running: true,
	}}
	root := buildDockerFixture(t, []dockerFixtureImage{img}, containers)

	targets, errs := discoverDocker(root)
	if len(errs) != 0 {
		t.Fatalf("unexpected ScanErrors: %+v", errs)
	}
	// Expect 2 targets: 1 image-only + 1 running container.
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d: %+v", len(targets), targets)
	}
	var running *ContainerTarget
	for i := range targets {
		if targets[i].ContainerID != "" {
			running = &targets[i]
			break
		}
	}
	if running == nil {
		t.Fatalf("no running-container target in output: %+v", targets)
	}
	if running.ContainerName != "happy_curie" {
		t.Errorf("ContainerName: got %q, want happy_curie", running.ContainerName)
	}
	// Image had 1 layer; container adds 1 upper-dir → 2 total.
	if len(running.MergedRootFS.Layers) != 2 {
		t.Errorf("expected 2 layers (image + upper-dir), got %d: %v",
			len(running.MergedRootFS.Layers), running.MergedRootFS.Layers)
	}
}

// TestDiscoverDocker_StoppedContainerSkipped: a container with
// State.Running=false does NOT produce a running-container target.
// Stopped-container inventory is noise — the image target already
// covers it, and conflating the two mis-reports "what's running."
func TestDiscoverDocker_StoppedContainerSkipped(t *testing.T) {
	img := dockerFixtureImage{
		ID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		DiffIDs: []string{
			"sha256:4444444444444444444444444444444444444444444444444444444444444444",
		},
	}
	containers := []dockerFixtureContainer{{
		ID:      "stopped-xxxxxx",
		Name:    "boring_boole",
		ImageID: img.ID,
		Running: false,
	}}
	root := buildDockerFixture(t, []dockerFixtureImage{img}, containers)

	targets, _ := discoverDocker(root)
	for _, tt := range targets {
		if tt.ContainerID != "" {
			t.Errorf("stopped container should be skipped; got %+v", tt)
		}
	}
}

// TestDiscoverDocker_DanglingLayer: imagedb references a layer
// whose overlay2/<cache>/diff dir has been garbage-collected.
// Discoverer must NOT include the image with a half-resolved
// MergedRootFS (that would produce ghost records attributed to the
// wrong content).  Surfaces as a ScanError instead.
func TestDiscoverDocker_DanglingLayer(t *testing.T) {
	img := dockerFixtureImage{
		ID: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		DiffIDs: []string{
			"sha256:5555555555555555555555555555555555555555555555555555555555555555",
		},
	}
	root := buildDockerFixture(t, []dockerFixtureImage{img}, nil)
	// Simulate garbage collection: nuke the overlay2 diff dir.
	chainID := stripSHA256(img.DiffIDs[0])
	cacheID := "cache-" + chainID[:12]
	if err := os.RemoveAll(filepath.Join(root, "overlay2", cacheID)); err != nil {
		t.Fatalf("remove diff dir: %v", err)
	}

	targets, errs := discoverDocker(root)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets when image has dangling layer; got %+v", targets)
	}
	// At least one ScanError surfaces the dangling-layer issue.
	found := false
	for _, e := range errs {
		if e.Error != "" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a ScanError for dangling layer; got none")
	}
}
