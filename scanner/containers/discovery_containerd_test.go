package containers

import (
	"context"
	"strings"
	"testing"
)

// TestDiscoverContainerd_AbsentSilent: on a host with no containerd
// data-root, discovery contributes zero targets AND zero diagnostics —
// a Docker-only or Podman-only host must not be flooded with a spurious
// "containerd not implemented" line.
func TestDiscoverContainerd_AbsentSilent(t *testing.T) {
	// A path that definitely doesn't exist as a containerd root.
	missing := t.TempDir() + "/does-not-exist"
	targets, errs := discoverContainerd(missing)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets on absent host, got %d", len(targets))
	}
	if len(errs) != 0 {
		t.Errorf("expected no diagnostic on absent host, got %+v", errs)
	}
}

// TestDiscoverContainerd_DetectedButUnimplemented: when a containerd
// data-root IS present, the no-op is made observable — exactly one
// ScanError surfaces explaining that container discovery is unimplemented
// so an operator on a containerd/Kubernetes node sees why inventory is
// empty rather than a silent no-op.
func TestDiscoverContainerd_DetectedButUnimplemented(t *testing.T) {
	root := t.TempDir() // stands in for /var/lib/containerd
	targets, errs := discoverContainerd(root)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets (discovery unimplemented), got %d", len(targets))
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly one diagnostic, got %d: %+v", len(errs), errs)
	}
	e := errs[0]
	if e.EnvType != "container" {
		t.Errorf("EnvType: got %q, want container", e.EnvType)
	}
	if e.Path != root {
		t.Errorf("Path: got %q, want %q", e.Path, root)
	}
	if !strings.Contains(e.Error, "containerd") || !strings.Contains(e.Error, "not yet implemented") {
		t.Errorf("diagnostic message missing expected content: %q", e.Error)
	}
}

// TestDiscoverContainerd_SurfacedThroughDispatcher: the diagnostic is
// visible via the real DiscoverTargets entrypoint (with its Timestamp
// stamped), not just when calling discoverContainerd directly.
func TestDiscoverContainerd_SurfacedThroughDispatcher(t *testing.T) {
	root := t.TempDir()
	s := NewScanner(Config{
		// Point every backend at empty/absent roots so only containerd
		// produces a diagnostic and the assertion stays deterministic.
		DockerRoot:     t.TempDir() + "/no-docker",
		ContainerdRoot: root,
		PodmanRoots:    []string{t.TempDir() + "/no-podman"},
	})
	_, errs := s.DiscoverTargets(context.Background())
	var found bool
	for _, e := range errs {
		if strings.Contains(e.Error, "containerd") && strings.Contains(e.Error, "not yet implemented") {
			found = true
			if e.Timestamp.IsZero() {
				t.Errorf("dispatcher did not stamp the containerd diagnostic timestamp")
			}
		}
	}
	if !found {
		t.Errorf("containerd diagnostic not surfaced through DiscoverTargets: %+v", errs)
	}
}
