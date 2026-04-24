package containers

import (
	"context"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// Runtime identifies which container engine produced a target.
// Emitted on every PackageRecord scanned from inside a container so
// dashboards can say "this CVE is inside a Docker container" vs
// "inside a Podman rootless container."
type Runtime string

const (
	RuntimeDocker     Runtime = "docker"
	RuntimeContainerd Runtime = "containerd"
	RuntimePodman     Runtime = "podman"
	RuntimeCRIO       Runtime = "crio"
)

// ContainerTarget is one unit of work the container scanner produces
// for the orchestrator.  Images yield targets with ``ContainerID == ""``;
// running containers yield targets with ``ContainerID`` set and
// ``MergedRootFS`` that includes the container's upper-dir as the top
// layer (so ``pip install`` etc. inside a running container surfaces).
type ContainerTarget struct {
	// Runtime identifies the engine that produced this target.
	Runtime Runtime
	// ImageID is the OCI image digest (``sha256:...``).  Present for
	// both image-only targets and running-container targets (the
	// container was started from this image).
	ImageID string
	// ImageTags lists every tag the engine has for ``ImageID``
	// locally (``python:3.12``, ``docker.io/library/python:3.12``,
	// etc.).  May be empty for dangling images.
	ImageTags []string
	// ContainerID is the container UUID — empty for image-only
	// targets.  Present for running-container targets.
	ContainerID string
	// ContainerName is the engine-assigned name (``happy_curie``).
	// Empty for image-only targets.
	ContainerName string
	// MergedRootFS is the stacked view the Phase-A walker will
	// process.  For images: layers in the image's rootfs.diff_ids
	// order, bottom-to-top.  For running containers: the same plus
	// the container's upper-dir appended as the final layer.
	MergedRootFS MergedTree
}

// Config controls container discovery.  Zero value means "use
// production defaults": every known runtime is probed, discovery
// errors are collected but never fatal.
type Config struct {
	// DockerRoot overrides ``/var/lib/docker``.  Tests set this to a
	// fixture tree; production reads the real path.  Empty string =
	// use the default.
	DockerRoot string
	// ContainerdRoot overrides ``/var/lib/containerd``.
	ContainerdRoot string
	// PodmanRoots overrides the podman storage paths; first match
	// wins.  Defaults to ``[/var/lib/containers/storage]`` plus the
	// caller's rootless ``$HOME/.local/share/containers/storage``
	// when HOME is readable.  Tests pass a single fixture path.
	PodmanRoots []string
	// CRIORoot overrides the CRI-O storage root (same layout as
	// Podman; defaults to ``/var/lib/containers/storage`` same as
	// Podman's system path, so we skip this if PodmanRoots already
	// covered it).
	CRIORoot string
	// Now is injected for deterministic timestamps in discovery
	// logs.  ``nil`` = use time.Now.
	Now func() time.Time
}

// Scanner performs runtime discovery across Docker, containerd,
// Podman, and CRI-O, and hands the resulting ``ContainerTarget`` set
// to the orchestrator.  It is NOT a scanner.Scanner plugin — see the
// Sprint-17 container-scanner plan §4 for the rationale.  The
// orchestrator invokes DiscoverTargets() once per scan cycle,
// then for each target opens a sub-scan with the merged rootfs as
// the scan root so the existing plugin registry handles it normally.
type Scanner struct {
	cfg Config
}

// NewScanner returns a Scanner with the given config.  The zero
// Config value is valid and probes every known runtime at its
// default path.
func NewScanner(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// DiscoverTargets fans out to every per-runtime discoverer and
// aggregates their targets.  A runtime that isn't present on this
// host (e.g. the agent is on a pure-Podman box with no Docker)
// silently contributes zero targets; every non-fatal issue surfaces
// as a ScanError so operators can audit what was skipped and why.
//
// Context cancellation is respected at the per-runtime boundary;
// each discoverer is expected to check ``ctx.Err()`` during its
// filesystem walk if it does heavy work.
func (s *Scanner) DiscoverTargets(ctx context.Context) ([]ContainerTarget, []scanner.ScanError) {
	var (
		targets []ContainerTarget
		errs    []scanner.ScanError
	)

	// Docker — the most common runtime, first to probe.
	if ctx.Err() == nil {
		t, e := discoverDocker(s.cfg.DockerRoot)
		targets = append(targets, t...)
		errs = append(errs, s.stamp(e)...)
	}

	// containerd — Kubernetes nodes, standalone containerd.
	if ctx.Err() == nil {
		t, e := discoverContainerd(s.cfg.ContainerdRoot)
		targets = append(targets, t...)
		errs = append(errs, s.stamp(e)...)
	}

	// Podman (system + rootless) — covers CRI-O's system path too.
	if ctx.Err() == nil {
		t, e := discoverPodman(s.effectivePodmanRoots())
		targets = append(targets, t...)
		errs = append(errs, s.stamp(e)...)
	}

	// CRI-O at a non-default path — only probe when explicitly
	// configured; otherwise the default overlaps with Podman's
	// system path and would double-scan every image.
	if ctx.Err() == nil && s.cfg.CRIORoot != "" {
		t, e := discoverPodman([]string{s.cfg.CRIORoot})
		// Re-label the runtime — the on-disk format is identical
		// to Podman's but the operator-facing tag differs.
		for i := range t {
			t[i].Runtime = RuntimeCRIO
		}
		targets = append(targets, t...)
		errs = append(errs, s.stamp(e)...)
	}

	return dedupeTargets(targets), errs
}

// effectivePodmanRoots returns the Podman root paths to probe,
// honouring the caller's override or falling back to the
// conventional layout.
func (s *Scanner) effectivePodmanRoots() []string {
	if len(s.cfg.PodmanRoots) > 0 {
		return s.cfg.PodmanRoots
	}
	roots := []string{"/var/lib/containers/storage"}
	// Rootless podman: per-user storage under $HOME.  We add it as
	// a best-effort path; missing HOME is not an error, just a no-op.
	if home := userHome(); home != "" {
		roots = append(roots, home+"/.local/share/containers/storage")
	}
	return roots
}

// stamp sets Timestamp on every ScanError that doesn't already have
// one so the discoverer code can stay time-independent.  Mirrors the
// pattern used in the JVM scanner.
func (s *Scanner) stamp(errs []scanner.ScanError) []scanner.ScanError {
	if len(errs) == 0 {
		return errs
	}
	now := s.nowFn()()
	for i := range errs {
		if errs[i].Timestamp.IsZero() {
			errs[i].Timestamp = now
		}
	}
	return errs
}

func (s *Scanner) nowFn() func() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now
	}
	return func() time.Time { return time.Now().UTC() }
}

// dedupeTargets removes duplicate ``ContainerTarget``s that can
// arise when two runtimes share a storage path (Podman + CRI-O at
// ``/var/lib/containers/storage``) or when a rootless + rootful
// Podman surface the same image.  Uniqueness key is
// (Runtime, ImageID, ContainerID).
func dedupeTargets(ts []ContainerTarget) []ContainerTarget {
	seen := map[string]struct{}{}
	out := ts[:0]
	for _, t := range ts {
		key := string(t.Runtime) + "|" + t.ImageID + "|" + t.ContainerID
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, t)
	}
	return out
}
