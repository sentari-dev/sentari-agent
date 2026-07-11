package containers

import (
	"fmt"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// defaultContainerdRoot is the well-known containerd data-root on
// Linux.  Overridable via Config.ContainerdRoot for tests or for hosts
// where containerd was configured with a non-default `root =` in
// /etc/containerd/config.toml.
const defaultContainerdRoot = "/var/lib/containerd"

// discoverContainerd is a deliberate no-op in this sprint.
//
// Containerd stores its image→layer metadata in a BoltDB
// (`io.containerd.metadata.v1.bolt/meta.db`) rather than in JSON
// files the way Docker and Podman do.  Parsing that without linking
// against bbolt (which is pure Go, but non-trivial to embed under
// the `CGO_ENABLED=0` + tree-shaking rules we run the agent under)
// is the remaining work for containerd support.
//
// The alternative path — walking the content-addressable blob
// store and reconstructing image manifests by shape — is feasible
// but requires decompressing each layer tar to a staging directory,
// which breaks the "merged tree is a virtual view of the on-disk
// state" invariant that the Phase-A walker relies on.
//
// Returning nil, nil here is the right behaviour for this Phase-B
// PR: a containerd-backed Kubernetes node surfaces its host
// inventory (the agent's baseline scan path) but skips container
// internals silently.  A follow-up PR lands either (a) the bolt
// parser, or (b) a snapshot-walker that treats
// `io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs` as
// anonymous layer directories without image attribution — useful
// for "what's installed somewhere on this node" at the cost of
// losing the image-id label.
//
// The `root` parameter is reserved for the follow-up and kept in
// the signature so the scanner.go dispatcher doesn't need to
// change when the real implementation lands.  It also lets us detect
// whether containerd is actually present on this host so the no-op is
// observable to an operator (see below) instead of silently empty.
func discoverContainerd(root string) ([]ContainerTarget, []scanner.ScanError) {
	if root == "" {
		root = defaultContainerdRoot
	}
	// No containerd data-root on disk — this host doesn't run
	// containerd, so stay silent exactly like the Docker and Podman
	// backends do for an absent runtime.  Emitting a diagnostic here
	// would flood every Docker-only or Podman-only host with a
	// spurious "containerd not implemented" line.
	if !dirExists(root) {
		return nil, nil
	}
	// containerd IS installed but this backend can't yet read its
	// BoltDB metadata store (see the package comment above).  Surface a
	// single runtime diagnostic — the same ScanError mechanism the
	// Docker/Podman backends use for skipped content — so an operator
	// on a containerd-backed Kubernetes node sees *why* their container
	// inventory is empty rather than a silent no-op.  Timestamp is left
	// zero; Scanner.stamp fills it in at the dispatcher boundary.
	return nil, []scanner.ScanError{{
		Path:    root,
		EnvType: "container",
		Error: fmt.Sprintf(
			"containerd runtime detected at %s but container discovery is not yet "+
				"implemented (image metadata lives in a BoltDB store); host inventory is "+
				"scanned, container internals are skipped",
			root,
		),
	}}
}
