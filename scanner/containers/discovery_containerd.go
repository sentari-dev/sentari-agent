package containers

import (
	"github.com/sentari-dev/sentari-agent/scanner"
)

// discoverContainerd is a deliberate no-op in this sprint.
//
// Containerd stores its image→layer metadata in a BoltDB
// (``io.containerd.metadata.v1.bolt/meta.db``) rather than in JSON
// files the way Docker and Podman do.  Parsing that without linking
// against bbolt (which is pure Go, but non-trivial to embed under
// the ``CGO_ENABLED=0`` + tree-shaking rules we run the agent under)
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
// ``io.containerd.snapshotter.v1.overlayfs/snapshots/*/fs`` as
// anonymous layer directories without image attribution — useful
// for "what's installed somewhere on this node" at the cost of
// losing the image-id label.
//
// The ``root`` parameter is reserved for the follow-up and kept in
// the signature so the scanner.go dispatcher doesn't need to
// change when the real implementation lands.
func discoverContainerd(root string) ([]ContainerTarget, []scanner.ScanError) {
	_ = root
	return nil, nil
}
