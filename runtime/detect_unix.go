//go:build unix

package runtime

import (
	"os"
	"strings"
)

// detect runs the per-OS probes in increasing-cost order.  Linux +
// macOS share this implementation:
//
//   - K8s exposes ``KUBERNETES_SERVICE_HOST`` to every pod, including
//     Windows pods.  Cheapest + most specific signal.
//   - Podman drops a marker file at ``/run/.containerenv`` when it
//     boots a container.
//   - Linux containers (Docker, containerd, kubepods that mask the
//     KUBERNETES_SERVICE_HOST env var somehow) leave fingerprints
//     in ``/proc/1/cgroup``.  macOS has no /proc — the read fails,
//     we fall through to bare_metal, which is the canonical signal
//     that the host is a developer laptop and not a container.
//   - Default: bare_metal.
func detect() string {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return K8s
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return Container
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, marker := range []string{"docker", "containerd", "kubepods"} {
			if strings.Contains(s, marker) {
				return Container
			}
		}
	}
	return BareMetal
}
