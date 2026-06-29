//go:build unix

package runtime

import (
	"os"
	"strings"
)

// probes bundles the (injectable) syscalls the Unix container detector
// relies on. Production wires them to the real os.* functions; tests
// substitute in-memory stubs so cgroup-v1/v2 layouts can be simulated
// without a real container.
type probes struct {
	getenv   func(string) string
	stat     func(string) error
	readFile func(string) ([]byte, error)
}

// realProbes binds probes to the live filesystem and environment.
func realProbes() probes {
	return probes{
		getenv: os.Getenv,
		stat: func(path string) error {
			_, err := os.Stat(path)
			return err
		},
		readFile: os.ReadFile,
	}
}

// containerCgroupMarkers are the controller/scope substrings that, when
// present in a cgroup hierarchy line, identify a containerized host.
// These appear under cgroup-v1 (in /proc/1/cgroup controller paths) AND
// cgroup-v2 (in the unified "0::/..." hierarchy of /proc/self/cgroup),
// so the same marker set covers both layouts.
var containerCgroupMarkers = []string{"docker", "containerd", "kubepods", "crio", "libpod", "lxc"}

// detect runs the per-OS probes in increasing-cost order.  Linux +
// macOS share this implementation.
func detect() string {
	return detectContainer(realProbes())
}

// detectContainer implements the detection logic against an injectable
// set of probes.  Probe order (cheapest + most specific first):
//
//   - K8s exposes KUBERNETES_SERVICE_HOST to every pod.
//   - Podman/CRI-O drop /run/.containerenv; Docker drops /.dockerenv.
//   - cgroup-v1 hosts leave controller fingerprints in /proc/1/cgroup.
//   - cgroup-v2 hosts collapse everything into a single unified
//     hierarchy line ("0::/...") whose scope path still names the
//     runtime (e.g. ".../docker-<id>.scope", ".../kubepods.slice/...").
//     /proc/1/cgroup on a v2 host carries NO controller markers, so we
//     also read /proc/self/cgroup and scan both for the marker set.
//   - macOS has no /proc — the reads fail and we fall through to
//     bare_metal, the canonical "developer laptop, not a container"
//     signal.
func detectContainer(p probes) string {
	if p.getenv("KUBERNETES_SERVICE_HOST") != "" {
		return K8s
	}
	// Marker files: Podman/CRI-O use /run/.containerenv; Docker uses
	// /.dockerenv. Either is a definitive container signal.
	for _, marker := range []string{"/run/.containerenv", "/.dockerenv"} {
		if err := p.stat(marker); err == nil {
			return Container
		}
	}
	// cgroup inspection — covers both v1 (/proc/1/cgroup controller
	// paths) and v2 (/proc/self/cgroup unified hierarchy). On a v2 host
	// /proc/1/cgroup is just "0::/" with no markers, hence reading
	// /proc/self/cgroup as well.
	for _, path := range []string{"/proc/1/cgroup", "/proc/self/cgroup"} {
		data, err := p.readFile(path)
		if err != nil {
			continue
		}
		s := string(data)
		for _, marker := range containerCgroupMarkers {
			if strings.Contains(s, marker) {
				return Container
			}
		}
	}
	return BareMetal
}
