//go:build unix

package runtime

import (
	"errors"
	"os"
	"testing"
)

// probeStub lets a test simulate the file-system signals detectContainer
// reads, without needing a real container.
type probeStub struct {
	k8sEnv   string
	statOK   map[string]bool   // paths that os.Stat would succeed on
	files    map[string]string // path -> contents for ReadFile
}

func (p probeStub) env(key string) string { return p.k8sEnv }

func (p probeStub) stat(path string) error {
	if p.statOK[path] {
		return nil
	}
	return os.ErrNotExist
}

func (p probeStub) read(path string) ([]byte, error) {
	if c, ok := p.files[path]; ok {
		return []byte(c), nil
	}
	return nil, os.ErrNotExist
}

func newProbe(p probeStub) probes {
	return probes{getenv: p.env, stat: p.stat, readFile: p.read}
}

// cgroup-v2 hosts have a single unified hierarchy line in
// /proc/self/cgroup of the form "0::/..." and /proc/1/cgroup does NOT
// carry the v1 "docker"/"kubepods" controller markers. Container
// detection must still fire on these hosts.
func TestDetectContainer_Cgroupv2DockerSelfCgroup(t *testing.T) {
	p := newProbe(probeStub{
		files: map[string]string{
			// v2 host: /proc/1/cgroup is just the unified line (no markers).
			"/proc/1/cgroup": "0::/\n",
			// the container's own cgroup path carries the docker scope.
			"/proc/self/cgroup": "0::/system.slice/docker-abc123.scope\n",
		},
	})
	if got := detectContainer(p); got != Container {
		t.Errorf("cgroup-v2 docker: got %s, want %s", got, Container)
	}
}

// Some cgroup-v2 runtimes (Podman/CRI-O, recent Docker) drop a
// /run/.containerenv marker; that is already handled, but a v2 host may
// instead surface only the kubepods scope in the unified hierarchy.
func TestDetectContainer_Cgroupv2Kubepods(t *testing.T) {
	p := newProbe(probeStub{
		files: map[string]string{
			"/proc/self/cgroup": "0::/kubepods.slice/kubepods-burstable.slice/abc.scope\n",
		},
	})
	if got := detectContainer(p); got != Container {
		t.Errorf("cgroup-v2 kubepods: got %s, want %s", got, Container)
	}
}

// Regression: the existing cgroup-v1 path (markers in /proc/1/cgroup)
// must keep working.
func TestDetectContainer_Cgroupv1StillDetected(t *testing.T) {
	p := newProbe(probeStub{
		files: map[string]string{
			"/proc/1/cgroup": "12:devices:/docker/abc123\n11:freezer:/docker/abc123\n",
		},
	})
	if got := detectContainer(p); got != Container {
		t.Errorf("cgroup-v1 docker: got %s, want %s", got, Container)
	}
}

// /.dockerenv (Docker's classic marker file) must be honoured.
func TestDetectContainer_DockerenvMarker(t *testing.T) {
	p := newProbe(probeStub{
		statOK: map[string]bool{"/.dockerenv": true},
	})
	if got := detectContainer(p); got != Container {
		t.Errorf("/.dockerenv: got %s, want %s", got, Container)
	}
}

// K8s env var still wins.
func TestDetectContainer_K8sEnvWins(t *testing.T) {
	p := newProbe(probeStub{k8sEnv: "10.0.0.1"})
	if got := detectContainer(p); got != K8s {
		t.Errorf("k8s env: got %s, want %s", got, K8s)
	}
}

// A genuine bare-metal / macOS host (no markers, no /proc) falls
// through to bare_metal.
func TestDetectContainer_BareMetal(t *testing.T) {
	p := newProbe(probeStub{
		files: map[string]string{
			// A bare host's /proc/self/cgroup has only innocuous slices.
			"/proc/self/cgroup": "0::/user.slice/user-1000.slice/session-1.scope\n",
		},
	})
	if got := detectContainer(p); got != BareMetal {
		t.Errorf("bare metal: got %s, want %s", got, BareMetal)
	}
}

// Defensive: a read error on /proc/self/cgroup must not panic.
func TestDetectContainer_ReadError(t *testing.T) {
	p := probes{
		getenv:   func(string) string { return "" },
		stat:     func(string) error { return os.ErrNotExist },
		readFile: func(string) ([]byte, error) { return nil, errors.New("boom") },
	}
	if got := detectContainer(p); got != BareMetal {
		t.Errorf("read error: got %s, want %s", got, BareMetal)
	}
}
