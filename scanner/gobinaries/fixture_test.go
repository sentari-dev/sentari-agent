package gobinaries

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// The fixture module (testdata/fixturemod) is a stdlib-only Go program with a
// single dependency satisfied by a local replace directive. Building it with
// the host toolchain yields a real Go binary whose embedded module metadata
// the probe/scan tests read back. The build is hermetic — GOPROXY=off and a
// local replace mean no network — and cached once per GOOS per test binary.

// Values the fixture binary embeds (verified against `go version -m`):
//   - main module example.com/fixturemod at version "(devel)" (built with
//     -buildvcs=false, so no vcs.revision to substitute)
//   - dependency example.com/fakedep, replaced by the local directory; the
//     toolchain records the replacement path "./fakedep" at version "(devel)"
const (
	fixtureMainModule    = "example.com/fixturemod"
	fixtureReplacePath   = "./fakedep"
	fixtureModuleVersion = "(devel)"
)

type builtFixture struct {
	path string
	err  error
}

var (
	fixtureMu    sync.Mutex
	fixtureCache = map[string]builtFixture{}
)

// buildFixtureBinary builds testdata/fixturemod for the requested GOOS into a
// process-lifetime temp dir and returns the binary path. Cross-GOOS builds
// (stdlib-only) need no cgo and parse on any host. Skips the whole test when
// no go toolchain is available.
func buildFixtureBinary(t *testing.T, goos string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available; skipping fixture build")
	}

	fixtureMu.Lock()
	defer fixtureMu.Unlock()
	if bf, ok := fixtureCache[goos]; ok {
		if bf.err != nil {
			t.Fatalf("cached fixture build for %s failed: %v", goos, bf.err)
		}
		return bf.path
	}

	outDir, err := os.MkdirTemp("", "gobinfixture-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	outName := "fixturebin"
	if goos == "windows" {
		outName += ".exe"
	}
	outPath := filepath.Join(outDir, outName)

	moduleDir, err := filepath.Abs(filepath.Join("testdata", "fixturemod"))
	if err != nil {
		t.Fatalf("abs module dir: %v", err)
	}

	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", outPath, ".")
	cmd.Dir = moduleDir
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOPROXY=off",
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=0",
	)
	out, buildErr := cmd.CombinedOutput()
	if buildErr != nil {
		fixtureCache[goos] = builtFixture{err: buildErr}
		t.Fatalf("build fixture for %s failed: %v\n%s", goos, buildErr, out)
	}
	fixtureCache[goos] = builtFixture{path: outPath}
	return outPath
}

// hostFixtureBinary builds the fixture for the current GOOS.
func hostFixtureBinary(t *testing.T) string {
	t.Helper()
	return buildFixtureBinary(t, runtime.GOOS)
}
