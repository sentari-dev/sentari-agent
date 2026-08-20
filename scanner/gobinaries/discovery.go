package gobinaries

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// layoutBinDir is carried on Environment.Name so Scan dispatches through one
// walk strategy. A single layout today, but the tag keeps dispatch explicit
// and mirrors the JVM plugin's layout-tag convention.
const layoutBinDir = "bin-dir"

// Discovery roots are package-level vars so tests can substitute fixture
// trees (the JVM discovery precedent). systemDirectRoots are scanned as-is;
// optStyleParents are one-level parents under which each existing <child>/bin
// becomes an Environment. Both exclude distro-managed trees (/usr/bin, /bin,
// …): those binaries are already inventoried as OS packages with release-keyed
// CVE correlation, so re-walking them to expose module interiors is cost for
// the managed half of the estate. GOPATH/HOME go-bin roots are resolved at
// DiscoverAll time (they depend on env vars).
var (
	systemDirectRoots = initSystemDirectRoots()
	optStyleParents   = initOptStyleParents()
)

func initSystemDirectRoots() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/usr/local/bin", "/usr/local/sbin"}
	case "darwin":
		// Apple-Silicon Homebrew installs under /opt/homebrew/bin — the same
		// gap that once hid Node runtimes from detection.
		return []string{"/usr/local/bin", "/opt/homebrew/bin"}
	default:
		return nil
	}
}

func initOptStyleParents() []string {
	switch runtime.GOOS {
	case "linux", "darwin":
		return []string{"/opt"}
	case "windows":
		return []string{
			`C:\Program Files`,
			`C:\Program Files (x86)`,
		}
	default:
		return nil
	}
}

// DiscoverAll returns one Environment per existing well-known unmanaged-install
// binary directory: the fixed system roots, each <child>/bin under the
// opt-style parents, and the Go install-target bin ($GOPATH/bin, else
// $HOME/go/bin). Paths are cleaned and de-duplicated so overlapping roots
// collapse; the orchestrator additionally dedups across all RootScanners.
func (Scanner) DiscoverAll(ctx context.Context) ([]scanner.Environment, []scanner.ScanError) {
	_ = ctx
	var envs []scanner.Environment
	seen := map[string]struct{}{}

	emit := func(dir string) {
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if _, dup := seen[clean]; dup {
			return
		}
		if !isDir(clean) {
			return
		}
		seen[clean] = struct{}{}
		envs = append(envs, scanner.Environment{
			EnvType: EnvGoBinary,
			Name:    layoutBinDir,
			Path:    clean,
		})
	}

	for _, root := range systemDirectRoots {
		emit(root)
	}

	for _, parent := range optStyleParents {
		entries, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if !d.IsDir() {
				continue
			}
			emit(filepath.Join(parent, d.Name(), "bin"))
		}
	}

	emit(goInstallBin())

	return envs, nil
}

// goInstallBin resolves the directory `go install` writes binaries to:
// $GOPATH/bin when GOPATH is set (first entry of a list), otherwise
// $HOME/go/bin (the module-era default). Returns "" when neither can be
// resolved (minimal CI containers).
func goInstallBin() string {
	if gp := os.Getenv("GOPATH"); gp != "" {
		// GOPATH may be a list; the first entry is the install target.
		first := gp
		if idx := indexPathList(gp); idx >= 0 {
			first = gp[:idx]
		}
		if first != "" {
			return filepath.Join(first, "bin")
		}
	}
	if home := userHome(); home != "" {
		return filepath.Join(home, "go", "bin")
	}
	return ""
}

// indexPathList returns the index of the first OS path-list separator in s,
// or -1 if none.
func indexPathList(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == os.PathListSeparator {
			return i
		}
	}
	return -1
}

// userHome resolves the user's home directory from the platform-appropriate
// env var only (USERPROFILE on Windows, else HOME). Deliberately not
// os.UserHomeDir, which can resolve a service UID to an unexpected home.
func userHome() string {
	if runtime.GOOS == "windows" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			return up
		}
	}
	return os.Getenv("HOME")
}

// isDir reports whether path exists and is a directory.
func isDir(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.IsDir()
}
