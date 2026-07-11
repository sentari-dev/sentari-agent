package runtimeversions

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const maxReleaseFileBytes = 64 * 1024

// _defaultJDKWalkDepth caps how deep DetectAllJDKs descends below each
// candidate root. JDKs live at depth 1 (`/usr/lib/jvm/<jdk>/release`)
// or 2 (`/opt/<vendor>/<jdk>/release`). A cap of 4 keeps the walk cheap
// on hosts with deep container/volume mounts under /opt or /srv while
// still finding every real-world layout we know about.
const _defaultJDKWalkDepth = 4

// DetectJDKInDir reads <dir>/release and produces an InstalledRuntime
// if the file exists + parses. Returns (nil, nil) when no release
// file is found (the dir isn't a JDK install).
func DetectJDKInDir(dir string) (*InstalledRuntime, error) {
	releasePath := filepath.Join(dir, "release")
	raw, err := safeio.ReadFile(releasePath, maxReleaseFileBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, safeio.ErrSymlink) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", releasePath, err)
	}
	javaVersion, implementor := parseJDKReleaseFile(raw)
	if javaVersion == "" {
		return nil, nil
	}
	return &InstalledRuntime{
		Name:        RuntimeJDK,
		Version:     javaVersion,
		Cycle:       CycleFor(RuntimeJDK, javaVersion),
		Distro:      parseJDKDistroFromImplementor(implementor),
		InstallPath: dir,
	}, nil
}

// homebrewJDKCellarRoots are the Homebrew Cellar parents under which the
// `openjdk` (and versioned `openjdk@NN`) formulae install on macOS.
var homebrewJDKCellarRoots = []string{
	"/opt/homebrew/Cellar", // Apple Silicon Homebrew
	"/usr/local/Cellar",    // Intel Homebrew
}

// homebrewJDKHomeSubpath is the fixed path from a Homebrew openjdk keg's
// version directory down to the JDK home that holds the `release` file:
// <cellar>/openjdk[@NN]/<version>/libexec/openjdk.jdk/Contents/Home/release.
var homebrewJDKHomeSubpath = filepath.Join("libexec", "openjdk.jdk", "Contents", "Home")

// DetectAllJDKs walks a set of candidate roots looking for JDK installs.
// Each candidate that contains a `release` file is treated as one JDK.
// Depth is capped at _defaultJDKWalkDepth levels below each root.
//
// Homebrew-installed OpenJDK is handled separately: `brew install openjdk`
// buries the release file at
// <cellar>/openjdk/<version>/libexec/openjdk.jdk/Contents/Home/release —
// eight levels below the Cellar root, far below the walk depth cap, and not
// reachable from the /opt candidate root.  The `brew link` caveat symlink at
// /Library/Java/JavaVirtualMachines/openjdk.jdk is also skipped by the
// symlink guard in the walk, so that route is dead too.  A dedicated Cellar
// reader probes the fixed keg sub-path directly, mirroring detectHomebrewPythons.
func DetectAllJDKs(ctx context.Context, roots []string) []InstalledRuntime {
	out := detectAllJDKsWithDepth(ctx, roots, _defaultJDKWalkDepth)
	out = append(out, detectHomebrewJDKs(homebrewJDKCellarRoots)...)
	return out
}

// detectHomebrewJDKs enumerates <root>/openjdk*/<version>/ under each Homebrew
// Cellar root and probes the fixed libexec/openjdk.jdk/Contents/Home/release
// sub-path for every keg version, emitting one InstalledRuntime per JDK found.
// Non-existent roots (e.g. on Linux, or Intel paths on Apple Silicon) are
// silently skipped.  Symlinked keg entries are skipped by the IsDir() check
// (a symlink DirEntry reports IsDir()==false), keeping the reader in step with
// the scanner's symlink-refusing posture.
func detectHomebrewJDKs(roots []string) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		formulae, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, formula := range formulae {
			name := formula.Name()
			// `openjdk`, `openjdk@17`, `openjdk@21`, `openjdk@11`, `openjdk@8`, …
			if !formula.IsDir() || (name != "openjdk" && !strings.HasPrefix(name, "openjdk@")) {
				continue
			}
			versions, err := os.ReadDir(filepath.Join(root, name))
			if err != nil {
				continue
			}
			for _, ver := range versions {
				if !ver.IsDir() {
					continue
				}
				home := filepath.Join(root, name, ver.Name(), homebrewJDKHomeSubpath)
				rt, derr := DetectJDKInDir(home)
				if derr != nil || rt == nil {
					continue
				}
				out = append(out, *rt)
			}
		}
	}
	return out
}

func detectAllJDKsWithDepth(ctx context.Context, roots []string, maxDepth int) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		if ctx.Err() != nil {
			return out
		}
		rootClean := filepath.Clean(root)
		_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			if pathfilter.ShouldSkipDir(path) {
				return filepath.SkipDir
			}
			// Depth cap — measured in path separators below rootClean.
			if path != rootClean {
				rel, rerr := filepath.Rel(rootClean, path)
				if rerr == nil {
					if strings.Count(rel, string(filepath.Separator))+1 > maxDepth {
						return filepath.SkipDir
					}
				}
			}
			rt, derr := DetectJDKInDir(path)
			if derr != nil || rt == nil {
				return nil
			}
			out = append(out, *rt)
			return filepath.SkipDir
		})
	}
	return out
}

func parseJDKReleaseFile(raw []byte) (javaVersion, implementor string) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "JAVA_VERSION=") {
			javaVersion = strings.Trim(strings.TrimPrefix(line, "JAVA_VERSION="), "\"")
		} else if strings.HasPrefix(line, "IMPLEMENTOR=") {
			implementor = strings.Trim(strings.TrimPrefix(line, "IMPLEMENTOR="), "\"")
		}
	}
	return javaVersion, implementor
}

// parseJDKDistroFromImplementor maps the IMPLEMENTOR string to a
// canonical distro name. Unknown vendors pass through unchanged so
// the dashboard can surface whatever the JDK reports.
func parseJDKDistroFromImplementor(impl string) string {
	switch {
	case impl == "":
		return ""
	case strings.Contains(impl, "Adoptium") || strings.Contains(impl, "AdoptOpenJDK"):
		return "Temurin"
	case strings.Contains(impl, "Amazon"):
		return "Corretto"
	case strings.Contains(impl, "Azul"):
		return "Zulu"
	case strings.Contains(impl, "Microsoft"):
		return "Microsoft"
	case strings.Contains(impl, "Oracle"):
		return "Oracle"
	default:
		return impl
	}
}
