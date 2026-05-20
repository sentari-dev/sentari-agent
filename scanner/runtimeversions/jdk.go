package runtimeversions

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
		Name:        "jdk",
		Version:     javaVersion,
		Cycle:       CycleFor("jdk", javaVersion),
		Distro:      parseJDKDistroFromImplementor(implementor),
		InstallPath: dir,
	}, nil
}

// DetectAllJDKs walks a set of candidate roots looking for JDK installs.
// Each candidate that contains a `release` file is treated as one JDK.
// Depth is capped at _defaultJDKWalkDepth levels below each root.
func DetectAllJDKs(roots []string) []InstalledRuntime {
	return detectAllJDKsWithDepth(roots, _defaultJDKWalkDepth)
}

func detectAllJDKsWithDepth(roots []string, maxDepth int) []InstalledRuntime {
	var out []InstalledRuntime
	for _, root := range roots {
		rootClean := filepath.Clean(root)
		_ = filepath.WalkDir(rootClean, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
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
