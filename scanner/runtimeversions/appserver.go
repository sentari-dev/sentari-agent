package runtimeversions

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const _maxVersionFileBytes = 64 * 1024

// _versionTokenRE pulls the first dotted version token out of a free-form
// "… - Version 40.0.1.Final" / "jetty-12.0.5 - …" style line.
var _versionTokenRE = regexp.MustCompile(`(\d+\.\d+[\w.]*)`)

// envHomes are server homes operators set explicitly; each points AT an
// install (not a parent), so it is classified directly.
var _envHomeVars = []string{
	"WILDFLY_HOME", "JBOSS_HOME", "EAP_HOME",
	"CATALINA_HOME", "CATALINA_BASE", "JETTY_HOME", "WL_HOME",
}

// DetectAllAppServers walks each parent one level deep, classifies every
// child directory by marker, and also classifies explicit env-var homes.
// Returns one InstalledRuntime per identified install. Best-effort: an
// unreadable candidate is skipped, never fatal.
func DetectAllAppServers(parents []string) []InstalledRuntime {
	seen := map[string]struct{}{}
	var out []InstalledRuntime

	consider := func(dir string) {
		clean := filepath.Clean(dir)
		if _, dup := seen[clean]; dup {
			return
		}
		if rt, ok := classify(clean); ok {
			seen[clean] = struct{}{}
			out = append(out, rt)
		}
	}

	for _, v := range _envHomeVars {
		if h := os.Getenv(v); h != "" {
			consider(h)
		}
	}
	for _, parent := range parents {
		entries, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if d.IsDir() {
				consider(filepath.Join(parent, d.Name()))
			}
		}
	}
	return out
}

// classify identifies the app server rooted at dir (if any) and extracts
// its version. Order matters: JBoss/WildFly first (most specific markers).
func classify(dir string) (InstalledRuntime, bool) {
	switch {
	case isFile(filepath.Join(dir, "version.txt")) &&
		(isFile(filepath.Join(dir, "bin/standalone.sh")) || isFile(filepath.Join(dir, "bin/standalone.bat"))):
		name := "wildfly"
		distro := "Red Hat"
		if slot := readSlot(filepath.Join(dir, "bin/product.conf")); slot == "eap" {
			name = "jboss-eap"
		}
		ver := parseVersionToken(readText(filepath.Join(dir, "version.txt")))
		return mk(name, ver, distro, dir), true

	case isFile(filepath.Join(dir, "lib/catalina.jar")):
		ver := jarImplementationVersion(filepath.Join(dir, "lib/catalina.jar"))
		return mk("tomcat", ver, "Apache", dir), true

	case isFile(filepath.Join(dir, "VERSION.txt")) &&
		strings.HasPrefix(strings.ToLower(readText(filepath.Join(dir, "VERSION.txt"))), "jetty-"):
		ver := parseVersionToken(readText(filepath.Join(dir, "VERSION.txt")))
		return mk("jetty", ver, "Eclipse", dir), true

	case isFile(filepath.Join(dir, "glassfish/config/branding/glassfish-version.properties")):
		ver := parseVersionToken(readText(filepath.Join(dir, "glassfish/config/branding/glassfish-version.properties")))
		return mk("payara", ver, "Payara", dir), true
	}
	return InstalledRuntime{}, false
}

func mk(name, version, distro, dir string) InstalledRuntime {
	if version == "" {
		version = "unknown"
	}
	return InstalledRuntime{
		Name:        name,
		Version:     version,
		Cycle:       CycleFor(name, version),
		Distro:      distro,
		InstallPath: dir,
	}
}

func parseVersionToken(s string) string {
	if m := _versionTokenRE.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func readSlot(path string) string {
	for _, line := range strings.Split(readText(path), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "slot=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "slot="))
		}
	}
	return ""
}

func readText(path string) string {
	b, err := safeio.ReadFile(path, _maxVersionFileBytes)
	if err != nil {
		return ""
	}
	return string(b)
}

func isFile(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode().IsRegular()
}

// jarImplementationVersion reads META-INF/MANIFEST.MF Implementation-Version
// from a JAR without executing anything. safeio guards the open against
// symlinks; archive/zip reads entries lazily.
func jarImplementationVersion(jarPath string) string {
	if _, err := safeio.ReadFile(jarPath, 1); err != nil && errors.Is(err, safeio.ErrSymlink) {
		return ""
	}
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return ""
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return ""
		}
		defer rc.Close()
		buf := make([]byte, 16*1024)
		n, _ := rc.Read(buf)
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if strings.HasPrefix(line, "Implementation-Version:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Implementation-Version:"))
			}
		}
	}
	return ""
}
