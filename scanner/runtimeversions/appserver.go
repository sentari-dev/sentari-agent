package runtimeversions

import (
	"archive/zip"
	"context"
	"io"
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
	"CATALINA_HOME", "CATALINA_BASE", "JETTY_HOME", "WL_HOME", "WAS_HOME",
}

// DetectAllAppServers walks each parent one level deep, classifies every
// child directory by marker, and also classifies explicit env-var homes.
// Returns one InstalledRuntime per identified install. Best-effort: an
// unreadable candidate is skipped, never fatal.
func DetectAllAppServers(ctx context.Context, parents []string) []InstalledRuntime {
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
		if ctx.Err() != nil {
			return out
		}
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

	case isFile(filepath.Join(dir, "start.jar")) ||
		isFile(filepath.Join(dir, "etc/jetty.xml")) ||
		isFile(filepath.Join(dir, "etc/jetty-http.xml")) ||
		(isFile(filepath.Join(dir, "VERSION.txt")) &&
			strings.HasPrefix(strings.ToLower(readText(filepath.Join(dir, "VERSION.txt"))), "jetty-")):
		ver := parseVersionToken(readText(filepath.Join(dir, "VERSION.txt")))
		if ver == "" {
			ver = jettyVersionFromLib(dir)
		}
		return mk("jetty", ver, "Eclipse", dir), true

	case isFile(filepath.Join(dir, "glassfish/config/branding/glassfish-version.properties")):
		// Payara is a fork of Eclipse GlassFish and ships the SAME branding
		// file, so its presence alone cannot tell the two apart — keying
		// "payara" off it mislabels a stock Eclipse GlassFish install. Read
		// the product name from the branding file (Payara sets a "Payara …"
		// product name; upstream sets "Eclipse GlassFish") and fall back to a
		// Payara-only module jar before assigning the Payara identity.
		branding := readText(filepath.Join(dir, "glassfish/config/branding/glassfish-version.properties"))
		ver := parseVersionToken(branding)
		if isPayaraInstall(dir, branding) {
			return mk("payara", ver, "Payara", dir), true
		}
		return mk("glassfish", ver, "Eclipse GlassFish", dir), true

	// WebLogic / WebSphere — presence-only (no public EOL feed). Markers mirror
	// the jvm package's discovery. Version is best-effort: WebLogic exposes it in
	// the weblogic.jar manifest; WebSphere needs versionInfo (a binary), which we
	// won't run, so it stays "unknown" (presence still recorded).
	case isFile(filepath.Join(dir, "server/lib/weblogic.jar")) ||
		isFile(filepath.Join(dir, "server/bin/startWebLogic.sh")) ||
		isFile(filepath.Join(dir, "server/bin/startWebLogic.cmd")):
		ver := jarImplementationVersion(filepath.Join(dir, "server/lib/weblogic.jar"))
		return mk("weblogic", ver, "Oracle", dir), true

	case isFile(filepath.Join(dir, "bin/versionInfo.sh")) ||
		isFile(filepath.Join(dir, "bin/versionInfo.bat")):
		return mk("websphere", "", "IBM", dir), true
	}
	return InstalledRuntime{}, false
}

// isPayaraInstall distinguishes a Payara install from an upstream Eclipse
// GlassFish install. Both ship glassfish/config/branding/glassfish-version.
// properties (Payara is a GlassFish fork), so the branding file's presence is
// not sufficient. Two signals identify Payara: (a) a Payara-specific product
// name in the branding properties — upstream sets product_name/
// abbrev_product_name to "Eclipse GlassFish"/"GlassFish", Payara sets a
// "Payara …" value; or (b) a Payara-only module jar under glassfish/modules
// (e.g. payara-micro-*.jar, payara-boot-*.jar). Reads files only — never runs
// a binary.
func isPayaraInstall(dir, branding string) bool {
	for _, line := range strings.Split(branding, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(strings.ToLower(key)) {
		case "product_name", "abbrev_product_name":
			if strings.Contains(strings.ToLower(val), "payara") {
				return true
			}
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "glassfish", "modules", "payara-*.jar"))
	return len(matches) > 0
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

// jettyVersionFromLib extracts the version from lib/jetty-server-<ver>.jar
// when VERSION.txt is absent (modern jetty-home distributions don't always
// ship it). Returns "" if no such jar is found. Reads the filename only —
// no file contents — so no version-file parsing is needed.
func jettyVersionFromLib(dir string) string {
	matches, err := filepath.Glob(filepath.Join(dir, "lib", "jetty-server-*.jar"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	base := filepath.Base(matches[0])
	base = strings.TrimPrefix(base, "jetty-server-")
	base = strings.TrimSuffix(base, ".jar")
	return base
}

// jarImplementationVersion reads META-INF/MANIFEST.MF Implementation-Version
// from a JAR without executing anything. The path is opened exactly once via
// safeio.Open (which refuses a symlink or non-regular leaf at the fd), and the
// zip is read through that same fd with zip.NewReader — no path re-open — so a
// symlink/FIFO can't be swapped in between a probe and the open (TOCTOU).
func jarImplementationVersion(jarPath string) string {
	f, err := safeio.Open(jarPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return ""
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return ""
	}
	for _, zf := range zr.File {
		if zf.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return ""
		}
		// io.ReadFull is short-read-safe: it returns the actual byte count
		// even on a truncated/partial manifest (ErrUnexpectedEOF), unlike a
		// single Read whose short reads are legal and would drop data.
		buf := make([]byte, 16*1024)
		n, _ := io.ReadFull(rc, buf)
		rc.Close()
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if strings.HasPrefix(line, "Implementation-Version:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Implementation-Version:"))
			}
		}
		return ""
	}
	return ""
}
