package runtimeversions

import (
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

const _maxBinaryScanBytes = 8 * 1024 * 1024 // bounded byte-scan of a web-server binary

var (
	_nginxVerRE  = regexp.MustCompile(`nginx/(\d+\.\d+[\w.]*)`)
	_apacheVerRE = regexp.MustCompile(`Apache/(\d+\.\d+[\w.]*)`)
)

// DetectAllWebServers walks each parent one level deep and classifies web
// servers by marker files. pkgVersion supplies an OS-package version when the
// server was installed via apt/yum; it returns "" when unknown, in which case
// the version is best-effort byte-scanned from the binary. IIS is handled by a
// platform-specific probe (webserver_windows.go), merged by the caller.
func DetectAllWebServers(ctx context.Context, parents []string, pkgVersion func(name string) string) []InstalledRuntime {
	seen := map[string]struct{}{}
	var out []InstalledRuntime
	consider := func(dir string) {
		clean := filepath.Clean(dir)
		if _, dup := seen[clean]; dup {
			return
		}
		if rt, ok := classifyWebServer(clean, pkgVersion); ok {
			seen[clean] = struct{}{}
			out = append(out, rt)
		}
	}
	for _, parent := range parents {
		if ctx.Err() != nil {
			return out
		}
		entries, err := safeio.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if d.IsDir() {
				consider(filepath.Join(parent, d.Name()))
			}
		}
	}
	return append(out, detectIIS()...) // no-op on non-windows (build-tagged)
}

func classifyWebServer(dir string, pkgVersion func(name string) string) (InstalledRuntime, bool) {
	switch {
	case isFile(filepath.Join(dir, "sbin", "nginx")) || isFile(filepath.Join(dir, "conf", "nginx.conf")) ||
		isFile(filepath.Join(dir, "nginx.conf")):
		ver := pkgVersion("nginx")
		if ver == "" {
			ver = scanBinaryVersion(filepath.Join(dir, "sbin", "nginx"), _nginxVerRE)
		}
		return mk("nginx", ver, "nginx", dir), true
	case isFile(filepath.Join(dir, "conf", "httpd.conf")) ||
		isFile(filepath.Join(dir, "conf", "apache2.conf")) ||
		isFile(filepath.Join(dir, "httpd.conf")) || isFile(filepath.Join(dir, "apache2.conf")) ||
		isFile(filepath.Join(dir, "httpd")) || isFile(filepath.Join(dir, "apache2")):
		ver := pkgVersion("httpd")
		if ver == "" {
			ver = pkgVersion("apache2")
		}
		if ver == "" {
			ver = scanBinaryVersion(filepath.Join(dir, "httpd"), _apacheVerRE)
		}
		if ver == "" {
			ver = scanBinaryVersion(filepath.Join(dir, "apache2"), _apacheVerRE)
		}
		return mk("apache-httpd", ver, "Apache", dir), true
	}
	return InstalledRuntime{}, false
}

// scanBinaryVersion reads an ELF/PE binary in bounded chunks (never executes it)
// and returns the first regex capture, or "" if none. Reuses safeio.Open's
// symlink-refusing, TOCTOU-safe fd (same discipline as jarImplementationVersion).
func scanBinaryVersion(path string, re *regexp.Regexp) string {
	f, err := safeio.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return ""
	}
	size := info.Size()
	if size > _maxBinaryScanBytes {
		size = _maxBinaryScanBytes
	}
	buf := make([]byte, size)
	// io.ReadFull is short-read-safe: it returns the actual byte count even
	// on a partial read (io.EOF/io.ErrUnexpectedEOF), unlike a single Read
	// whose short reads are legal and would silently drop data.
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}
	if m := re.FindSubmatch(buf[:n]); m != nil {
		// [\w.]* is greedy over the character class, so trailing binary
		// noise made of literal dots (e.g. "1.25.3...") would otherwise
		// be captured; trim it back to the version token.
		return strings.TrimRight(string(m[1]), ".")
	}
	return ""
}
