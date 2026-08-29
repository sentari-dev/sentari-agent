//go:build darwin

package hardening

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/hardening/plist"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// systemVersionPath is the macOS product-version plist. A var so tests can
// repoint it.
var systemVersionPath = "/System/Library/CoreServices/SystemVersion.plist"

// darwinMajorVersion reads ProductVersion from SystemVersion.plist and returns
// its major component (e.g. 14 for "14.5"). Returns 0 when unknown — the
// firewall collector treats <15 as "ALF plist authoritative", so an unknown
// version conservatively still reads the plist. It never invokes sw_vers.
func darwinMajorVersion() (major int) {
	// darwinMajorVersion runs from defaultDarwinPaths() BEFORE any per-collector
	// guard() is entered, so a crafted SystemVersion.plist that panicked the
	// parser would abort the whole hardening pass (and, via Collect, the scan).
	// The binary parser is now panic-free by contract; this recover is
	// defence-in-depth so a future parser regression degrades to "version
	// unknown" (0) instead of taking down the scan.
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("hardening: SystemVersion.plist parse panicked; treating OS version as unknown", "panic", r)
			major = 0
		}
	}()
	b, err := safeio.ReadFile(systemVersionPath, maxPlistFileSize)
	if err != nil {
		return 0
	}
	root, err := plist.Parse(b)
	if err != nil {
		return 0
	}
	ver, ok := plist.String(root, "ProductVersion")
	if !ok {
		return 0
	}
	m, _, _ := strings.Cut(ver, ".")
	n, err := strconv.Atoi(strings.TrimSpace(m))
	if err != nil {
		return 0
	}
	return n
}
