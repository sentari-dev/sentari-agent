package osrelease

import (
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// procKernelOsreleasePath and procVersionPath are the Linux data-file sources
// for the kernel release. Both are vars so tests can override them and exercise
// the parse/cap/sanitize logic on any platform (mirrors the osReleasePath seam).
var (
	procKernelOsreleasePath = "/proc/sys/kernel/osrelease"
	procVersionPath         = "/proc/version"
)

// maxKernelFileSize bounds the read of the /proc sources. A real kernel-release
// line is < 100 bytes; the small cap defends against a hostile mount pointing a
// source at a huge file.
const maxKernelFileSize = 4 * 1024

// readLinuxKernel returns the running kernel release (the uname -r string) read
// from /proc data files — it never invokes uname. Primary source is
// /proc/sys/kernel/osrelease (a single line equal to uname -r); if that is
// unreadable (e.g. a hardened /proc mount) it falls back to parsing the release
// token out of /proc/version. Best-effort: ok=false on any failure, never an
// error. OS-independent (paths come from seams) so its logic is unit-testable
// on any platform, not only Linux.
func readLinuxKernel() (string, bool) {
	if data, err := safeio.ReadFile(procKernelOsreleasePath, maxKernelFileSize); err == nil {
		if k, ok := sanitizeKernel(string(data)); ok {
			return k, true
		}
	}
	if data, err := safeio.ReadFile(procVersionPath, maxKernelFileSize); err == nil {
		if k, ok := parseProcVersion(data); ok {
			return k, true
		}
	}
	return "", false
}

// parseProcVersion extracts the kernel release from a /proc/version line of the
// form "Linux version <release> (builder@host) ...". It returns ok=false when
// the line lacks the "Linux version " prefix or has no release token.
func parseProcVersion(data []byte) (string, bool) {
	line := strings.TrimSpace(string(data))
	const prefix = "Linux version "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	field, _, _ := strings.Cut(strings.TrimSpace(line[len(prefix):]), " ")
	return sanitizeKernel(field)
}

// sanitizeKernel trims surrounding whitespace, rejects any embedded control
// byte (a hostile data source must not smuggle raw bytes into the scan
// payload), and caps the length at fieldCap. It returns ok=false for an
// empty/whitespace value or one containing control bytes.
func sanitizeKernel(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	if len(v) > fieldCap {
		v = v[:fieldCap]
	}
	return v, true
}
