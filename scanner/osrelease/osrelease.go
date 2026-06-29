// Package osrelease parses /etc/os-release to identify the host's Linux
// distribution and release. The server uses this to derive a release-keyed
// CVE partition (e.g. debian:12) for OS packages (apt/yum CVE-correctness
// slice). Pure-Go, size-capped, no binary invocation.
package osrelease

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// osReleasePath is the standard location; var so tests can override it.
var osReleasePath = "/etc/os-release"

// maxOSReleaseSize bounds the read — a real os-release file is < 1 KiB; the
// cap defends against a hostile symlink to a huge file.
const maxOSReleaseSize = 64 * 1024

// fieldCap bounds each parsed value so a malformed file can't hand the server
// an unbounded ID/VERSION_ID string.
const fieldCap = 64

// Result is the distro identity extracted from /etc/os-release.
type Result struct {
	ID        string
	VersionID string
}

// Detect reads and parses /etc/os-release. It returns ok=false (and a zero
// Result) when the file is absent/unreadable or contains no usable ID — the
// caller then omits os_release from the scan payload, and the server falls
// back to a release-less sentinel partition. Never returns an error: distro
// detection is best-effort and must never fail a scan.
func Detect() (Result, bool) {
	data, err := safeio.ReadFile(osReleasePath, maxOSReleaseSize)
	if err != nil {
		return Result{}, false
	}
	return parse(data)
}

func parse(data []byte) (Result, bool) {
	var res Result
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ID":
			res.ID = clean(val)
		case "VERSION_ID":
			res.VersionID = clean(val)
		}
	}
	// ID is the load-bearing field; without it the server can't pick a
	// distro, so report "not detected".
	if res.ID == "" {
		return Result{}, false
	}
	return res, true
}

// clean strips surrounding quotes/whitespace, lowercases, and bounds length —
// os-release values are often quoted ("22.04") and we want a canonical token.
func clean(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) > fieldCap {
		v = v[:fieldCap]
	}
	return v
}
