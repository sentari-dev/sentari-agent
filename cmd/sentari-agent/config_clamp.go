//go:build enterprise

package main

import (
	"runtime"
	"strings"
)

// Sane bounds for server-pushed scanner parameters.  A hostile or
// misconfigured server must not be able to drive the agent into a
// pathological state: a too-small interval hammers the server, a
// too-large one means the agent effectively never scans, and an
// unbounded max_depth lets a deep/looping directory tree blow up
// memory and CPU.  The agent always clamps into these ranges before
// applying a polled value (scan_root is validated separately).
const (
	minScanIntervalSeconds = 60    // 1 minute  — floor against hammering
	maxScanIntervalSeconds = 86400 // 24 hours  — ceiling against never-scanning
	maxScannerDepth        = 64    // cap against resource blowup on deep trees
)

// clampScanIntervalSeconds bounds a server-supplied scan_interval (in
// seconds) into [minScanIntervalSeconds, maxScanIntervalSeconds].  The
// caller only invokes this for strictly-positive values, but the floor
// also defends against any non-positive slipping through.
func clampScanIntervalSeconds(secs int) int {
	if secs < minScanIntervalSeconds {
		return minScanIntervalSeconds
	}
	if secs > maxScanIntervalSeconds {
		return maxScanIntervalSeconds
	}
	return secs
}

// clampMaxDepth bounds a server-supplied scanner max_depth into
// [1, maxScannerDepth].  Depth must be at least 1 to scan anything at
// all and is capped to keep filesystem walks bounded.
func clampMaxDepth(depth int) int {
	if depth < 1 {
		return 1
	}
	if depth > maxScannerDepth {
		return maxScannerDepth
	}
	return depth
}

// isScanRootDenied returns true if the given path is in the denylist of
// sensitive directories that must not be used as a scan root.  This prevents
// a compromised server from directing the agent to exfiltrate filesystem
// layout information via scan errors.
func isScanRootDenied(cleaned string) bool {
	return scanRootDeniedForOS(cleaned, runtime.GOOS)
}

// scanRootDeniedForOS is the OS-parameterised core of isScanRootDenied,
// split out so both the POSIX and Windows branches are unit-testable on any
// build host.
func scanRootDeniedForOS(cleaned, goos string) bool {
	if goos == "windows" {
		// Windows system trees.  Both the candidate and the denied prefixes
		// are folded to lowercase forward-slash form before comparison: NTFS
		// is case-insensitive, and the path may arrive with either separator
		// (the scanner now normalises payload paths to '/', but an operator
		// config or flag may still use '\').
		norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }
		denied := []string{
			`C:\Windows`,
			`C:\Program Files`,
			`C:\Program Files (x86)`,
			`C:\ProgramData`,
		}
		lc := norm(cleaned)
		for _, prefix := range denied {
			lp := norm(prefix)
			if lc == lp || strings.HasPrefix(lc, lp+"/") {
				return true
			}
		}
		return false
	}
	denied := []string{"/etc", "/root", "/home", "/proc", "/sys", "/var/log", "/dev", "/run"}
	for _, prefix := range denied {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
			return true
		}
	}
	return false
}
