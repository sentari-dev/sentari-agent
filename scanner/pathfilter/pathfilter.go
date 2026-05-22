// Package pathfilter classifies filesystem paths so the agent can skip
// directories that are slow, semantically empty, or both.  Two
// distinct exclusions live here:
//
//  1. Cloud-synced paths (iCloud Drive, OneDrive, Dropbox, Google Drive).
//     Reading these triggers on-demand downloads from the cloud
//     provider and a single venv discovery can stall for tens of
//     minutes.  Scanning a Python venv that lives inside iCloud also
//     produces no real fleet-wide signal — operators never deploy
//     workloads onto cloud-synced trees.  Skipped unconditionally by
//     all runtime walkers; no flag to re-enable (operators with a
//     legitimate cloud-mounted runtime should mount it locally first).
//
//  2. Network-mounted paths (NFS, SMB/CIFS, WebDAV, AutoFS, FUSE
//     remotes).  Walking these introduces network latency and may
//     pick up envs that belong to a different device.  Opt-in only:
//     the agent's ``--exclude-network-paths`` CLI flag flips
//     ``ExcludeNetworkPaths`` so the walkers consult
//     ``IsNetworkFilesystem`` and skip matches.
//
// Both classifiers return false on errors so a misconfigured host
// never silently drops legitimate scan coverage.
package pathfilter

import (
	"path/filepath"
	"runtime"
	"strings"
)

// ExcludeNetworkPaths is the package-level toggle that the runtime
// walkers consult.  Default false (matches existing behaviour: scan
// everything).  The agent CLI sets this to true when the operator
// passes --exclude-network-paths.  Module-level state rather than
// per-call config so the dozen+ walk sites don't need their signatures
// changed — the flag is read-only after process startup.
var ExcludeNetworkPaths bool

// ShouldSkipDir returns true when a walker should ``filepath.SkipDir``
// at ``path``.  Combines both exclusions so each walker site is a
// single call instead of repeating the cloud-then-network ladder.
//
// Cheap when both exclusions are off: a cloud-path prefix check on
// darwin only and a constant ``false`` everywhere else.  The
// network-FS branch only fires when an operator opted in via
// --exclude-network-paths, since IsNetworkFilesystem syscalls per
// path.  Tests assert short-circuit behaviour matches this contract.
func ShouldSkipDir(path string) bool {
	if IsCloudSyncedPath(path) {
		return true
	}
	if ExcludeNetworkPaths {
		if isNet, _ := IsNetworkFilesystem(path); isNet {
			return true
		}
	}
	return false
}

// cloudPathPrefixes lists absolute path prefixes that indicate a
// cloud-synced filesystem on macOS.  Other operating systems do not
// have analogous standardised locations: Windows cloud sync clients
// store mount points under per-vendor paths, and Linux has none.
//
// The slice is consulted with the cleaned, absolute path — relative
// paths return false.
var cloudPathPrefixes = []string{
	// iCloud Drive (Apple): every file outside the "Downloads" folder
	// is dataless by default and the kernel pulls it on first read.
	"/Users/_/Library/Mobile Documents/",
	// Modern (Big Sur+) third-party cloud providers — Dropbox,
	// OneDrive, Google Drive — register a virtual file provider
	// under ~/Library/CloudStorage/<Provider>-<account>/.
	"/Users/_/Library/CloudStorage/",
}

// IsCloudSyncedPath reports whether absPath sits inside a known
// cloud-synced location.  The check is a cheap path-prefix test —
// nothing here touches the filesystem.  Falsey for relative paths.
func IsCloudSyncedPath(absPath string) bool {
	if runtime.GOOS != "darwin" {
		// Reserved for future per-OS extension.  Returning false here
		// preserves existing scan coverage; opt-in network exclusion
		// remains the catch-all for other platforms.
		return false
	}
	if absPath == "" || !filepath.IsAbs(absPath) {
		return false
	}
	clean := filepath.Clean(absPath)
	if !strings.HasPrefix(clean, "/Users/") {
		return false
	}
	// Strip the username component so the prefix list works for any
	// user.  Replace "/Users/<user>/..." with "/Users/_/..." before
	// comparison.
	parts := strings.SplitN(clean, "/", 4)
	if len(parts) < 3 || parts[1] != "Users" {
		return false
	}
	rebuilt := "/Users/_"
	if len(parts) >= 4 {
		rebuilt = rebuilt + "/" + parts[3]
	}
	for _, prefix := range cloudPathPrefixes {
		// Trim the trailing slash from the prefix so an exact-match
		// directory (e.g. "/Users/x/Library/Mobile Documents") also
		// counts as cloud-synced, not just children of it.
		bare := strings.TrimSuffix(prefix, "/")
		if rebuilt == bare || strings.HasPrefix(rebuilt, prefix) {
			return true
		}
	}
	return false
}
