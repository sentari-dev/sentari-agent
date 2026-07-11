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
//     the scanner's primary discovery walk and every runtime walker;
//     no flag to re-enable (operators with a legitimate cloud-mounted
//     runtime should mount it locally first).  Covers macOS iCloud /
//     CloudStorage and Windows OneDrive; see IsCloudSyncedPath.
//
//  2. Network-mounted paths (NFS, SMB/CIFS, WebDAV, AutoFS, FUSE
//     remotes).  Walking these introduces network latency and may
//     pick up envs that belong to a different device.  Opt-in only:
//     the agent's `--exclude-network-paths` CLI flag flips
//     `ExcludeNetworkPaths` so the walkers consult
//     `IsNetworkFilesystem` and skip matches.
//
// Both classifiers return false on errors so a misconfigured host
// never silently drops legitimate scan coverage.
package pathfilter

import (
	"os"
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

// ShouldSkipDir returns true when a walker should `filepath.SkipDir`
// at `path`.  Combines both exclusions so each walker site is a
// single call instead of repeating the cloud-then-network ladder.
//
// Cheap when both exclusions are off: a cloud-path prefix check on
// darwin only and a constant `false` everywhere else.  The
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
	if skipDirHook != nil && skipDirHook(path) {
		return true
	}
	return false
}

// skipDirHook is an optional, test-only predicate ShouldSkipDir
// consults in addition to the cloud/network classifiers.  Nil in
// production, so the hot path stays the cloud-then-network ladder;
// tests install a closure via SetSkipDirHookForTest to exercise
// walker-level skip wiring without a real cloud or network mount.
// Package-level rather than plumbed through every walk site for the
// same reason ExcludeNetworkPaths is.
var skipDirHook func(path string) bool

// SetSkipDirHookForTest installs an extra skip predicate for
// ShouldSkipDir and returns a restore func that reinstates the prior
// state.  Test-only: production never calls it, so skipDirHook stays
// nil.  It exists so a walker test in another package (e.g. the
// scanner's primary discovery walk) can prove its ShouldSkipDir wiring
// prunes a subtree, which is otherwise hard to trigger portably —
// cloud prefixes are OS-specific and IsNetworkFilesystem needs a real
// remote mount.
func SetSkipDirHookForTest(fn func(path string) bool) (restore func()) {
	prev := skipDirHook
	skipDirHook = fn
	return func() { skipDirHook = prev }
}

// cloudPathPrefixes lists absolute path prefixes that indicate a
// cloud-synced filesystem on macOS.  Windows OneDrive is handled
// separately (its mount points are env-var-driven, not fixed prefixes
// — see matchWindowsCloudPath); Linux has no standardised cloud-sync
// mount location so it is not classified here.
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
// nothing here touches the filesystem (the Windows branch reads
// process env vars, not disk).  Falsey for relative paths.  Handled
// per-OS: macOS iCloud/CloudStorage prefixes, Windows OneDrive mount
// points, and false everywhere else (Linux has no standardised
// cloud-sync location; opt-in network exclusion is the catch-all).
func IsCloudSyncedPath(absPath string) bool {
	switch runtime.GOOS {
	case "darwin":
		return isCloudSyncedPathDarwin(absPath)
	case "windows":
		return isCloudSyncedPathWindows(absPath)
	default:
		return false
	}
}

// isCloudSyncedPathDarwin matches absPath against the macOS iCloud /
// CloudStorage prefixes, ignoring the concrete username component.
func isCloudSyncedPathDarwin(absPath string) bool {
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

// isCloudSyncedPathWindows reports whether absPath sits inside a
// OneDrive-synced tree.  OneDrive stores files as reparse points that
// the client pulls on first read ("Files On-Demand"), so walking a
// OneDrive tree triggers the same on-demand-download stall the macOS
// iCloud case does — and a venv synced into OneDrive is no more a real
// fleet workload there than under iCloud.
//
// OneDrive's mount points are per-account, not a fixed prefix, so we
// derive them from the env vars the client exports into every user
// session (%OneDrive%, plus %OneDriveCommercial% / %OneDriveConsumer%
// for a multi-account login) and fall back to the \Users\<user>\
// OneDrive* convention for a service account walking another profile
// whose env vars we don't inherit.
func isCloudSyncedPathWindows(absPath string) bool {
	return matchWindowsCloudPath(
		absPath,
		[]string{
			os.Getenv("OneDrive"),
			os.Getenv("OneDriveCommercial"),
			os.Getenv("OneDriveConsumer"),
		},
		os.Getenv("USERPROFILE"),
	)
}

// matchWindowsCloudPath is the pure core of the Windows cloud-path
// check, split out so it is unit-testable with synthetic env values.
// A path matches when it is at or under any explicit OneDrive root, or
// when its first component below userProfile begins with "OneDrive"
// (covers named-tenant variants like "OneDrive - Contoso" that the env
// vars may not enumerate).  Relative paths never match.
func matchWindowsCloudPath(absPath string, oneDriveRoots []string, userProfile string) bool {
	if absPath == "" || !filepath.IsAbs(absPath) {
		return false
	}
	clean := filepath.Clean(absPath)
	sep := string(filepath.Separator)
	for _, root := range oneDriveRoots {
		if root == "" {
			continue
		}
		r := filepath.Clean(root)
		if clean == r || strings.HasPrefix(clean, r+sep) {
			return true
		}
	}
	if userProfile != "" {
		up := filepath.Clean(userProfile)
		if strings.HasPrefix(clean, up+sep) {
			rest := clean[len(up)+len(sep):]
			first := rest
			if idx := strings.IndexByte(rest, filepath.Separator); idx >= 0 {
				first = rest[:idx]
			}
			if strings.HasPrefix(first, "OneDrive") {
				return true
			}
		}
	}
	return false
}
