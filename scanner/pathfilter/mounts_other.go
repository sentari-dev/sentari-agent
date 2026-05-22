//go:build !darwin

package pathfilter

// IsNetworkFilesystem on non-darwin platforms is a stub that returns
// (false, nil).  Wiring up per-OS detection (linux Statfs Type field +
// f_type magic table, windows GetDriveType DRIVE_REMOTE) is on the
// roadmap but each platform needs its own validation; until then the
// agent treats every path as "scan it" so a misclassification can't
// silently drop fleet coverage.
//
// The compose-time switch is still respected by the runtime walkers —
// ``ExcludeNetworkPaths=true`` on non-darwin is a no-op rather than a
// hard error so cross-platform CI runs stay green.
func IsNetworkFilesystem(path string) (bool, error) {
	return false, nil
}
