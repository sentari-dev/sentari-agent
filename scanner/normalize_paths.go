package scanner

import "strings"

// toForwardSlash rewrites backslash separators to forward slashes regardless
// of the host OS.  filepath.ToSlash is deliberately NOT used: it swaps
// os.PathSeparator, so on a non-Windows host it would no-op and leave a
// Windows-shaped path (one that reached us via a config value, container
// layer, or test) untouched.  The wire-format contract here is simply "no
// backslashes", so an unconditional replace is both correct and host-stable.
func toForwardSlash(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// NormalizePaths rewrites every filesystem-path field in a scan result to use
// forward slashes, regardless of the host OS.
//
// On Windows the scanner produces native backslash paths (e.g.
// `C:\Users\alice\site-packages`).  The server stores these verbatim and the
// dashboard renders them across a mixed-OS fleet; any server-side path-prefix
// comparison (package-location grouping, container-origin filters) is far more
// robust against a single canonical separator.  Emitting `/`-separated paths
// from every agent keeps Windows, Linux and macOS records uniform on the wire.
//
// toForwardSlash is a no-op on POSIX (those paths contain no backslashes),
// so this is safe — and idempotent — to call unconditionally.  Only true
// filesystem paths are touched; logical identifiers (env_type, ecosystem,
// signal source labels, the dependency `introduced_by_path` chain of package
// names) are deliberately left alone.
func NormalizePaths(result *ScanResult) {
	if result == nil {
		return
	}
	for i := range result.Packages {
		result.Packages[i].InstallPath = toForwardSlash(result.Packages[i].InstallPath)
		result.Packages[i].Environment = toForwardSlash(result.Packages[i].Environment)
	}
	for i := range result.Errors {
		result.Errors[i].Path = toForwardSlash(result.Errors[i].Path)
	}
	for i := range result.Lockfiles {
		result.Lockfiles[i].Path = toForwardSlash(result.Lockfiles[i].Path)
	}
	for i := range result.InstalledRuntimes {
		result.InstalledRuntimes[i].InstallPath = toForwardSlash(result.InstalledRuntimes[i].InstallPath)
	}
}
