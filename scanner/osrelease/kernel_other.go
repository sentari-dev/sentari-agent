//go:build !linux && !darwin && !windows

package osrelease

// DetectKernel has no data source on this platform, so it reports "not
// detected". Kept so the package builds for every GOOS.
func DetectKernel() (string, bool) { return "", false }
