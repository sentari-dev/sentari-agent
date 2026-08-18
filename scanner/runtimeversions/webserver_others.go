//go:build !windows

package runtimeversions

// detectIIS is a no-op on non-Windows platforms.
func detectIIS() []InstalledRuntime { return nil }
