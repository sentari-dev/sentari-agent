//go:build !windows

package scanner

// discoverWindowsRegistryEnvs returns nothing on non-Windows platforms.
// The real implementation is in system_windows.go.
func discoverWindowsRegistryEnvs() ([]discoveredEnv, []ScanError) {
	return nil, nil
}

// readWindowsMachineGUID returns an empty string on non-Windows platforms.
// The real implementation is in system_windows.go.
func readWindowsMachineGUID() string {
	return ""
}
