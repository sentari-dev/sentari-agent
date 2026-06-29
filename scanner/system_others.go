//go:build !windows

package scanner

import "context"

// windowsRegistryScanner is a no-op on non-Windows platforms.  The real
// DiscoverAll lives in system_windows.go.  We keep the type registered
// on every platform so RegisteredScanners() has a stable shape across
// builds — tests can assert "windows_registry is always in the registry"
// without OS conditionals.
type windowsRegistryScanner struct{}

func (windowsRegistryScanner) EnvType() string { return envWindowsRegistry }

func (windowsRegistryScanner) DiscoverAll(_ context.Context) ([]Environment, []ScanError) {
	return nil, nil
}

func (windowsRegistryScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	return scanPipEnvironment(env.Path)
}

// readWindowsMachineGUID returns an empty string on non-Windows platforms.
// The real implementation is in system_windows.go.
func readWindowsMachineGUID() string {
	return ""
}
