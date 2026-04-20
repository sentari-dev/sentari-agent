package scanner

// envWindowsRegistry is the EnvType() key for the Windows-registry
// RootScanner.  Its implementation is platform-split between
// system_windows.go (real registry query) and system_others.go (no-op).
// Emitted PackageRecord entries are tagged with EnvPip — the registry
// scanner only contributes *discovery* of pip install roots that the
// filesystem walk might miss; the packages themselves are pip.
const envWindowsRegistry = "windows_registry"

func init() {
	Register(windowsRegistryScanner{})
}
